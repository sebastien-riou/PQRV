#!/usr/bin/env python3
"""Run a bare-metal RV32 ELF file with the Unicorn CPU emulator.

Machines (--machine):
  virt (default): the subset of the QEMU 'virt' machine used by
    common/rv32_virt, for programs which print text and exit:
    - RAM: 8 MiB at 0x80000000, as in link.ld
    - NS16550A UART at 0x10000000: bytes written to THR go to stdout
    - SiFive test finisher at 0x00100000: 0x5555 means exit(0),
      (code << 16) | 0x3333 means exit(code)
    The same ELF file runs on QEMU with:
      qemu-system-riscv32 -M virt -bios none -nographic -kernel <elf>
  crypto-benchmark: the rv32imc target of crypto-benchmark
    (target/rv32imc/link.ld and hal.c), for lbmk-test.elf built with
    -DRAW_COM=1:
    - FLASH: 512 KiB at 0x00000000, RAM: 2 MiB at 0x20000000
    - LiteX UART at 0x60001800: the binary lean-benchmark output is saved
      with --uart-log (parse it with lean_benchmark.py --uart-log)
    - stops when main returns (symbol interrupt_handler) and succeeds if the
      program printed "done" without "EXCEPTION"

The CPU is a SiFive E31 (RV32IMAC). Unicorn does not support other
extensions and may silently mis-execute their instructions (e.g. Zbb rori),
so ELF files built for them are refused.

There is no timeout: the emulation runs until the program exits.

Requires the 'unicorn' Python package (pip install unicorn).
"""

import argparse
import re
import struct
import sys

try:
    from unicorn import (UC_ARCH_RISCV, UC_HOOK_CODE, UC_HOOK_INTR,
                         UC_HOOK_MEM_INVALID, UC_MODE_RISCV32, Uc, UcError)
    from unicorn.riscv_const import (UC_CPU_RISCV32_SIFIVE_E31,
                                     UC_RISCV_REG_PC)
except ImportError:
    sys.exit("error: the 'unicorn' Python package is missing, install it in a "
             "virtual environment with: pip install unicorn")

MIB = 1024 * 1024
MMIO_SIZE = 0x1000

MACHINES = {
    "virt": {
        "memory": [(0x80000000, 8 * MIB)],
        "uart": ("ns16550", 0x10000000),
        "finisher": 0x00100000,
        "stop_symbol": None,
    },
    "crypto-benchmark": {
        "memory": [(0x00000000, 512 * 1024), (0x20000000, 2 * MIB)],
        "uart": ("litex", 0x60001800),
        "finisher": None,
        "stop_symbol": "interrupt_handler",
    },
}

NS16550_LSR = 5
NS16550_LSR_THR_EMPTY = 0x60
LITEX_RXEMPTY = 8
FINISHER_PASS = 0x5555
FINISHER_FAIL = 0x3333

# Extensions supported by the emulated CPU (and implied ones)
SUPPORTED_EXTENSIONS = {"i", "m", "a", "c", "zicsr", "zifencei", "zmmul",
                        "zaamo", "zalrsc", "zca"}

EM_RISCV = 243
PT_LOAD = 1
SHT_SYMTAB = 2


class Elf32:
    """Minimal little-endian ELF32 RISC-V file parser."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        data = self.data
        if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
            raise ValueError(f"{path}: not a little-endian ELF32 file")
        (e_machine, self.entry, self.phoff, self.shoff, self.phentsize,
         self.phnum, self.shentsize, self.shnum,
         self.shstrndx) = struct.unpack_from("<18xH4xIII6xHHHHH", data, 0)
        if e_machine != EM_RISCV:
            raise ValueError(f"{path}: not a RISC-V ELF file")

    def segments(self):
        """Yield (address, bytes) of the PT_LOAD segments."""
        for i in range(self.phnum):
            (p_type, p_offset, _p_vaddr, p_paddr, p_filesz,
             _p_memsz) = struct.unpack_from(
                 "<IIIIII", self.data, self.phoff + i * self.phentsize)
            if p_type == PT_LOAD and p_filesz:
                yield p_paddr, self.data[p_offset:p_offset + p_filesz]

    def _sections(self):
        for i in range(self.shnum):
            yield struct.unpack_from("<IIIIIIIIII", self.data,
                                     self.shoff + i * self.shentsize)

    def _string(self, offset):
        return self.data[offset:self.data.index(b"\0", offset)].decode()

    def section(self, name):
        """Return the content of a section, or None."""
        sections = list(self._sections())
        strtab = sections[self.shstrndx][4]
        for sh in sections:
            if self._string(strtab + sh[0]) == name:
                return self.data[sh[4]:sh[4] + sh[5]]
        return None

    def symbol(self, name):
        """Return the address of a symbol, or None."""
        sections = list(self._sections())
        for sh in sections:
            if sh[1] != SHT_SYMTAB:
                continue
            strtab = sections[sh[6]][4]
            for off in range(sh[4], sh[4] + sh[5], 16):
                st_name, st_value = struct.unpack_from("<II", self.data, off)
                if st_name and self._string(strtab + st_name) == name:
                    return st_value
        return None

    def unsupported_extensions(self):
        """Return the ISA extensions of the file not in
        SUPPORTED_EXTENSIONS."""
        attributes = self.section(".riscv.attributes")
        match = re.search(rb"rv32[0-9a-z_]+", attributes or b"")
        if not match:
            return []
        tokens = match.group().decode().split("_")
        extensions = list(re.sub(r"\d+p\d+$", "", tokens[0])[4:])
        for token in tokens[1:]:
            token = re.sub(r"\d+p\d+$", "", token)
            # single letter extensions may be concatenated (e.g. "imac")
            extensions += [token] if token.startswith(("z", "x", "s")) \
                else list(token)
        return [e for e in extensions if e not in SUPPORTED_EXTENSIONS]


def run(path, machine_name, uart_log):
    """Run the program and return its exit code."""
    machine = MACHINES[machine_name]
    elf = Elf32(path)
    unsupported = elf.unsupported_extensions()
    if unsupported:
        print(f"error: {path} uses ISA extensions that the emulator does not "
              f"support: {', '.join(unsupported)}", file=sys.stderr)
        return 1

    state = {"exit_code": None}
    output = bytearray()

    uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)
    uc.ctl_set_cpu_model(UC_CPU_RISCV32_SIFIVE_E31)
    for base, size in machine["memory"]:
        uc.mem_map(base, size)

    def uart_out(value):
        byte = value & 0xFF
        output.append(byte)
        if machine_name == "virt":
            sys.stdout.buffer.write(bytes([byte]))
            if byte == ord("\n"):
                sys.stdout.flush()

    # MMIO ranges must be page aligned, offsets are relative to the page
    uart_type, uart_base = machine["uart"]
    uart_page = uart_base & ~(MMIO_SIZE - 1)
    uart_offset = uart_base - uart_page
    if uart_type == "ns16550":
        def uart_read(_uc, offset, _size, _data):
            if offset - uart_offset == NS16550_LSR:
                return NS16550_LSR_THR_EMPTY
            return 0
    else:
        def uart_read(_uc, offset, _size, _data):
            return 1 if offset - uart_offset == LITEX_RXEMPTY else 0

    def uart_write(_uc, offset, _size, value, _data):
        if offset == uart_offset:
            uart_out(value)
    uc.mmio_map(uart_page, MMIO_SIZE, uart_read, None, uart_write, None)

    if machine["finisher"] is not None:
        def finisher_read(_uc, _offset, _size, _data):
            return 0

        def finisher_write(uc_, offset, _size, value, _data):
            if offset != 0:
                return
            if value & 0xFFFF == FINISHER_PASS:
                state["exit_code"] = 0
            elif value & 0xFFFF == FINISHER_FAIL:
                state["exit_code"] = value >> 16
            else:
                return
            uc_.emu_stop()

        uc.mmio_map(machine["finisher"], MMIO_SIZE, finisher_read, None,
                    finisher_write, None)

    if machine["stop_symbol"] is not None:
        stop = elf.symbol(machine["stop_symbol"])
        if stop is None:
            print(f"error: symbol {machine['stop_symbol']} not found",
                  file=sys.stderr)
            return 1

        def stop_hook(uc_, _address, _size, _data):
            done = b"done" in output and b"EXCEPTION" not in output
            state["exit_code"] = 0 if done else 1
            uc_.emu_stop()

        uc.hook_add(UC_HOOK_CODE, stop_hook, begin=stop, end=stop)

    def invalid_access(uc_, _access, address, size, _value, _data):
        pc = uc_.reg_read(UC_RISCV_REG_PC)
        print(f"\nerror: invalid memory access to 0x{address:08x} "
              f"({size} bytes) at pc=0x{pc:08x}", file=sys.stderr)
        return False

    def trap(uc_, cause, _data):
        pc = uc_.reg_read(UC_RISCV_REG_PC)
        print(f"\nerror: unexpected trap (cause {cause}) at pc=0x{pc:08x}",
              file=sys.stderr)
        state["exit_code"] = 1
        uc_.emu_stop()

    uc.hook_add(UC_HOOK_MEM_INVALID, invalid_access)
    uc.hook_add(UC_HOOK_INTR, trap)

    for address, data in elf.segments():
        if not any(base <= address and address + len(data) <= base + size
                   for base, size in machine["memory"]):
            print(f"error: {path}: segment at 0x{address:08x} is outside "
                  f"memory", file=sys.stderr)
            return 1
        uc.mem_write(address, data)

    try:
        # stop address: unmapped in all machines (0 is the entry point of some)
        uc.emu_start(elf.entry, 0xFFFFFFFE)
    except UcError as e:
        pc = uc.reg_read(UC_RISCV_REG_PC)
        print(f"\nerror: emulation failed at pc=0x{pc:08x}: {e}",
              file=sys.stderr)
        state["exit_code"] = 1
    finally:
        sys.stdout.flush()
        if uart_log:
            with open(uart_log, "wb") as f:
                f.write(output)

    if machine_name != "virt":
        # The output is binary, show its text status lines only
        for line in re.findall(rb"(?:done|EXCEPTION|Error code: 0x[0-9a-fA-F]+)",
                               bytes(output)):
            print(line.decode())
    if state["exit_code"] is None:
        pc = uc.reg_read(UC_RISCV_REG_PC)
        print(f"\nerror: emulation stopped at pc=0x{pc:08x} without exit",
              file=sys.stderr)
        return 1
    return state["exit_code"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("elf", help="bare-metal RV32 ELF file to run")
    parser.add_argument("--machine", choices=sorted(MACHINES), default="virt",
                        help="emulated machine (default: virt)")
    parser.add_argument("--uart-log", metavar="FILE",
                        help="save the UART output to FILE")
    args = parser.parse_args()
    return run(args.elf, args.machine, args.uart_log)


if __name__ == "__main__":
    sys.exit(main())
