#!/usr/bin/env python3
"""Run a bare-metal RV32 ELF file built for the QEMU 'virt' memory map
(common/rv32_virt) with the Unicorn CPU emulator.

Emulated machine (the subset of QEMU 'virt' that common/rv32_virt uses):
  - CPU: SiFive E31 (RV32IMAC): instructions outside this ISA trap
  - RAM: 8 MiB at 0x80000000, as in link.ld
  - NS16550A UART at 0x10000000: bytes written to THR go to stdout
  - SiFive test finisher at 0x00100000: 0x5555 means exit(0),
    (code << 16) | 0x3333 means exit(code)

The same ELF file runs on QEMU with:
  qemu-system-riscv32 -M virt -bios none -nographic -kernel <elf>

There is no timeout: the emulation runs until the program exits.

Requires the 'unicorn' Python package (pip install unicorn).
"""

import argparse
import struct
import sys

try:
    from unicorn import (UC_ARCH_RISCV, UC_HOOK_INTR, UC_HOOK_MEM_INVALID,
                         UC_MODE_RISCV32, Uc, UcError)
    from unicorn.riscv_const import (UC_CPU_RISCV32_SIFIVE_E31,
                                     UC_RISCV_REG_PC)
except ImportError:
    sys.exit("error: the 'unicorn' Python package is missing, install it in a "
             "virtual environment with: pip install unicorn")

RAM_BASE = 0x80000000
RAM_SIZE = 8 * 1024 * 1024
UART_BASE = 0x10000000
UART_LSR = 5
UART_LSR_THR_EMPTY = 0x60
FINISHER_BASE = 0x00100000
FINISHER_PASS = 0x5555
FINISHER_FAIL = 0x3333
MMIO_SIZE = 0x1000

EM_RISCV = 243
PT_LOAD = 1


def load_elf(uc, path):
    """Copy the PT_LOAD segments of a little-endian ELF32 RISC-V file to the
    emulated RAM and return the entry point."""
    with open(path, "rb") as f:
        elf = f.read()
    if elf[:4] != b"\x7fELF" or elf[4] != 1 or elf[5] != 1:
        raise ValueError(f"{path}: not a little-endian ELF32 file")
    (e_machine, e_entry, e_phoff, e_phentsize,
     e_phnum) = struct.unpack_from("<18xH4xII10xHH", elf, 0)
    if e_machine != EM_RISCV:
        raise ValueError(f"{path}: not a RISC-V ELF file")
    for i in range(e_phnum):
        (p_type, p_offset, _p_vaddr, p_paddr, p_filesz,
         _p_memsz) = struct.unpack_from("<IIIIII", elf, e_phoff + i * e_phentsize)
        if p_type != PT_LOAD or p_filesz == 0:
            continue
        if p_paddr < RAM_BASE or p_paddr + p_filesz > RAM_BASE + RAM_SIZE:
            raise ValueError(f"{path}: segment at 0x{p_paddr:08x} is outside RAM")
        uc.mem_write(p_paddr, elf[p_offset:p_offset + p_filesz])
    return e_entry


def run(path):
    """Run the program and return its exit code."""
    state = {"exit_code": None}

    uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)
    uc.ctl_set_cpu_model(UC_CPU_RISCV32_SIFIVE_E31)
    uc.mem_map(RAM_BASE, RAM_SIZE)

    def uart_read(_uc, offset, _size, _data):
        return UART_LSR_THR_EMPTY if offset == UART_LSR else 0

    def uart_write(_uc, offset, _size, value, _data):
        if offset == 0:
            sys.stdout.buffer.write(bytes([value & 0xFF]))
            if value & 0xFF == ord("\n"):
                sys.stdout.flush()

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

    uc.mmio_map(UART_BASE, MMIO_SIZE, uart_read, None, uart_write, None)
    uc.mmio_map(FINISHER_BASE, MMIO_SIZE, finisher_read, None,
                finisher_write, None)
    uc.hook_add(UC_HOOK_MEM_INVALID, invalid_access)
    uc.hook_add(UC_HOOK_INTR, trap)

    entry = load_elf(uc, path)
    try:
        uc.emu_start(entry, 0)
    except UcError as e:
        pc = uc.reg_read(UC_RISCV_REG_PC)
        print(f"\nerror: emulation failed at pc=0x{pc:08x}: {e}", file=sys.stderr)
        return 1
    finally:
        sys.stdout.flush()

    if state["exit_code"] is None:
        pc = uc.reg_read(UC_RISCV_REG_PC)
        print(f"\nerror: emulation stopped at pc=0x{pc:08x} without exit",
              file=sys.stderr)
        return 1
    return state["exit_code"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("elf", help="bare-metal RV32 ELF file to run")
    args = parser.parse_args()
    return run(args.elf)


if __name__ == "__main__":
    sys.exit(main())
