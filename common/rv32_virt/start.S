/*
 * Minimal bare-metal startup for RV32 programs using the QEMU 'virt' memory
 * map (RAM at 0x80000000, see link.ld). No interrupt is used.
 */
    .section .text.init, "ax"
    .globl _start
_start:
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop
    la      sp, __stack_top

    /* Zero .bss */
    la      t0, __bss_start
    la      t1, __bss_end
1:
    bgeu    t0, t1, 2f
    sw      zero, 0(t0)
    addi    t0, t0, 4
    j       1b
2:
    li      a0, 0
    li      a1, 0
    call    main
    call    exit
3:
    j       3b
