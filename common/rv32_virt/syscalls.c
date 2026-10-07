/*
 * Minimal newlib system calls for bare-metal RV32 programs on the QEMU 'virt'
 * machine: console output on the NS16550A UART and exit through the SiFive
 * test device. There is no file system and no input.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#define UART0_THR ((volatile uint8_t *)0x10000000)
#define TEST_FINISHER ((volatile uint32_t *)0x00100000)
#define FINISHER_PASS 0x5555
#define FINISHER_FAIL 0x3333

/* Space kept free between the heap and the stack pointer */
#define STACK_MARGIN 4096

int _write(int fd, const void *buf, size_t count);
void _exit(int status);
void *_sbrk(ptrdiff_t incr);
int _isatty(int fd);
int _close(int fd);
int _fstat(int fd, struct stat *st);
int _lseek(int fd, int offset, int whence);
int _read(int fd, void *buf, size_t count);

int _write(int fd, const void *buf, size_t count)
{
    const uint8_t *p = buf;
    size_t i;

    (void)fd;
    for (i = 0; i < count; i++)
        *UART0_THR = p[i];
    return count;
}

void _exit(int status)
{
    if (status == 0)
        *TEST_FINISHER = FINISHER_PASS;
    else
        *TEST_FINISHER = ((uint32_t)status << 16) | FINISHER_FAIL;
    for (;;)
        ;
}

void *_sbrk(ptrdiff_t incr)
{
    extern char _end[];
    static char *heap_end = _end;
    char *prev = heap_end;
    char *sp = __builtin_frame_address(0);

    if (heap_end + incr > sp - STACK_MARGIN) {
        errno = ENOMEM;
        return (void *)-1;
    }
    heap_end += incr;
    return prev;
}

int _isatty(int fd)
{
    (void)fd;
    return 1;
}

int _close(int fd)
{
    (void)fd;
    errno = EBADF;
    return -1;
}

int _fstat(int fd, struct stat *st)
{
    (void)fd;
    st->st_mode = S_IFCHR;
    return 0;
}

int _lseek(int fd, int offset, int whence)
{
    (void)fd;
    (void)offset;
    (void)whence;
    return 0;
}

int _read(int fd, void *buf, size_t count)
{
    (void)fd;
    (void)buf;
    (void)count;
    return 0;
}
