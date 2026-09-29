/* S4 payload: freestanding static ELF at 0x400000, executed by s3_launcher
 * INSIDE a Windows (PE) process. No syscalls allowed — writes the magic to
 * the fixed VA the launcher pre-mapped, then returns like a normal function.
 */
__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "movabs $0x50000000, %rax \n\t"
        "movl $0xC0FFEE42, (%rax) \n\t"
        "xorl %eax, %eax \n\t"
        "ret \n\t");
}
