.code16
.globl _start
_start:
    movw    $0x13, %ax
    int     $0x10
    movw    $0x0C0A, %ax
    xorl    %ecx, %ecx
    xorl    %edx, %edx
.Lloop:
    int     $0x10
    incw    %cx
    incw    %dx
    incb    %al
    jmp     .Lloop