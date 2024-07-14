global _start

section .text
_start:
    xor rax, rax
    xor rbx, rbx
    inc rbx
    mov rcx, 10
loopFib:
    add rax, rbx
    xchg rax, rbx
    cmp rbx, 10
    js loopFib

    ;xor rax, rax
    ;xor rbx, rbx
    ;inc bl
    ;add al, bl
    ;not rax

    ;mov rax, rsp
    ;mov rax, [rsp]
    ;mov al, 0
    ;mov bl, 1
    ;xchg rbx, rax
