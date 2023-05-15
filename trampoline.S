# PLT trampoline for lazy binding
    .text
    .globl trampoline
    .hidden trampoline
    .type trampoline, @function
    .align 16

trampoline:

# Your code here
    push %rbx
    mov %rsp, %rbx
    sub $0x40, %rsp
    mov %rax, 0x0(%rsp)
    mov %rcx, 0x8(%rsp)
    mov %rdx, 0x10(%rsp)
    mov %rsi, 0x18(%rsp)
    mov %rdi, 0x20(%rsp)
    mov %r8, 0x28(%rsp)
    mov %r9, 0x30(%rsp)

    mov 0x08(%rbx), %rdi
    mov 0x10(%rbx), %rsi

    call runtimeResolve

    mov %rax, %r11

    mov 0x0(%rsp), %rax
    mov 0x8(%rsp), %rcx
    mov 0x10(%rsp), %rdx
    mov 0x18(%rsp), %rsi
    mov 0x20(%rsp), %rdi
    mov 0x28(%rsp), %r8
    mov 0x30(%rsp), %r9
    add $0x40, %rsp
    mov %rbx, %rsp
    pop %rbx
    add $0x10, %rsp

    jmp *%r11
# Your code here
