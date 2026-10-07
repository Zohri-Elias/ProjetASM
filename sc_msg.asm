BITS 64

_start:
    ; ===== Sauvegarder la stack initiale =====
    mov     r12, rsp

    ; ===== write(1, "INFECTE!\n", 9) =====
    xor     rax, rax
    mov     al, 1
    xor     rdi, rdi
    mov     dil, 1
    lea     rsi, [rel msg]
    xor     rdx, rdx
    mov     dl, 9
    syscall

    ; ===== Restaurer la stack initiale =====
    mov     rsp, r12

    ; ===== Saut relatif vers e_entry =====
    call    $+5
    pop     rbx
    add     rbx, strict dword 0x41414141
    jmp     rbx

msg: db "INFECTE!", 10
