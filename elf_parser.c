/*
 * elf_parser.c — Lecteur d'en-tete et de program headers ELF64.
 *
 * Objectif (phase A, tache 1) : lire un binaire ELF64 et afficher son
 * en-tete puis sa table de program headers, comme un mini "readelf".
 * C'est de la LECTURE seule : le fichier cible n'est jamais modifie.
 *
 * Compilation :  gcc -Wall -Wextra -o elf_parser elf_parser.c
 * Usage       :  ./elf_parser <fichier_elf>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage : %s <fichier_elf>\n", argv[0]);
        return EXIT_FAILURE;
    }

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
