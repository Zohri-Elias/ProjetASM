#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

// Traduit un p_type (un nombre) en texte lisible.
static const char *type_phdr(Elf64_Word t) {
    switch (t) {
        case PT_NULL:    return "NULL";
        case PT_LOAD:    return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_INTERP:  return "INTERP";
        case PT_NOTE:    return "NOTE";
        case PT_PHDR:    return "PHDR";
        case PT_TLS:     return "TLS";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case PT_GNU_STACK:    return "GNU_STACK";
        case PT_GNU_RELRO:    return "GNU_RELRO";
        case PT_GNU_PROPERTY: return "GNU_PROPERTY";
        default:         return "AUTRE";
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage : %s <fichier_elf>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) { perror("fopen"); return EXIT_FAILURE; }

    // 1) Lire l'en-tete pour connaitre e_phoff, e_phnum
    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
        printf("Lecture en-tete impossible.\n"); fclose(f); return EXIT_FAILURE;
    }
    if (ehdr.e_ident[0]!=0x7F || ehdr.e_ident[1]!='E' ||
        ehdr.e_ident[2]!='L' || ehdr.e_ident[3]!='F') {
        printf("Pas un ELF.\n"); fclose(f); return EXIT_FAILURE;
    }

    printf("Point d'entree : 0x%lx\n", ehdr.e_entry);
    printf("%u program headers, table a l'offset %lu\n\n", ehdr.e_phnum, ehdr.e_phoff);

    // 2) Se placer au debut de la table des program headers
    if (fseek(f, ehdr.e_phoff, SEEK_SET) != 0) {
        perror("fseek"); fclose(f); return EXIT_FAILURE;
    }

    // 3) Lire chaque program header, un par un
    printf("  #   Type          Offset     VirtAddr     Flags\n");
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (fread(&phdr, sizeof(phdr), 1, f) != 1) {
            printf("Lecture phdr %d impossible.\n", i); break;
        }
        printf("  %-2d  %-12s  0x%08lx  0x%09lx  %c%c%c\n",
               i,
               type_phdr(phdr.p_type),
               phdr.p_offset,
               phdr.p_vaddr,
               (phdr.p_flags & PF_R) ? 'R' : '-',
               (phdr.p_flags & PF_W) ? 'W' : '-',
               (phdr.p_flags & PF_X) ? 'E' : '-');
    }

    fclose(f);
    return 0;
}
