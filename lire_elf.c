#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage : %s <fichier_elf>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
        printf("Lecture de l'en-tete impossible.\n");
        fclose(f);
        return EXIT_FAILURE;
    }

    if (ehdr.e_ident[0] != 0x7F || ehdr.e_ident[1] != 'E' ||
        ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
        printf("Ce fichier n'est pas un ELF.\n");
        fclose(f);
        return EXIT_FAILURE;
    }

    printf("C'est bien un ELF !\n");
    printf("  Point d'entree (e_entry)  : 0x%lx\n", ehdr.e_entry);
    printf("  Offset des phdr (e_phoff) : %lu\n", ehdr.e_phoff);
    printf("  Nb de phdr (e_phnum)      : %u\n", ehdr.e_phnum);

    fclose(f);
    return 0;
}
