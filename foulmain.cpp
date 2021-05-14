#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern int VERBOSE;
int decrypt_macho(const char *inputFile, const char *outputFile);

int
main(int argc, char* argv[])
{
    int opt;
    while((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
            case 'v':
                VERBOSE = 1;
                break;
            default:
                printf("optopt = %c\n", (char)optopt);
                printf("opterr = %d\n", opterr);
                fprintf(stderr, "usage: %s [-v] encfile outfile\n", argv[0]);
                exit(1);
        } 
    }
    argc -= optind;
    argv += optind;
    if (argc < 2) {
        fprintf(stderr, "usage: fouldecrypt [-v] encfile outfile\n");
        return 1;
    }
    return decrypt_macho(argv[0], argv[1]);
}
