#define main __main
#include "main.cpp"
#undef main

int
main(int argc, char* argv[]) {
    @autoreleasepool {
        int opt;
        while((opt = getopt(argc, argv, "v")) != -1) {
            switch (opt) {
                case 'v':
                    VERBOSE = 1;
                    break;
                default:
                    printf("optopt = %c\n", (char)optopt);
                    printf("opterr = %d\n", opterr);
                    fprintf(stderr, "usage: %s [-v] encfile\n", argv[0]);
                    exit(1);
            } 
        }
        argc -= optind;
        argv += optind;

        if (argc < 1) {
            return 1;
        }
        char outpath[0x200] = { 0 };
        strcpy(outpath, "/tmp/");
        const char *lastPathComponent = strrchr(argv[0], '/');
        if (!lastPathComponent) {
            strcat(outpath, argv[0]);
        } else {
            strcat(outpath, lastPathComponent + 1);
        }
        int ret = decrypt_macho(argv[0], outpath);
        if (!ret) {
            printf("Wrote decrypted image to %s\n", outpath);
        }
        return ret;
    }
}
