#define main __main
#include "main.m"
#undef main

int
main(int argc, char* argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            return 1;
        }
        char outpath[0x200] = { 0 };
        strcpy(outpath, "/tmp/");
        const char *lastPathComponent = strrchr(argv[1], '/');
        if (!lastPathComponent) {
            strcat(outpath, argv[1]);
        } else {
            strcat(outpath, lastPathComponent + 1);
        }
        int ret = decrypt_macho(argv[1], outpath);
        if (!ret) {
            printf("Wrote decrypted image to %s\n", outpath);
        }
        return ret;
    }
}
