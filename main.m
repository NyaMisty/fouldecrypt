#include <stdio.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <mach-o/loader.h>

extern int mremap_encrypted(void*, size_t, uint32_t, uint32_t, uint32_t);

static int
unprotect(int f, uint8_t *dupe, struct encryption_info_command_64 *info)
{
    void *base = mmap(NULL, info->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, info->cryptoff);
    if (base == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    int error = mremap_encrypted(base, info->cryptsize, info->cryptid,
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
    if (error) {
        perror("mremap_encrypted");
        munmap(base, info->cryptsize);
        return 1;
    }

    memcpy(dupe + info->cryptoff, base, info->cryptsize);

    munmap(base, info->cryptsize);
    return 0;
}

static uint8_t*
map(const char *path, bool mutable, size_t *size, int *descriptor)
{
    int f = open(path, mutable ? O_RDWR : O_RDONLY);
    if (f < 0) {
        perror("open");
        return NULL;
    }

    struct stat s;
    if (fstat(f, &s) < 0) {
        perror("fstat");
        close(f);
        return NULL;
    }

    uint8_t *base = mmap(NULL, s.st_size, mutable ? PROT_READ | PROT_WRITE : PROT_READ,
        mutable ? MAP_SHARED : MAP_PRIVATE, f, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        close(f);
        return NULL;
    }

    *size = s.st_size;
    if (descriptor) {
        *descriptor = f;
    } else {
        close(f);
    }
    return base;
}

int
decrypt_macho(const char *inputFile, const char *outputFile)
{
    // map RO one for decrypt
    size_t base_size;
    int f;
    uint8_t *base = map(inputFile, false, &base_size, &f);
    if (base == NULL) {
        return 1;
    }
    
    // map RW one for modify
    size_t dupe_size;
    uint8_t *dupe = map(outputFile, true, &dupe_size, NULL);
    if (dupe == NULL) {
        munmap(base, base_size);
        return 1;
    }

    // If the files are not of the same size, then they are not duplicates of
    // each other, which is an error.
    //
    if (base_size != dupe_size) {
        munmap(base, base_size);
        munmap(dupe, dupe_size);
        return 1;
    }

    struct mach_header_64* header = (struct mach_header_64*) base;
    assert(header->magic == MH_MAGIC_64);
    assert(header->cputype == CPU_TYPE_ARM64);
    assert(header->cpusubtype == CPU_SUBTYPE_ARM64_ALL);

    uint32_t offset = sizeof(struct mach_header_64);

    // Enumerate all load commands and check for the encryption header, if found
    // start "unprotect"'ing the contents.
    //
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command* command = (struct load_command*) (base + offset);

        if (command->cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command_64 *encryption_info =
                (struct encryption_info_command_64*) command;
            // If "unprotect"'ing is successful, then change the "cryptid" so that
            // the loader does not attempt to decrypt decrypted pages.
            //
            if (unprotect(f, dupe, encryption_info) == 0) {
                encryption_info = (struct encryption_info_command_64*) (dupe + offset);
                encryption_info->cryptid = 0;
            }
            // There should only be ONE header present anyways, so stop after
            // the first one.
            //
            break;
        }

        offset += command->cmdsize;
    }

    munmap(base, base_size);
    munmap(dupe, dupe_size);
    return 0;
}

int
main(int argc, char* argv[])
{
    @autoreleasepool {
        if (argc < 3) {
            return 1;
        }
        return decrypt_macho(argv[1], argv[2]);
    }
}
