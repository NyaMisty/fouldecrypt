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
#include <time.h>
#include <sys/time.h>

#include "kerninfra/kerninfra.hpp"

#undef PAGE_SIZE
#define PAGE_SIZE 0x4000
#define EXEC_PAGE_SIZE 0x1000

int VERBOSE = 0;
#define DLOG(f_, ...)                                                                            \
{                                                                                                 \
    if (VERBOSE) {                                                                                \
        struct tm _tm123_;                                                                            \
        struct timeval _xxtv123_;                                                                     \
        gettimeofday(&_xxtv123_, NULL);                                                               \
        localtime_r(&_xxtv123_.tv_sec, &_tm123_);                                                     \
        printf("%2d:%2d:%2d.%d\t", _tm123_.tm_hour, _tm123_.tm_min, _tm123_.tm_sec, _xxtv123_.tv_usec); \
        printf((f_), ##__VA_ARGS__);                                                                  \
        printf("\n");                                                                               \
    }                                                                                              \
};


extern "C" int mremap_encrypted(void*, size_t, uint32_t, uint32_t, uint32_t);
/*
static int
unprotect(int f, uint8_t *dupe, struct encryption_info_command_64 *info)
{
    vm_address_t offalign = info->cryptoff & ~(PAGE_SIZE - 1);
    vm_address_t mapoffset = info->cryptoff - offalign;
    size_t aligned_size = info->cryptsize + mapoffset;
    size_t realsize = info->cryptsize;
    int cryptid = info->cryptid;
    DLOG("mapping encrypted data pages using off: 0x%lx, size: 0x%zx", offalign, aligned_size);
    
    void *tmp_dec_area = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    
    
    auto curp = proc_t_p(current_proc());
    auto vPageShift = curp.task()._map().page_shift();
    DLOG("original page shift: %d", vPageShift.load());
    vPageShift.store(12);
    DLOG("new page shift: %d", vPageShift.load());

    //int fpid = fork();
    int fpid = 0;
    if (fpid < 0) {
        perror("fork(unprotect)");
    } else if (fpid == 0) {
        exit(0);
        // we are child!
        void *oribase = mmap(NULL, aligned_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, offalign);
        if (oribase == MAP_FAILED) {
            perror("mmap(unprotect)");
            return 1;
        }

        void *base = (char *)oribase + mapoffset;
        DLOG("mremap_encrypted pages using addr: %p, size: 0x%lx, cryptid: %d, cputype: %x, cpusubtype: %x", 
            base, aligned_size, cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
        //int error = mremap_encrypted(oribase, aligned_size, info->cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
        int error = mremap_encrypted(base, realsize, cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
        if (error) {
            perror("mremap_encrypted(unprotect)");
            munmap(oribase, info->cryptsize);
            return 1;
        }

        memmove(tmp_dec_area, base, realsize);

        DLOG("cleaning up...");
        munmap(oribase, info->cryptsize);

        exit(0);
    } else {
        vPageShift.store(14);
        DLOG("restored page shift: %d", vPageShift.load());
        wait(NULL);
    }
    
    DLOG("copying child process's ret pages..");
    //memcpy(dupe + info->cryptoff, base + (info->cryptoff - offalign), info->cryptsize);
    memcpy(dupe + info->cryptoff, tmp_dec_area, info->cryptsize);

    return 0;
}*/

static int
unprotect(int f, uint8_t *dupe, struct encryption_info_command_64 *info)
{
    assert((info->cryptoff & (EXEC_PAGE_SIZE - 1)) == 0);

    DLOG("Going to decrypt crypt page: off 0x%x size 0x%x cryptid %d", info->cryptoff, info->cryptsize, info->cryptid);
    
    void *oribase = NULL;
    if (!(info->cryptoff & (PAGE_SIZE - 1))) {
        // already 4k aligned, pretty good!
        oribase = mmap(NULL, info->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, info->cryptoff);
    } else {
        if (!!init_kerninfra()) {
            fprintf(stderr, "Failed to init kerninfra!!\n");
            exit(1);
        } else {
            DLOG("successfully initialized kerninfra!");
        }


        // patching kernel task map to allow 4K page (MAGIC)
        auto curp = proc_t_p(current_proc());
        auto vPageShift = curp.task()._map().page_shift();
        DLOG("original page shift: %d", vPageShift.load());
        vPageShift.store(12);
        DLOG("new page shift: %d", vPageShift.load());

        // now map the 4K-aligned enc pages, like the good old days
        DLOG("mapping encrypted data pages using off: 0x%x, size: 0x%x", info->cryptoff, info->cryptsize);
        oribase = mmap(NULL, info->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, info->cryptoff);
        if (oribase == MAP_FAILED) {
            perror("mmap(unprotect)");
            return 1;
        }

        // restore kernel task map to 16K page, or it will panic because encrypting compressor's paging
        vPageShift.store(14);
        DLOG("restored page shift: %d", vPageShift.load());
    }
    
    // old-school mremap_encrypted
    void *base = (char *)oribase;
    DLOG("mremap_encrypted pages using addr: %p, size: 0x%x, cryptid: %d, cputype: %x, cpusubtype: %x", 
        base, info->cryptsize, info->cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
    int error = mremap_encrypted(base, info->cryptsize, info->cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
    if (error) {
        perror("mremap_encrypted(unprotect)");
        munmap(oribase, info->cryptsize);
        return 1;
    }

    DLOG("copying enc pages, size: 0x%x..", info->cryptsize);
    memcpy(dupe + info->cryptoff, base, info->cryptsize);

    DLOG("cleaning up...");
    munmap(oribase, info->cryptsize);

    return 0;
}

static uint8_t*
map(const char *path, bool _mutable, size_t *size, int *descriptor)
{
    int f = open(path, _mutable ? O_CREAT | O_TRUNC | O_RDWR : O_RDONLY, 0755);
    if (f < 0) {
        perror(_mutable ? "open(map-ro)" : "open(map-rw)");
        return NULL;
    }
    
    if (_mutable) {
        if (ftruncate(f, *size) < 0) {
            perror("ftruncate(map)");
            return NULL;
        }
    }

    struct stat s;
    if (fstat(f, &s) < 0) {
        perror("fstat(map)");
        close(f);
        return NULL;
    }

    uint8_t *base = (uint8_t *)mmap(NULL, s.st_size, _mutable ? PROT_READ | PROT_WRITE : PROT_READ,
        _mutable ? MAP_PRIVATE : MAP_PRIVATE, f, 0);
    if (base == MAP_FAILED) {
        perror(_mutable ? "mmap(map-ro)" : "mmap(map-rw)");
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
    DLOG("mapping input file: %s", inputFile);
    size_t base_size;
    int f;
    uint8_t *base = map(inputFile, false, &base_size, &f);
    if (base == NULL) {
        return 1;
    }
    
    DLOG("mapping output file: %s", outputFile);
    size_t dupe_size = base_size;
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

    DLOG("finding encryption_info segment in file...");
    struct mach_header_64* header = (struct mach_header_64*) base;
    assert(header->magic == MH_MAGIC_64);
    assert(header->cputype == CPU_TYPE_ARM64);
    assert(header->cpusubtype == CPU_SUBTYPE_ARM64_ALL);

    uint32_t offset = sizeof(struct mach_header_64);

    // Enumerate all load commands and check for the encryption header, if found
    // start "unprotect"'ing the contents.
    //
    struct encryption_info_command_64 *encryption_info = NULL;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command* command = (struct load_command*) (base + offset);

        if (command->cmd == LC_ENCRYPTION_INFO_64) {
            DLOG("    found encryption_info segment at offset %x", offset);
            encryption_info = (struct encryption_info_command_64*) command;
            // There should only be ONE header present anyways, so stop after
            // the first one.
            //
            break;
        }

        offset += command->cmdsize;
    }
    if (!encryption_info || !encryption_info->cryptid) {
        fprintf(stderr, "file not encrypted!\n");
        exit(1);
    }
    // If "unprotect"'ing is successful, then change the "cryptid" so that
    // the loader does not attempt to decrypt decrypted pages.
    //
    DLOG("copying original data of size 0x%zx...", base_size);
    memcpy(dupe, base, base_size);
    
    DLOG("decrypting encrypted data...");
    if (unprotect(f, dupe, encryption_info) == 0) {
        encryption_info = (struct encryption_info_command_64*) (dupe + offset);
        encryption_info->cryptid = 0;
    }

    munmap(base, base_size);
    munmap(dupe, dupe_size);
    return 0;
}

int
main(int argc, char* argv[])
{
    //@autoreleasepool {
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
    //}
}
