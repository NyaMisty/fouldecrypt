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
#include <mach-o/fat.h>
#include <time.h>
#include <sys/time.h>
#include <libkern/OSByteOrder.h>

#include <mach/mach.h>

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
        printf("%02d:%02d:%02d.%06d\t", _tm123_.tm_hour, _tm123_.tm_min, _tm123_.tm_sec, _xxtv123_.tv_usec); \
        printf((f_), ##__VA_ARGS__);                                                                  \
        printf("\n");                                                                               \
    }                                                                                              \
};


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
        _mutable ? MAP_SHARED : MAP_PRIVATE, f, 0);
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

bool has_prep_kernel = false;
int prepare_kernel() {
    if (!has_prep_kernel) {
        int ret = init_kerninfra(KERNLOG_NONE);
        if (ret) return ret;
        has_prep_kernel = true;
    }
    return 0;
}

extern "C" int mremap_encrypted(void*, size_t, uint32_t, uint32_t, uint32_t);

extern "C" kern_return_t mach_vm_remap(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
                            mach_vm_offset_t, int, vm_map_t, mach_vm_address_t,
                            boolean_t, vm_prot_t *, vm_prot_t *, vm_inherit_t);

void *__mmap(const char *info, void *base, size_t size, int prot, int flags, int fd, size_t off) {
    DLOG("-->> %s mmaping(%p, 0x%zx, %d, 0x%x, %d, 0x%zx)", info, base, size, prot, flags, fd, off);
    void *ret = mmap(base, size, prot, flags, fd, off);
    if (ret == MAP_FAILED) {
        perror("mmap");
    }
    DLOG("<<-- %s mmaping(%p, 0x%zx, %d, 0x%x, %d, 0x%zx) = %p", info, base, size, prot, flags, fd, off, ret);
    return ret;
}

int __mremap_encrypted(const char *info, void *base, size_t cryptsize, uint32_t cryptid, uint32_t cpuType, uint32_t cpuSubType) {
    DLOG("<<-- %s mremap_encrypted(%p, 0x%zx, %d, 0x%x, 0x%x)", info, base, cryptsize, cryptid, cpuType, cpuSubType);
    int ret = mremap_encrypted(base, cryptsize, cryptid, cpuType, cpuSubType);
    if (ret) {
        perror("mremap_encrypted");
    }
    DLOG("-->> %s mremap_encrypted(%p, 0x%zx, %d, 0x%x, 0x%x) = %d", info, base, cryptsize, cryptid, cpuType, cpuSubType, ret);
    return ret;
}

#define LOGINDENT "            "
void debugprint_vme(addr_t _vmentry) {
    auto encVmEntry = _vm_map_entry_p(_vmentry);
    DLOG(LOGINDENT"mmaped entry: %p - %p", (void *)encVmEntry.start().load(), (void *)encVmEntry.end().load());
    DLOG(LOGINDENT"mmaped vme_offset: 0x%llx", encVmEntry.vme_offset().load());
    DLOG(LOGINDENT"mmaped vme_flags: 0x%x", encVmEntry.vme_flags().load());
    DLOG(LOGINDENT"mmaped vme_object: 0x%llx", encVmEntry.vme_object().load());
}

void debugprint_vmobj(addr_t _vmobj) {
    auto vmobj = vm_object_t_p(_vmobj);
    DLOG(LOGINDENT"mmaped vmobj *shadow: %p **shadow: %p", (void *)vmobj.shadow().load_addr(), (void *)vmobj.shadow().shadow().load_addr());
    DLOG(LOGINDENT"mmaped vmobj pager: %p shadow pager: %p", (void *)vmobj.pager().load_addr(), (void *)vmobj.shadow().pager().load_addr());
    DLOG(LOGINDENT"mmaped vmobj shadow pager op: %p", (void *)vmobj.shadow().pager().mo_pager_ops().load_addr());
}

void debugprint_pager(addr_t _pager) {
    auto applePager = apple_protect_pager_t_p(_pager);
    DLOG(LOGINDENT"mmaped vme_object apple protect pager: ", NULL)
    DLOG(LOGINDENT"    backingOff %llx",  applePager.backing_offset().load())
    DLOG(LOGINDENT"    cryptoBackingOff %llx", applePager.crypto_backing_offset().load())
    DLOG(LOGINDENT"    cryptoStart %llx", applePager.crypto_start().load())
    DLOG(LOGINDENT"    cryptoEnd %llx", applePager.crypto_end().load())
    DLOG(LOGINDENT"    cryptInfo %p", (void *)applePager.crypt_info().load())
}
#undef LOGINDENT

static int
unprotect(int f, uint8_t *dupe, int cpuType, int cpuSubType, struct encryption_info_command *info, size_t macho_off)
{
#define LOGINDENT "        "
    assert((info->cryptoff & (EXEC_PAGE_SIZE - 1)) == 0);

    DLOG(LOGINDENT"Going to decrypt crypt page: off 0x%x size 0x%x cryptid %d, cpuType %x cpuSubType %x", info->cryptoff, info->cryptsize, info->cryptid, cpuType, cpuSubType);
    //getchar();

    size_t off_aligned = info->cryptoff & ~(PAGE_SIZE - 1);
    //size_t size_aligned = info->cryptsize + info->cryptoff - off_aligned;
    size_t map_padding = info->cryptoff - off_aligned;
    
    int err = 0;
    void *decryptedBuf = malloc(info->cryptsize);

    if (!(info->cryptoff & (PAGE_SIZE - 1))) {
        DLOG(LOGINDENT"Already 16k aligned, directly go ahead :)");
        void *cryptbase = __mmap("16k-aligned", NULL, info->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, info->cryptoff + macho_off);
        // old-school mremap_encrypted
        if (__mremap_encrypted("unprotect", cryptbase, info->cryptsize, info->cryptid, cpuType, cpuSubType)) {
            munmap(cryptbase, info->cryptsize);
            return 1;
        }
        DLOG(LOGINDENT"    copying %p to %p, size %x", (char *)decryptedBuf, cryptbase, info->cryptsize);
        memmove(decryptedBuf, cryptbase, info->cryptsize);
        munmap(cryptbase, info->cryptsize);
    } else {
        DLOG(LOGINDENT"Not 16k aligned, trying to do the hack :O");

        if (!!prepare_kernel()) {
            fprintf(stderr, "Failed to init kerninfra!!\n");
            exit(1);
        } else {
            DLOG(LOGINDENT"successfully initialized kerninfra!");
        }

        for (size_t off = off_aligned; off < info->cryptoff + info->cryptsize; off += PAGE_SIZE) {
            size_t off_end = MIN(off + PAGE_SIZE, info->cryptoff + info->cryptsize);
            size_t curMapLen = (off_end - off) & (PAGE_SIZE - 1); if (!curMapLen) curMapLen = PAGE_SIZE;
            size_t inPageStart = off < info->cryptoff ? info->cryptoff - off : 0;
            size_t inPageEnd = curMapLen;
            size_t cryptOff = off + inPageStart;
            DLOG(LOGINDENT"    processing file off %lx-%lx, curPage len: %lx, inPageStart: %lx, inPageEnd: %lx", off, off_end, curMapLen, inPageStart, inPageEnd);
            char *cryptbase = (char *)__mmap("directly 16k-aligned mmap", NULL, curMapLen, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, off + macho_off);

            if (__mremap_encrypted("unprotect", cryptbase, curMapLen, info->cryptid, cpuType, cpuSubType)) {
                munmap(cryptbase, curMapLen);
                return 1;
            }

            auto curp = proc_t_p(current_proc());
            addr_t _encVmEntry = lookup_vm_map_entry(curp.task()._map().load_addr(), (addr_t)(cryptbase));
            DLOG(LOGINDENT"    Got mmaped entry: %p", (void*)_encVmEntry);
            debugprint_vme(_encVmEntry);

            auto encVmEntry = _vm_map_entry_p(_encVmEntry);
            auto vmobj = encVmEntry.vme_object();
            debugprint_vmobj(vmobj.load_addr());
            auto applePager = apple_protect_pager_t_p(vmobj.shadow().pager().load_addr());
            DLOG(LOGINDENT"    mmaped vme_object apple protect pager: ", NULL);
            debugprint_pager(applePager.addr());

            applePager.crypto_backing_offset().store(macho_off + cryptOff);
            applePager.crypto_start().store(inPageStart);

            DLOG(LOGINDENT"    patched mmaped vme_object apple protect pager: ", NULL)
            debugprint_pager(applePager.addr());
            
            DLOG(LOGINDENT"    copying %p to %p, size %lx", (char *)decryptedBuf + cryptOff - info->cryptoff, cryptbase + inPageStart, curMapLen - inPageStart);
            memmove((char *)decryptedBuf + cryptOff - info->cryptoff, cryptbase + inPageStart, curMapLen - inPageStart);

            munmap(cryptbase, curMapLen);
        }
    }

    if (err) {
        return 1;
    }

    DLOG(LOGINDENT"copying enc pages, size: 0x%x..", info->cryptsize);
    memcpy(dupe + info->cryptoff, decryptedBuf, info->cryptsize);

    DLOG(LOGINDENT"cleaning up...");
    free(decryptedBuf);
    return 0;
#undef LOGINDENT
}

int
decrypt_macho_slide(int f, uint8_t *inputData, uint8_t *outputData, size_t macho_off) {
#define LOGINDENT "    "
    uint32_t offset = 0;
    int cpuType = 0, cpuSubType = 0;
    int ncmds = 0;
    if (*(uint32_t *)inputData == MH_MAGIC_64) { // 64bit
        struct mach_header_64* header = (struct mach_header_64*) inputData;
        cpuType = header->cputype;
        cpuSubType = header->cpusubtype;
        ncmds = header->ncmds;
        offset = sizeof(struct mach_header_64);
    } else if (*(uint32_t *)inputData == MH_MAGIC) { // 32bit
        struct mach_header* header = (struct mach_header*) inputData;
        cpuType = header->cputype;
        cpuSubType = header->cpusubtype;
        ncmds = header->ncmds;
        offset = sizeof(struct mach_header);
    }

    DLOG(LOGINDENT"finding encryption_info segment in slide...");
    
    // Enumerate all load commands and check for the encryption header, if found
    // start "unprotect"'ing the contents.

    struct encryption_info_command *encryption_info = NULL; // for both 32bit and 64bit macho, the command layout are the same
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command* command = (struct load_command*) (inputData + offset);

        if (command->cmd == LC_ENCRYPTION_INFO || command->cmd == LC_ENCRYPTION_INFO_64) {
            DLOG(LOGINDENT"    found encryption_info segment at offset %x", offset);
            encryption_info = (struct encryption_info_command*) command;
            // There should only be ONE header present anyways, so stop after
            // the first one.
            //
            break;
        }

        offset += command->cmdsize;
    }
    if (!encryption_info || !encryption_info->cryptid) {
        DLOG(LOGINDENT"this slide is not encrypted!");
        return 0;
    }
    
    // If "unprotect"'ing is successful, then change the "cryptid" so that
    // the loader does not attempt to decrypt decrypted pages.
    //
    
    DLOG(LOGINDENT"decrypting encrypted data...");
    if (unprotect(f, outputData, cpuType, cpuSubType, encryption_info, macho_off) == 0) {
        encryption_info = (struct encryption_info_command*) (outputData + offset);
        encryption_info->cryptid = 0;
    } else {
        return 1;
    }
    
    return 0;
#undef LOGINDENT
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

    DLOG("copying original data of size 0x%zx...", base_size);
    memcpy(dupe, base, base_size);
    
    int ret = 0;
    if (*(uint32_t *)base == FAT_CIGAM || *(uint32_t *)base == FAT_MAGIC) {
        bool isBe = *(uint32_t *)base == FAT_CIGAM;
        struct fat_header *fat_header = (struct fat_header *) base;
        struct fat_arch *fatarches = (struct fat_arch *) (fat_header + 1);
        auto fatInt = [isBe](int t) -> int {return isBe ? OSSwapInt32(t) : t;};
        
        DLOG("handling %d fat arches...", fatInt(fat_header->nfat_arch));
        for (int fat_i = 0; fat_i < fatInt(fat_header->nfat_arch); fat_i++) {
            auto curFatArch = &fatarches[fat_i];
            DLOG("    handling fat arch %d, cpuType 0x%x, cpuSubType 0x%x, fileOff 0x%x, size 0x%x, align 0x%x", fat_i, 
                fatInt(curFatArch->cputype), fatInt(curFatArch->cpusubtype), fatInt(curFatArch->offset), fatInt(curFatArch->size), fatInt(curFatArch->align));
            ret = decrypt_macho_slide(f, base + fatInt(curFatArch->offset), dupe + fatInt(curFatArch->offset), fatInt(curFatArch->offset));
            if (ret) {
                break;
            }
        }
    } else {
        DLOG("    not fat binary, directly decrypting it!");
        ret = decrypt_macho_slide(f, base, dupe, 0);
    }

    munmap(base, base_size);
    munmap(dupe, dupe_size);
    return ret;
}
