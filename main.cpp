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

#include <functional>

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

int swap_pageshift(std::function<int()> cb) {
    // patching kernel task map to allow 4K page (MAGIC)
    auto curp = proc_t_p(current_proc());
    auto vPageShift = curp.task()._map().page_shift();
    DLOG("original page shift: %d", vPageShift.load());
    
    vPageShift.store(12);
    DLOG("new page shift: %d", vPageShift.load());

    int ret = cb();

    // restore kernel task map to 16K page, or it will panic because encrypting compressor's paging
    vPageShift.store(14);
    DLOG("restored page shift: %d", vPageShift.load());
    
    return ret;
}

int swap_csblob(int f, std::function<int()> cb) {
    auto vp = vnode_t_p(vnode_from_fd(f));
    assert(vp.v_type().load() == 1); // == VREG
    
    auto ubcinfo = ubc_info_p(vp.v_un().load());
    auto vCSBlob = ubcinfo.cs_blobs();
    auto oriBlob = vCSBlob.load();
    DLOG("original CSBlob: %p", (void *)oriBlob);

    vCSBlob.store(0);

    int ret = cb();

    vCSBlob.store(oriBlob);
    DLOG("restored CSBlob: %p", (void *)vCSBlob.load());

    return ret;
}

// static int
// unprotect(int f, uint8_t *dupe, struct encryption_info_command_64 *info)
// {
//     assert((info->cryptoff & (EXEC_PAGE_SIZE - 1)) == 0);

//     DLOG("Going to decrypt crypt page: off 0x%x size 0x%x cryptid %d", info->cryptoff, info->cryptsize, info->cryptid);

//     size_t off_aligned = info->cryptoff & ~(PAGE_SIZE - 1);
//     size_t size_aligned = (info->cryptsize & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
//     //size_t size_aligned = info->cryptsize + info->cryptoff - off_aligned;
//     size_t map_offset = info->cryptoff - off_aligned;
    
//     void *cryptbase = NULL; size_t cryptlen = 0; 
//     void *realcryptbase = NULL;
//     int err = 0;

//     if (!(info->cryptoff & (PAGE_SIZE - 1))) {
//         // already 16k aligned, pretty good!
//         DLOG("Already 16k aligned, directly go ahead :)");
//         cryptbase = __mmap("16k-aligned", NULL, size_aligned, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, info->cryptoff);
//         cryptlen = info->cryptsize;
//         realcryptbase = cryptbase;
//         // old-school mremap_encrypted
//         err = __mremap_encrypted("unprotect", cryptbase, info->cryptsize, info->cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);

//     } else {
//         DLOG("Not 16k aligned, trying to do the hack :O");

//         if (!!init_kerninfra()) {
//             fprintf(stderr, "Failed to init kerninfra!!\n");
//             exit(1);
//         } else {
//             DLOG("successfully initialized kerninfra!");
//         }
        
// #define DISABLE_FUN(is_disable, fun, stub) (!is_disable ? (fun) : std::function<decltype(fun)>(stub))

//         if (DISABLE_FUN(true, swap_csblob, [&](int, std::function<int()> cb)->int{return cb();})(f, [&]() -> int 
//         {
//             // void *haystack = __mmap("pre 16k-aligned mmap", NULL, size_aligned, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, off_aligned);
//             // void *haystacktmp = malloc(size_aligned);
//             // memmove(haystacktmp, haystack, size_aligned);

//             // // 16k then patch vme off
//             cryptbase = __mmap("directly 16k-aligned mmap", NULL, map_offset + size_aligned, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, off_aligned);
//             cryptlen = map_offset + info->cryptsize;
//             realcryptbase = (char *)cryptbase + map_offset;

//             // auto curp = proc_t_p(current_proc());
//             // addr_t _encVmEntry = lookup_vm_map_entry(curp.task()._map().load(), (addr_t)cryptbase);
//             // auto encVmEntry = _vm_map_entry_p(_encVmEntry);
//             // DLOG("mmaped vme_offset: 0x%llx", encVmEntry.vme_offset().load());
//             // uint32_t oriFlags = encVmEntry.vme_flags().load();
//             // DLOG("mmaped vme_flags: 0x%x", oriFlags);

//             // encVmEntry.vme_flags().store(oriFlags & ~0x80000u);
//             // encVmEntry.vme_offset().store(info->cryptoff);
//             // DLOG("patched vme with flag %x, offset %llx", encVmEntry.vme_flags().load(), encVmEntry.vme_offset().load());
//             // realcryptbase = cryptbase;
//             // cryptlen = info->cryptsize;

//             void *tmp = malloc(cryptlen);

//             if (DISABLE_FUN(false, swap_pageshift, [&](std::function<int()> cb)->int{return cb();})([&]() -> int 
//             {
//                 // now map the 4K-aligned enc pages, like the good old days
//                 //DLOG("mapping encrypted data pages using off: 0x%x, size: 0x%x", info->cryptoff, info->cryptsize);
                
//                 // cryptbase = __mmap("4k-aligned mmap", NULL, size_aligned, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, info->cryptoff);
//                 // cryptlen = info->cryptsize;
//                 // realcryptbase = (char *)cryptbase;
                
//                 // cryptbase = __mmap("4k-aligned mmap", NULL, info->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, info->cryptoff);
//                 // cryptlen = info->cryptsize;
//                 // realcryptbase = (char *)cryptbase;

//                 cryptbase = __mmap("4k-aligned mmap", NULL, 0x4000, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, 0x1000);
//                 cryptlen = info->cryptsize;
//                 realcryptbase = (char *)cryptbase;

//                 //memmove(tmp, cryptbase, cryptlen);    

//                 if (cryptbase == MAP_FAILED) {
//                     return 1;
//                 }

//                 /*oribase = __mmap("re-mmap 4k aligned", oribase, size_aligned - map_offset, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, f, info->cryptoff);
//                 if (oribase == MAP_FAILED) {
//                     return 1;
//                 }*/

//                 //err = __mremap_encrypted("unprotect", cryptbase, cryptlen, info->cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
//                 //err = __mremap_encrypted("unprotect", realcryptbase, size_aligned, info->cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
//                 getchar();
//                 //memmove(tmp, realcryptbase, info->cryptsize);
//                 return 0;
//             }
//             )) return 1;

//             /**/
//             //return 1;
                

//             return 0;
//         }
//         )) return 1;
//     }

//     char test[0x1000] = {0};
//     memmove(test, cryptbase, 0x1000);

//     getchar();

//     if (err) {
//         //perror("mremap_encrypted(unprotect)");
//         //munmap(cryptbase, cryptlen);
//         return 1;
//     }

//     DLOG("copying enc pages, size: 0x%x..", info->cryptsize);
//     memcpy(dupe + info->cryptoff, realcryptbase, info->cryptsize);

//     DLOG("cleaning up...");
//     //munmap(cryptbase, cryptlen);

//     return 0;
// }

void debugprint_vme(addr_t _vmentry) {
    auto encVmEntry = _vm_map_entry_p(_vmentry);
    DLOG("mmaped entry: %p - %p", (void *)encVmEntry.start().load(), (void *)encVmEntry.end().load());
    DLOG("mmaped vme_offset: 0x%llx", encVmEntry.vme_offset().load());
    DLOG("mmaped vme_flags: 0x%x", encVmEntry.vme_flags().load());
    DLOG("mmaped vme_object: 0x%llx", encVmEntry.vme_object().load());
}

void debugprint_vmobj(addr_t _vmobj) {
    auto vmobj = vm_object_t_p(_vmobj);
    DLOG("mmaped vmobj *shadow: %p **shadow: %p", (void *)vmobj.shadow().load_addr(), (void *)vmobj.shadow().shadow().load_addr());
    DLOG("mmaped vmobj pager: %p shadow pager: %p", (void *)vmobj.pager().load_addr(), (void *)vmobj.shadow().pager().load_addr());
    DLOG("mmaped vmobj shadow pager op: %p", (void *)vmobj.shadow().pager().mo_pager_ops().load_addr());
}

void debugprint_pager(addr_t _pager) {
    auto applePager = apple_protect_pager_t_p(_pager);
    DLOG("mmaped vme_object apple protect pager: ", NULL)
    DLOG("    backingOff %llx",  applePager.backing_offset().load())
    DLOG("    cryptoBackingOff %llx", applePager.crypto_backing_offset().load())
    DLOG("    cryptoStart %llx", applePager.crypto_start().load())
    DLOG("    cryptoEnd %llx", applePager.crypto_end().load())
    DLOG("    cryptInfo %p", (void *)applePager.crypt_info().load())
}

static int
unprotect(int f, uint8_t *dupe, struct encryption_info_command_64 *info)
{
    assert((info->cryptoff & (EXEC_PAGE_SIZE - 1)) == 0);

    DLOG("Going to decrypt crypt page: off 0x%x size 0x%x cryptid %d", info->cryptoff, info->cryptsize, info->cryptid);

    size_t off_aligned = info->cryptoff & ~(PAGE_SIZE - 1);
    //size_t size_aligned = info->cryptsize + info->cryptoff - off_aligned;
    size_t map_padding = info->cryptoff - off_aligned;
    
    int err = 0;
    void *decryptedBuf = malloc(info->cryptsize);

    if (!(info->cryptoff & (PAGE_SIZE - 1))) {
        // already 16k aligned, pretty good!
        DLOG("Already 16k aligned, directly go ahead :)");
        void *cryptbase = __mmap("16k-aligned", NULL, info->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, info->cryptoff);
        // old-school mremap_encrypted
        if (__mremap_encrypted("unprotect", cryptbase, info->cryptsize, info->cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)) {
            munmap(cryptbase, info->cryptsize);
            return 1;
        }
        memmove(decryptedBuf, cryptbase, info->cryptsize);
        munmap(cryptbase, info->cryptsize);
    } else {
        DLOG("Not 16k aligned, trying to do the hack :O");

        if (!!init_kerninfra()) {
            fprintf(stderr, "Failed to init kerninfra!!\n");
            exit(1);
        } else {
            DLOG("successfully initialized kerninfra!");
        }

        for (size_t off = off_aligned; off < info->cryptoff + info->cryptsize; off += PAGE_SIZE) {
            size_t off_end = MIN(off + PAGE_SIZE, info->cryptoff + info->cryptsize);
            size_t curMapLen = (off - off_end) & (PAGE_SIZE - 1); if (!curMapLen) curMapLen = PAGE_SIZE;
            char *cryptbase = (char *)__mmap("directly 16k-aligned mmap", NULL, curMapLen, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, off);
            size_t inPageStart = off < info->cryptoff ? info->cryptoff - off : 0;
            size_t inPageEnd = curMapLen;
            size_t cryptOff = off + inPageStart;

            if (__mremap_encrypted("unprotect", cryptbase, curMapLen, info->cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)) {
                munmap(cryptbase, curMapLen);
                return 1;
            }

            auto curp = proc_t_p(current_proc());
            addr_t _encVmEntry = lookup_vm_map_entry(curp.task()._map().load_addr(), (addr_t)(cryptbase));
            DLOG("Got mmaped entry: %p", (void*)_encVmEntry);
            debugprint_vme(_encVmEntry);

            auto encVmEntry = _vm_map_entry_p(_encVmEntry);
            auto vmobj = encVmEntry.vme_object();
            debugprint_vmobj(vmobj.load_addr());
            auto applePager = apple_protect_pager_t_p(vmobj.shadow().pager().load_addr());
            DLOG("mmaped vme_object apple protect pager: ", NULL);
            debugprint_pager(applePager.addr());

            applePager.crypto_backing_offset().store(cryptOff);
            applePager.crypto_start().store(inPageStart);

            DLOG("patched mmaped vme_object apple protect pager: ", NULL)
            debugprint_pager(applePager.addr());
            
            memmove((char *)decryptedBuf + cryptOff - info->cryptoff, cryptbase + inPageStart, curMapLen);

            munmap(cryptbase, curMapLen);
        }
    }

    if (err) {
        return 1;
    }

    DLOG("copying enc pages, size: 0x%x..", info->cryptsize);
    memcpy(dupe + info->cryptoff, decryptedBuf, info->cryptsize);

    DLOG("cleaning up...");
    free(decryptedBuf);
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
    } else {
        return 1;
    }

    munmap(base, base_size);
    munmap(dupe, dupe_size);
    return 0;
}