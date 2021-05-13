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
#include <dlfcn.h>

#define PRIVATE 1
#include <libproc.h>

#include <mach/mach.h>
#include <mach/vm_map.h>

#define MAP_HUGETLB 0x40000

extern "C" int mremap_encrypted(void*, size_t, uint32_t, uint32_t, uint32_t);

static int
unprotect(vm_address_t cryptaddr, struct encryption_info_command_64 *info)
{
    vm_address_t cryptaddr_align = cryptaddr & ~0x3fff;
    /*
    struct proc_regionwithpathinfo	rwpi;
    int buf_used = proc_pidinfo(getpid(), PROC_PIDREGIONPATHINFO2, cryptaddr_align, &rwpi, sizeof(rwpi));
    if (buf_used <= 0) {
        perror("proc_pidinfo(unprotect)");
    }
    printf("proc_pidinfo: ret %d, rwpi \n", buf_used);*/
    int error = mremap_encrypted((void *)cryptaddr_align, info->cryptsize + (cryptaddr - cryptaddr_align), info->cryptid, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
    if (error) {
        perror("mremap_encrypted(unprotect)");
        printf("cryptaddr: %p, cryptsize: 0x%x\n", (void *)cryptaddr, info->cryptsize);
        //printf("cryptaddr: %p, cryptsize: 0x%x, cryptdata: %p\n", (void *)cryptaddr, info->cryptsize, *(void **)cryptaddr);
        //munmap(base, info->cryptsize);
        return 1;
    }

    return 0;
}

static vm_address_t dylib_map(const char *inputFile, void *base) { // returns slide
    int f = open(inputFile, O_RDONLY);
    struct stat s;
    if (fstat(f, &s) < 0) {
        perror("fstat(map)");
        close(f);
        return 0;
    }
    
    int fcntlarg[3] = { 0 };
    fcntlarg[0] = 0;
    fcntlarg[1] = 0;
    fcntlarg[2] = s.st_size;
    fcntl(f, F_SPECULATIVE_READ, fcntlarg);

    struct mach_header_64* header = (struct mach_header_64*) base;
    assert(header->magic == MH_MAGIC_64);
    assert(header->cputype == CPU_TYPE_ARM64);
    assert(header->cpusubtype == CPU_SUBTYPE_ARM64_ALL);

    // Enumerate all load commands and check for the encryption header, if found
    // start "unprotect"'ing the contents.
    //
    vm_address_t minAddr = (vm_address_t)-1;
    vm_address_t maxAddr = 0;

    for (uint32_t offset = sizeof(struct mach_header_64), i = 0; i < header->ncmds; i++) {
        struct load_command* command = (struct load_command*) (base + offset);
        offset += command->cmdsize;

        if (command->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg =
                (struct segment_command_64*) command;
            printf("Got seg %s\n", seg->segname);
            if (!seg->vmaddr || !seg->filesize) continue;
            if (seg->vmaddr < minAddr) {
                minAddr = seg->vmaddr;
            }
            if (seg->vmaddr + seg->vmsize > maxAddr) {
                maxAddr = seg->vmaddr + seg->vmsize;
            }
        }
    }
    printf("maxAddr: %p, minAddr: %p\n", (void *)maxAddr, (void *)minAddr);
    size_t vmRangeSize = maxAddr - minAddr;
    
    vm_address_t allocAddr = 0;
    kern_return_t err = vm_allocate(mach_task_self(), &allocAddr, vmRangeSize, VM_FLAGS_ANYWHERE | (VM_MEMORY_DYLIB << 24));
    if (err) {  
        perror("vm_allocate(map)");
        close(f);
        return 0;
    }
    vm_address_t dybase = (vm_address_t)mmap((void *)allocAddr, vmRangeSize, VM_PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0, 0);
    vm_address_t slide = dybase - minAddr;
    for (uint32_t offset = sizeof(struct mach_header_64), i = 0; i < header->ncmds; i++) {
        struct load_command* command = (struct load_command*) (base + offset);
        offset += command->cmdsize;
        
        if (command->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg =
                (struct segment_command_64*) command;
            if (!seg->vmaddr || !seg->filesize) continue;
            printf("mmaping seg %s, addr %p, prot %d, size 0x%llx\n", seg->segname, (void *)(seg->vmaddr + slide), seg->initprot, seg->filesize);
            if (mmap((void *)(seg->vmaddr + slide), seg->filesize, seg->initprot, MAP_PRIVATE | MAP_FIXED | MAP_HUGETLB, f, seg->fileoff) == MAP_FAILED) {
                perror("mmap(dylib_map)");
                exit(1);
            }
        }

    }
    fcntlarg[0] = 0;
    fcntlarg[1] = 0;
    fcntlarg[2] = s.st_size;
    fcntl(f, F_SPECULATIVE_READ, fcntlarg);
    close(f);
    return slide;
}

        

static uint8_t*
map(const char *path, bool mutable, size_t *size, int *descriptor)
{
    int f = -1;
    if (mutable) {
        f = open(path, O_RDWR | O_CREAT, 0755);
    } else {
        f = open(path, O_RDONLY, 0755);
    }
    
    if (f < 0) {
        perror("open(map)");
        return NULL;
    }
    if (mutable) {
        if (ftruncate(f, *size) < 0) {
            perror("ftruncate(map)");
            close(f);
            return NULL;
        }
    }

    struct stat s;
    if (fstat(f, &s) < 0) {
        perror("fstat(map)");
        close(f);
        return NULL;
    }
    
    vm_address_t allocAddr = 0;
    uint8_t *base = NULL;
    if (!mutable) {
        base = mmap((void *)allocAddr, s.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    } else {
        base = mmap((void *)allocAddr, s.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, f, 0);
    }

    if (base == MAP_FAILED) {
        perror("mmap(map)");
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
    dlopen(inputFile, RTLD_LOCAL);
    printf("mapping input\n");
    // map RO one for decrypt
    size_t base_size;
    //int f;
    uint8_t *base = map(inputFile, false, &base_size, NULL);
    if (base == NULL) {
        return 1;
    }
    
    printf("mapping output\n");
    // map RW one for modify
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

    struct mach_header_64* header = (struct mach_header_64*) base;

    // Enumerate all load commands and check for the encryption header, if found
    // start "unprotect"'ing the contents.
    //
    struct encryption_info_command_64 *encryption_info = NULL;
    for (uint32_t offset = sizeof(struct mach_header_64), i = 0; i < header->ncmds; i++) {
        struct load_command* command = (struct load_command*) (base + offset);

        if (command->cmd == LC_ENCRYPTION_INFO_64) {
            encryption_info = (struct encryption_info_command_64*) command;
            // If "unprotect"'ing is successful, then change the "cryptid" so that
            // the loader does not attempt to decrypt decrypted pages.
            //
            // There should only be ONE header present anyways, so stop after
            // the first one.
            //
            break;
        }

        offset += command->cmdsize;
    }
    
    struct segment_command_64 *target_seg = NULL;
    for (uint32_t offset = sizeof(struct mach_header_64), i = 0; i < header->ncmds; i++) {
        struct load_command* command = (struct load_command*) (base + offset);

        if (command->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64*) command;
            if (seg->fileoff <= encryption_info->cryptoff && encryption_info->cryptoff + encryption_info->cryptsize <= seg->fileoff + seg->filesize) {
                target_seg = seg;
                break;
            }
        }

        offset += command->cmdsize;
    }
    
    if (!encryption_info || !target_seg) {
        printf("malformed macho! encryption_info: %p, target_seg: %p\n", encryption_info, target_seg);
        exit(2);
    }

    printf("mapping dylib\n");
    vm_address_t slide = dylib_map(inputFile, base);
    printf("got slide: %p\n", (void *)slide);
    printf("firstdata: %p\n", *(void **)(0x100000000 + slide));
    

    vm_address_t cryptaddr = slide + target_seg->vmaddr + (encryption_info->cryptoff - target_seg->fileoff);
    if (unprotect(cryptaddr, encryption_info) == 0) {
        printf("copying ori data\n");
        memcpy(dupe, base, base_size);
        encryption_info = (struct encryption_info_command_64*) ((uint8_t *)encryption_info + (dupe - base));
        encryption_info->cryptid = 0;
        printf("copying decrypted data\n");
        memcpy(dupe + encryption_info->cryptoff, (void *)cryptaddr, encryption_info->cryptsize);
    }

    munmap(base, base_size);
    munmap(dupe, dupe_size);
    return 0;
}

int
main(int argc, char* argv[])
{
    @autoreleasepool {
        printf("%d\n", getpid());
        getchar();
        if (argc < 3) {
            return 1;
        }
        return decrypt_macho(argv[1], argv[2]);
    }
}
