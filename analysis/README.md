# Analysis note

## What have I done

I reverse engineered the following componenets:

1. dyld itself
2. libSystem.B.dylib
3. iOS Kernel itself


## What's the problem

In fact flexdecrypt is just shooting his own foot. FlexDecrypt is too FAT, I just can't understand why an approach as simple as foulplay's original code would have to write so much code.

In case you don't know, FlexDecrypt simulated the dyld, mapping all segments into the place, and then rebuilded the whole MachO, although the only place needs to be changed is the encrypted ares (which would always have only one).

What's worse, his rebuild logic has bug, which makes a slightest malform MachO killing the whole decrypting process.

And what's the most confusing is that FlexDecrypt will automatically switch to posix_spawn approach when cryptoff is not 16K-aligned, without outputing any logs.


## TL;DR

1. mremap_encrypted has always been broken, flexdecrypt only use it when the cryptoff is aligned, or it silently switches to posix_spawn approach. And in fact, dyld is already not using it to map the framework.
2. The reason you can's simply pass the mapped page into mremap_encrypted is because it requires the input address to be page-aligned (16K aligned). 
3. but mmap also require the input file offset to be page-aligned (16K). so if we don't patch something, we will never successfully remap and decrypt a unaligned crypt area.
4. by patching the apple_protect_pager setup by mremap_encrypted, we can fix the mremap_encrypted, and then achieve our goal.

N. NEVER manually rebuild a file: in fact it's totally useless to simulate the dyld, because dyld is actually just simply mapping that segment, and call the decryption. it's even more useless to manually rebuild the whole MachO

## How I solved it

1. I started by adapting @meme's foulplay to iOS, which failed at unprotect()'s mmap. And that's actually because the size is not page-aligned. I quickly figured it out and fixed, but then the mremap_encrypted failed with "Invalid argument", and there the nightmare began.
2. I thought it's because dyld has some special call before hand, so I throroughly reverse engineered dyld's mapping process, and found it would append HUGETLB flag and uses fcntl to do speculative read. However that doesnt's work at all.
3. I wanted to debug the dyld, but it's pretty hard, especially on iOS. Then I remembered that the kdv can prints out all bsd syscall, so I recompiled it and adapted it to arm64e, but I found nothing but many calls to mremap_encrypted with cryptid==0, which is apparently uselss. 
4. Then I found now the MachO mapping is now directly handled by kernel, without going through the dyld. So instead I reviewed the mremap_encrypted's source code, and found out that it should return either OK or EPERM, unless a series of precondition failed.
5. Interestingly, those preconditions are actually almost the same as proc_pidinfo's PROC_PIDREGIONPATHINFO2, so I manually forged a call to it, and magically, the call succeed. And after comparing two functions, the only differences, is acturally mremap_encrypted checked if the input address are page-aligned, which it doesn't before.
6. then I thought I successfully adapted the foulplay for iOS. But then I found it's not outputting correct decrypted data. And now the nightmare just begins.
7. as we can see, the workflow is simply mmap -> mremap_encrypted -> memcpy. The problem is how to introduce a 16K-unaligned offset. I proposed three ways:
    - force the mmap to map the file with a 4K aligned address
    - force the mremap_encrypted to decrypt the file with a 4K aligned base
    - mmap & mremap_encrypted, but use mach_vm_remap to move a 4K-aligned address to 16K-aligned address

8. In order to force map a 4K-aligned file offset, we need to change our process's vm_map into a 4K one, which can be achieved by setting page_shift from 14 to 12. It's also possible to change page's vm_map_entry, and replace vme_object's offset.
9. I first tried to forced mmap to map 0x1000 offset of file, sometimes it succeeded (but gives wrong output), sometimes it hangs, sometimes it panic the device.
10. after examining the panic report, I thought it's pmap_cs_associate's check caused the problem, and I found it's controlled by vnode's ubc_info->cs_blobs. so I removed csblobs and tried again, still no luck.
11. actually I combined various options and tested hundreds of cases, you can have a look at the trace in the `find_working` branch:
    - mmap related: mmap aligned offset, mmap unaligned offset with patching page_shift, mmap unaligned offset with vme_offset patch
    - mremap related: whether to clear cs_blobs, whether to call it with patching page_shift, whether to call it with aligned address
    - magic: whether to read the mapped crypt area first, whether to map the crypt area one more time, whether to map segment like dyld
12. after 4 days of experiment, I realized it's not possible to directly tamper with the page size. The reason is in the kernel most places are hardcoded with a pagesize of 16K, so even if I bypassed the mmap check, bypassed the pmap_cs check, I'll still be killed by checks happening in real read ops, which will check physcial address and virtual address's aligness against hardcoded pagesize. And that means in no way can I really map a 4K pages with some simple patch.
13. Then I carefully examined mremap_encrypted's implementation. Its main logic is:
    - find area's corresponding vnode
    - find each vnode pages within the range
    - identify crypt_start/crypt_end (the start and end offset in page that actually need to be decrypted (e.g. you want to decrypt 0x5000-0x6000, then you are actually decrypting page 0x4000's 0x1000-0x2000) ), crypto_backing_offset (the offset used to init the cipher)
    - finally setup the decrypt pager for that page. 
14. So I realized I can actually mremap_encrypted using aligned address, and then patch the decrypt pager to cover only part of them. And the correct setup can be seen from set_code_unprotec() function. With this approach I finally successfully decrypt the page and got the right output.