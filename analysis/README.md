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

And what's the most confusing is that FlexDecrypt switched to use the old posix_spawn on iOS 14, without outputing any logs.


## TL;DR

1. Well the mremap_encrypted didn't fail at all after iOS 14. But it's true that dyld now doesnt't uses mremap_encrypted to decrypt the binary.
2. The reason you can's simply pass the cryptsize into the mremap_encrypted is because now it requires the input address to be page-aligned.
3. NEVER manually rebuild a file: in fact it's totally useless to simulate the dyld, because dyld is actually just simply mapping that segment, and call the decryption. it's even more useless to manually rebuild the whole MachO

## How I solved it

1. I started by adapting @meme's foulplay to iOS, which failed at unprotect()'s mmap. And that's actually because the size is not page-aligned. I quickly figured it out and fixed, but then the mremap_encrypted failed with "Invalid argument", and there the nightmare began.
2. I thought it's because dyld has some special call before hand, so I throroughly reverse engineered dyld's mapping process, and found it would append HUGETLB flag and uses fcntl to do speculative read. However that doesnt's work at all.
3. I wanted to debug the dyld, but it's pretty hard, especially on iOS. Then I remembered that the kdv can prints out all bsd syscall, so I recompiled it and adapted it to arm64e, but I found nothing but many calls to mremap_encrypted with cryptid==0, which is apparently uselss. 
4. Then I found now the MachO mapping is now directly handled by kernel, without going through the dyld. So instead I reviewed the mremap_encrypted's source code, and found out that it should return either OK or EPERM, unless a series of precondition failed.
5. Interestingly, those preconditions are actually almost the same as proc_pidinfo's PROC_PIDREGIONPATHINFO2, so I manually forged a call to it, and magically, the call succeed. And after comparing two functions, the only differences, is acturally mremap_encrypted checked if the input address are page-aligned, which it doesn't before.
6. so now I adapted the foulplay for iOS, and is available on my repo ;)

