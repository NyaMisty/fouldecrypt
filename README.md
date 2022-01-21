# FoulDecrypt

It's also available in my Cydia repo: http://repo.misty.moe. FoulDecrypt supports iOS 13.5 and later, and has been tested on iOS 14.2, 14.3 and 13.5 (both arm64 and arm64e).

Note: for unsupported versions, it has chances to panic the device, beware ;)

## Why FoulDecrypt

### 1. Fully static

Thanks to FlexDecrypt and FoulPlay we know there's a mremap_encrypted syscall, although AAPL already released full source code for this syscall now.

However, neither of them can actually get mremap_encrypted to work. That's because mremap_encrypted cannot accept non-aligned address, making it useless for most iOS 14 apps.

I managed to fix with kernel read/writing, so now we can achieve clutch's armv7+arm64 multi-arch decryption again in 2021!

### 2. Simplicity

FlexDecrypt's source code is pretty FAT, bundling the whole swift runtime to just achieve a simple mremap_encrypted.

And at the same time, foulplay independently found the same approach, and implemented it in a much more simple way.

I recompiled the foulplay for iOS, and a wrapper `flexdecrypt2` for flexdecrypt.

## How to use

Install the correct version:
- `fouldecrypt-TFP0` for < iOS 14
- `fouldecrypt-LIBKRW` if you are running Unc0ver
- `fouldecrypt-LIBKERNRW` if you are running Taurine

Run `fouldecrypt` on an encrypted binary.

## About `foulwrapper`

`foulwrapper` will find all Mach-Os in a specific application and decrypt them using `fouldecrypt`:

`usage: foulwrapper (application name or bundle identifier)`

## Credits
@meme: foulplay
@JohnCoates: flexdecrypt
