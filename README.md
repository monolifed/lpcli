# LPCLI
C implementation of lesspass (version 2) using openssl's crypto library.


## Usage

```
$./lpcli
Usage: lpcli <site> [login] [options]
Options:
  --lowercase, -l     include lowercase characters
  --uppercase, -u     include uppercase characters
  --digits, -d        include digits
  --symbols, -s       include symbols

  --length, -n        number of characters (16)
  --counter, -c       number to add to salt (1)

  --print, -p         print instead of copying to clipboard.
                      xclip is required to copy to clipboard on linux.
Notes:
  If none of l,u,d or s specified, luds is assumed.
  You can type short options without spaces. e.g. -ludn32c5p

```

## Building
Install openssl dev package and type "make -e USE_OSSL_DEV=1".

You can also edit the Makefile, set CRYPTO_SO to the libcrypto.so file available on your system and type "make".

## Building on Windows with Mingw
Copying "libeay32.dll" (which can be found in openssl or curl binary distributions)
to the same directory and typing "mingw32-make" should be sufficient.

If your dll has a different name and path,
you should change WIN_OSSL_DLL and WIN_OSSL_DLL_PATH in the Makefile.

If you are using openssl library, you should set USE_OSSL_DEV to 1 and 
change WIN_OSSL_DEV_PATH and WIN_OSSL_DEV_DLL in the Makefile.

Check: https://wiki.openssl.org/index.php/Binaries
.

## Misc
For an incomplete luajit version check:
https://gist.github.com/monolifed/e723aefb5043ccc1b817793e8502d69b
