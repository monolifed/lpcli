# Lesspassc
C implementation of lesspass (version 2) using openssl's crypto library.

Command line options are similar to the official cli:
https://github.com/lesspass/cli/

# Caveat
~~If your terminal encoding is not UTF-8 you might get different results than lesspass web for the same parameters.~~
On linux, if your encoding is not UTF8, for some values provided on command line, you may get different results than of lesspass.
You can use something like ``./lpcli `echo [site] [login] [password]|iconv -t UTF-8` `` as a work around 

# Building
Install openssl dev package and type "make -e USE_OSSL_DEV=1".

You can also edit the Makefile, set CRYPTO_SO to the libcrypto.so file available on your system and type "make".

# Building on Windows with Mingw
Copying "libeay32.dll" (which can be found in openssl or curl binary distributions)
to the same directory and typing "mingw32-make" should be sufficient.

If your dll has a different name and path,
you should change WIN_OSSL_DLL and WIN_OSSL_DLL_PATH in the Makefile.

If you are using openssl library, you should set USE_OSSL_DEV to 1 and 
change WIN_OSSL_DEV_PATH and WIN_OSSL_DEV_DLL in the Makefile.

Check: https://wiki.openssl.org/index.php/Binaries
.

# Misc
For an incomplete luajit version check:
https://gist.github.com/monolifed/e723aefb5043ccc1b817793e8502d69b
