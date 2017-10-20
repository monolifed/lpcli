# Lesspassc
C implementation of lesspass (version 2) using openssl's crypto library.

Command line options are similar to the official cli:
https://github.com/lesspass/cli/

# Building
Install openssl dev package and type "make -e USE_OSSL_DEV=1".
You can also edit the makefile and set CRYPTO_SO to the libcrypto.so file on your system.

# Building on Windows with Mingw
If you are using an openssl dev library you should set USE_OSSL_DEV to 1 and 
change WIN_OSSL_DEV_PATH and WIN_OSSL_DEV_DLL in the makefile.

Otherwise set USE_OSSL_DEV to 0 and change WIN_OSSL_DLL_PATH and WIN_OSSL_DLL instead.

Check: https://wiki.openssl.org/index.php/Binaries .

# Misc
For an incomplete luajit version check:
https://gist.github.com/monolifed/e723aefb5043ccc1b817793e8502d69b
