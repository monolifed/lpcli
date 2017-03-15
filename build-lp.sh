LCRYPTO_PATH=`locate -bl 1 libcrypto.so`
LCRYPTO=`basename $LCRYPTO_PATH`
echo Using $LCRYPTO
gcc -Wall -Wextra -pedantic -std=c99 -o lp lp.c lptest.c -l :$LCRYPTO
./lp site login pass
