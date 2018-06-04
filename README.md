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
  --counter, -c       numeric suffix of salt (1)

  --print, -p         print instead of copying to clipboard.
                      xclip is required to copy to clipboard on linux.
Notes:
  If none of l,u,d or s specified, luds is assumed.
  You can type short options without spaces. e.g. -ludn32c5p
  Length is between 5 and 35 and counter is greater than 0.
  Salt is site..login..hex(counter) where ".." is concatenation.
  Thus using an empty login or omitting it gives the same result.
```

Do not forget to check that you get the same password with both this one and lesspass.


## Misc
For an incomplete luajit version check:
https://gist.github.com/monolifed/e723aefb5043ccc1b817793e8502d69b
