# coc-encryption-test

Run with:

    python test.py session-xxxxx.json

## Dependencies

[blake2_py](https://github.com/buggywhip/blake2_py)
[tweetnacl-usable](https://github.com/ultramancool/tweetnacl-usable)

**Note:** You can compile tweetnacl-usable with:

    gcc -fPIC -shared -o tweetnacl.so tweetnacl.h tweetnacl.c randombytes.h randombytes.c
