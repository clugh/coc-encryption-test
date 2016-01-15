# coc-encryption-test

Run with:

    python tracer.py -U -i crypto_box_curve25519xsalsa20poly1305_tweet_keypair -i crypto_box_curve25519xsalsa20poly1305_tweet_beforenm -i crypto_box_curve25519xsalsa20poly1305_tweet_afternm -i crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm -i send -i recv -i close -X libNimsWrap.so com.supercell.clashofclans

## Installation

Compile `tweetnacl-usable` with:

    cd tweetnacl-usable
    gcc -fPIC -shared -o tweetnacl.so tweetnacl.h tweetnacl.c randombytes.h randombytes.c

Install Frida with:

    easy_install frida

Install pyblake2 with:

    pip install pyblake2
