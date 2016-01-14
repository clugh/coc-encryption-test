# coc-encryption-test

Run with:

    python tracer.py -U -i crypto_box_curve25519xsalsa20poly1305_tweet_keypair -i crypto_box_curve25519xsalsa20poly1305_tweet -i crypto_secretbox_xsalsa20poly1305_tweet -i crypto_secretbox_xsalsa20poly1305_tweet_open -i send -i recv -i close -X libNimsWrap.so com.supercell.clashofclans

## Installation

Compile `tweetnacl-usable` with:

    cd tweetnacl-usable
    gcc -fPIC -shared -o tweetnacl.so tweetnacl.h tweetnacl.c randombytes.h randombytes.c
