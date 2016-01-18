# coc-encryption-test

Run with:

    python tracer.py -U -i crypto_box_curve25519xsalsa20poly1305_tweet_keypair -i crypto_box_curve25519xsalsa20poly1305_tweet_beforenm -i crypto_box_curve25519xsalsa20poly1305_tweet_afternm -i crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm -i randombytes -i send -i recv -i close -X libNimsWrap.so com.supercell.clashofclans

## Installation

Install `Frida` with:

    pip install frida

Install `pynacl` with:

    pip install pynacl

Note: `pynacl` depends on `ccfi`

Install `pyblake2` with:

    pip install pyblake2
