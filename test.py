from ctypes import c_char_p, c_ulonglong, POINTER, CDLL, create_string_buffer
from blake2 import BLAKE2b
import json
import binascii
import array
import argparse

tweetnacl = CDLL("./tweetnacl.so")
tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm.argtypes = (c_char_p, c_char_p, c_char_p)
tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet.argtypes = (c_char_p, c_char_p, c_ulonglong, c_char_p, c_char_p)
tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet_open.argtypes = (c_char_p, c_char_p, c_ulonglong, c_char_p, c_char_p)

def crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(pk, sk):
  global tweetnacl
  s = create_string_buffer(32)
  tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(s, c_char_p(pk), c_char_p(sk))
  return s

def crypto_secretbox_xsalsa20poly1305_tweet(message, nonce, s):
  global tweetnacl
  length = len(message)
  ciphertext = create_string_buffer(length)
  tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet(ciphertext, c_char_p(message), c_ulonglong(length), c_char_p(nonce), s)
  return ciphertext

def crypto_secretbox_xsalsa20poly1305_tweet_open(ciphertext, nonce, s):
  global tweetnacl
  length = len(ciphertext)
  message = create_string_buffer(length)
  tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet_open(message, c_char_p(ciphertext), c_ulonglong(length), c_char_p(nonce), s)
  return message

def increment_nonce(nonce):
  arr = array.array('B', nonce)
  bump = 2
  for i in xrange(len(arr) - 1):
    if (arr[i] + bump) > 0xff:
      arr[i] = (arr[i] + bump) % 0xff
      bump = 1
    else:
      arr[i] = arr[i] + bump
      break
  return arr.tostring()

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Encryption Test")
  parser.add_argument("json", type=str, help="a JSON session file")
  args = parser.parse_args()

  if args.json:
    with open(args.json) as session:
      try:
        events = json.load(session)
      except:
        raise
      else:
        serverkey = None
        pk = None
        sk = None
        s = None
        k = None
        snonce = None
        rnonce = None
        for event in events:
          if event["type"] == "send" or event["type"] == "recv":
            if event["messageid"] == "2774":
              continue
            elif event["messageid"] == "4e84":
              continue
            else:
              if serverkey:
                if pk:
                  if sk:
                    if event["messageid"] == "2775":
                      b2 = BLAKE2b(digest_size=24)
                      b2.update(pk)
                      b2.update(serverkey)
                      nonce = b2.final()
                      message = event["message"].decode("hex")
                      s = crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(serverkey, sk)
                      ciphertext = crypto_secretbox_xsalsa20poly1305_tweet(message, nonce, s)
                      if binascii.hexlify(ciphertext) ==  event["ciphertext"]:
                        print "2775 ciphertext matches"
                      else:
                        print "Warning: 2775 ciphertext does not match"
                      snonce = message[56:80]
                    elif snonce:
                      if event["messageid"] == "4e88":
                        if s:
                          b2 = BLAKE2b(digest_size=24)
                          b2.update(snonce)
                          b2.update(pk)
                          b2.update(serverkey)
                          nonce = b2.final()
                          ciphertext = event["ciphertext"].decode("hex")
                          message = crypto_secretbox_xsalsa20poly1305_tweet_open(ciphertext, nonce, s)
                          if binascii.hexlify(message) == event["message"]:
                            print "4e88 message matches"
                          else:
                            print "Warning: 4e88 message does not match"
                          rnonce = message[32:56]
                          k = message[56:88]
                        else:
                          raise Exception("Missing s.")
                      else:
                        if rnonce:
                          if k:
                            if event["type"] == "send":
                              snonce = increment_nonce(snonce)
                              message = event["message"].decode("hex")
                              ciphertext = crypto_secretbox_xsalsa20poly1305_tweet(message, snonce, k)
                              if binascii.hexlify(ciphertext) ==  event["ciphertext"]:
                                print "{} ciphertext matches".format(event["messageid"])
                              else:
                                print "Warning: {} ciphertext does not match".format(event["messageid"])
                            elif event["type"] == "recv":
                              rnonce = increment_nonce(rnonce)
                              ciphertext = event["ciphertext"].decode("hex")
                              message = crypto_secretbox_xsalsa20poly1305_tweet_open(ciphertext, rnonce, k)
                              if binascii.hexlify(message) == event["message"]:
                                print "{} message matches".format(event["messageid"])
                              else:
                                print "Warning: {} message does not match".format(event["messageid"])
                          else:
                            raise Exception("Missing k.")
                        else:
                          raise Exception("Missing rnonce.")
                    else:
                      raise Exception("Missing snonce.")
                  else:
                    raise Exception("Missing secret key.")
                else:
                  raise Exception("Missing public key.")
              else:
                raise Exception("Missing server key.")
          elif event["type"] == "keypair":
            pk = event["pk"].decode("hex")
            sk = event["sk"].decode("hex")
          elif event["type"] == "crypto_box":
            serverkey = event["serverkey"].decode("hex")
          else:
            raise Exception("Invalid event type.")
  else:
    print "Warning: No file provided."