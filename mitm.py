from blake2_py.blake2 import BLAKE2b
import json
import binascii
import array

from ctypes import c_char_p, c_ulonglong, CDLL, create_string_buffer

_tweetnacl = CDLL("./tweetnacl-usable/tweetnacl.so")
_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_keypair.argtypes = (c_char_p, c_char_p)
_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm.argtypes = (c_char_p, c_char_p, c_char_p)
_tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet.argtypes = (c_char_p, c_char_p, c_ulonglong, c_char_p, c_char_p)
_tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet_open.argtypes = (c_char_p, c_char_p, c_ulonglong, c_char_p, c_char_p)

def crypto_box_curve25519xsalsa20poly1305_tweet_keypair():
  global _tweetnacl
  pk = create_string_buffer(32)
  sk = create_string_buffer(32)
  _tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_keypair(pk, sk)
  return (pk, sk)

def crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(pk, sk):
  global _tweetnacl
  s = create_string_buffer(32)
  _tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(s, c_char_p(pk), c_char_p(sk))
  return s

def crypto_secretbox_xsalsa20poly1305_tweet(message, nonce, s):
  global _tweetnacl
  length = len(message)
  ciphertext = create_string_buffer(length)
  _tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet(ciphertext, c_char_p(message), c_ulonglong(length), c_char_p(nonce), s)
  return ciphertext

def crypto_secretbox_xsalsa20poly1305_tweet_open(ciphertext, nonce, s):
  global _tweetnacl
  length = len(ciphertext)
  message = create_string_buffer(length)
  _tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet_open(message, c_char_p(ciphertext), c_ulonglong(length), c_char_p(nonce), s)
  return message

class mitm:

  serverkey = None
  pk = None
  sk = None
  s = None
  k = None
  snonce = None
  rnonce = None

  def __init__(self):
    pass

  def handle_event(self, event):
    event = json.loads(event)
    if event["type"] == "send" or event["type"] == "recv":
      if event["messageid"] == "2774":
        return
      elif event["messageid"] == "4e84":
        return
      else:
        if self.serverkey:
          if self.pk:
            if self.sk:
              if event["messageid"] == "2775":
                b2 = BLAKE2b(digest_size=24)
                b2.update(self.pk)
                b2.update(self.serverkey)
                nonce = b2.final()
                message = event["message"].decode("hex")
                self.s = crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(self.serverkey, self.sk)
                ciphertext = crypto_secretbox_xsalsa20poly1305_tweet(message, nonce, self.s)
                if binascii.hexlify(ciphertext) == event["ciphertext"]:
                  print "-> 2775 ciphertext matches"
                  message = crypto_secretbox_xsalsa20poly1305_tweet_open(event["ciphertext"].decode("hex"), nonce, self.s)
                  if binascii.hexlify(message) == event["message"]:
                    print "-> | {} message matches".format(event["messageid"])
                  else:
                    print "-> | Warning: {} message does not match".format(event["messageid"])
                else:
                  print "-> Warning: 2775 ciphertext does not match"
                self.snonce = message[56:80]
              elif self.snonce:
                if event["messageid"] == "4e88":
                  if self.s:
                    b2 = BLAKE2b(digest_size=24)
                    b2.update(self.snonce)
                    b2.update(self.pk)
                    b2.update(self.serverkey)
                    nonce = b2.final()
                    ciphertext = event["ciphertext"].decode("hex")
                    message = crypto_secretbox_xsalsa20poly1305_tweet_open(ciphertext, nonce, self.s)
                    if binascii.hexlify(message) == event["message"]:
                      print "<- 4e88 message matches"
                    else:
                      print "<- Warning: 4e88 message does not match"
                    self.rnonce = message[32:56]
                    self.k = message[56:88]
                  else:
                    raise Exception("Missing s.")
                else:
                  if self.rnonce:
                    if self.k:
                      if event["type"] == "send":
                        self.snonce = self.increment_nonce(self.snonce)
                        message = event["message"].decode("hex")
                        ciphertext = crypto_secretbox_xsalsa20poly1305_tweet(message, self.snonce, self.k)
                        if binascii.hexlify(ciphertext) == event["ciphertext"]:
                          print "-> {} ciphertext matches".format(event["messageid"])
                          message = crypto_secretbox_xsalsa20poly1305_tweet_open(event["ciphertext"].decode("hex"), self.snonce, self.k)
                          if binascii.hexlify(message) == event["message"]:
                            print "-> | {} message matches".format(event["messageid"])
                          else:
                            print "-> | Warning: {} message does not match".format(event["messageid"])
                        else:
                          print "-> Warning: {} ciphertext does not match".format(event["messageid"])
                      elif event["type"] == "recv":
                        self.rnonce = self.increment_nonce(self.rnonce)
                        ciphertext = event["ciphertext"].decode("hex")
                        message = crypto_secretbox_xsalsa20poly1305_tweet_open(ciphertext, self.rnonce, self.k)
                        if binascii.hexlify(message) == event["message"]:
                          print "<- {} message matches".format(event["messageid"])
                        else:
                          print "<- Warning: {} message does not match".format(event["messageid"])
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
      self.pk = event["pk"].decode("hex")
      self.sk = event["sk"].decode("hex")
    elif event["type"] == "crypto_box":
      self.serverkey = event["serverkey"].decode("hex")
    else:
      raise Exception("Invalid event type.")

  def increment_nonce(self, nonce):
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

