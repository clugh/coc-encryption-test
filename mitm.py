tweetnacl = __import__('tweetnacl-usable.tweetnacl', fromlist=["crypto_box_curve25519xsalsa20poly1305_tweet_keypair", "crypto_box_curve25519xsalsa20poly1305_tweet_beforenm", "crypto_box_curve25519xsalsa20poly1305_tweet_afternm", "crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm"])
from pyblake2 import blake2b
import json
import binascii
import array

crypto_box_keypair = tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_keypair
crypto_box_beforenm = tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm
crypto_box_afternm = tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_afternm
crypto_box_open_afternm = tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm

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
        print "-> {}".format(event["messageid"])
        return
      elif event["messageid"] == "4e84":
        print "<- {}".format(event["messageid"])
        return
      else:
        if self.serverkey:
          if self.pk:
            if self.sk:
              if event["messageid"] == "2775":
                b2 = blake2b(digest_size=24)
                b2.update(self.pk)
                b2.update(self.serverkey)
                nonce = b2.digest()
                message = event["message"].decode("hex")
                self.s = crypto_box_beforenm(self.serverkey, self.sk)
                ciphertext = crypto_box_afternm(message, nonce, self.s)
                if binascii.hexlify(ciphertext) == event["ciphertext"]:
                  print "-> 2775 ciphertext matches"
                  message = crypto_box_open_afternm(event["ciphertext"].decode("hex"), nonce, self.s)
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
                    b2 = blake2b(digest_size=24)
                    b2.update(self.snonce)
                    b2.update(self.pk)
                    b2.update(self.serverkey)
                    nonce = b2.digest()
                    ciphertext = event["ciphertext"].decode("hex")
                    message = crypto_box_open_afternm(ciphertext, nonce, self.s)
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
                        ciphertext = crypto_box_afternm(message, self.snonce, self.k)
                        if binascii.hexlify(ciphertext) == event["ciphertext"]:
                          print "-> {} ciphertext matches".format(event["messageid"])
                          message = crypto_box_open_afternm(event["ciphertext"].decode("hex"), self.snonce, self.k)
                          if binascii.hexlify(message) == event["message"]:
                            print "-> | {} message matches".format(event["messageid"])
                          else:
                            print "-> | Warning: {} message does not match".format(event["messageid"])
                        else:
                          print "-> Warning: {} ciphertext does not match".format(event["messageid"])
                      elif event["type"] == "recv":
                        self.rnonce = self.increment_nonce(self.rnonce)
                        ciphertext = event["ciphertext"].decode("hex")
                        message = crypto_box_open_afternm(ciphertext, self.rnonce, self.k)
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
    elif event["type"] == "beforenm":
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

