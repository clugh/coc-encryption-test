import nacl.utils
from nacl.public import Box, PrivateKey, PublicKey
from pyblake2 import blake2b
import array

class mitm:

  session = None
  script = None
  serverkey = None
  pk = None
  sk = None
  k = None
  snonce = None
  rnonce = None

  def __init__(self, session, script):
    self.session = session
    self.script = script
    # self.sk = PrivateKey("[private key here]".decode("hex"))
    # self.pk = self.sk.public_key
    # self.snonce = "[client nonce here]".decode("hex")

  def handle_event(self, event):
    for key in event:
      if event["type"] in {"keypair", "randombytes"}:
        break
      elif key in {"type", "from"}:
        continue
      elif key == "messageid":
        event[key] = int(event[key], 16)
      elif type(event[key]) is bool:
        continue
      else:
        event[key] = event[key].decode("hex")
    if event["type"] == "socket":
      self.log("session started")
      if not (self.sk and self.pk):
        self.sk = PrivateKey.generate()
        self.pk = self.sk.public_key
      if not self.snonce:
        self.snonce = nacl.utils.random(Box.NONCE_SIZE)
    elif event["type"] == "send" or event["type"] == "recv":
      if event["messageid"] == 10100:
        self.log("-> {}".format(event["messageid"]))
      elif event["messageid"] == 20100:
        self.log("<- {}".format(event["messageid"]))
      else:
        if self.serverkey:
          if self.pk:
            if self.sk:
              if event["messageid"] == 10101:
                b2 = blake2b(digest_size=24)
                b2.update(bytes(self.pk))
                b2.update(bytes(self.serverkey))
                nonce = b2.digest()
                message = event["message"]
                try:
                  s = Box(self.sk, self.serverkey)
                  ciphertext = s.encrypt(message, nonce)[24:]
                except:
                  self.log("-> Warning: failed to encrypt {}".format(event["messageid"]))
                  raise
                else:
                  if message[24:48] != self.snonce:
                    raise Exception("Client nonce mismatch ({}).".format(message[24:48].encode("hex")))
                  if ciphertext == event["ciphertext"]:
                    self.log("-> {} ciphertext matches".format(event["messageid"]))
                  else:
                    self.log("-> Warning: {} ciphertext does not match".format(event["messageid"]))
              elif self.snonce:
                if event["messageid"] == 20104:
                  b2 = blake2b(digest_size=24)
                  b2.update(bytes(self.snonce))
                  b2.update(bytes(self.pk))
                  b2.update(bytes(self.serverkey))
                  nonce = b2.digest()
                  ciphertext = event["ciphertext"]
                  try:
                    s = Box(self.sk, self.serverkey)
                    message = s.decrypt(ciphertext, nonce)
                  except:
                    self.log("<- Warning: failed to decrypt {}".format(event["messageid"]))
                    raise
                  else:
                    self.rnonce = message[:24]
                    self.k = Box.decode(message[24:56])
                    if message == event["message"]:
                      self.log("<- {} message matches".format(event["messageid"]))
                    else:
                      self.log("<- Warning: {} message does not match".format(event["messageid"]))
                else:
                  if self.rnonce:
                    if self.k:
                      if event["type"] == "send":
                        self.snonce = self.increment_nonce(self.snonce)
                        message = event["message"]
                        try:
                          ciphertext = self.k.encrypt(message, self.snonce)[24:]
                        except:
                          self.log("-> Warning: failed to encrypt {}".format(event["messageid"]))
                        else:
                          if ciphertext == event["ciphertext"]:
                            self.log("-> {} ciphertext matches".format(event["messageid"]))
                          else:
                            self.log("-> Warning: {} ciphertext does not match".format(event["messageid"]))
                      elif event["type"] == "recv":
                        self.rnonce = self.increment_nonce(self.rnonce)
                        ciphertext = event["ciphertext"]
                        try:
                          message = self.k.decrypt(ciphertext, self.rnonce)
                        except:
                          self.log("<- Warning: failed to decrypt {}".format(event["messageid"]))
                        else:
                          if message == event["message"]:
                            self.log("<- {} message matches".format(event["messageid"]))
                          else:
                            self.log("<- Warning: {} message does not match".format(event["messageid"]))
                    else:
                      raise Exception("Missing k.")
                  else:
                    raise Exception("Missing server nonce.")
              else:
                raise Exception("Missing client nonce.")
            else:
              raise Exception("Missing secret key.")
          else:
            raise Exception("Missing public key.")
        else:
          raise Exception("Missing server key.")
    elif event["type"] == "keypair":
      self.session.write_bytes(int(event["pk"], 16), bytes(self.pk))
      self.session.write_bytes(int(event["sk"], 16), bytes(self.sk))
      self.script.post_message({"type": "keypair"})
    elif event["type"] == "randombytes":
      if event["length"] == 24:
        self.session.write_bytes(int(event["randombytes"], 16), self.increment_nonce_firstbyte(self.snonce))
      self.script.post_message({"type": "randombytes"})
    elif event["type"] == "beforenm":
      self.serverkey = PublicKey(bytes(event["serverkey"]))
    elif event["type"] == "close":
      self.log("session closed")
    else:
      raise Exception("Invalid event type ({}).".format(event["type"]))

  def increment_nonce(self, nonce):
    arr = array.array('B', nonce)
    bump = 2
    for i in xrange(len(arr) - 1):
      if (arr[i] + bump) > 0xff:
        arr[i] = (arr[i] + bump) % 0x100
        bump = 1
      else:
        arr[i] = arr[i] + bump
        break
    return arr.tostring()

  def increment_nonce_firstbyte(self, nonce):
    arr = array.array('B', nonce)
    if arr[0] == 0xff:
      raise Exception("Client nonce overflow.")
    elif (arr[0] - 1) > 0:
      arr[0] += 1
    return arr.tostring()

  def log(self, message):
    self.script.post_message({"type": "log", "message": message})