import nacl.utils
from nacl.public import Box, PrivateKey, PublicKey
from pyblake2 import blake2b
import array
from tee import Tee
import os

class mitm:

  BASE_DIR = os.path.dirname(os.path.abspath(__file__))

  session = None
  script = None
  serverkey = None
  pk = None
  sk = None
  k = None
  snonce = None
  rnonce = None
  tee = None

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
      elif type(event[key]) in {str, unicode}:
        event[key] = event[key].decode("hex")
    if event["type"] == "socket":
      self.log("session started")
      self.tee = Tee(os.path.join(self.BASE_DIR, "session-{}.log".format(event["threadid"])))
      if not (self.sk and self.pk):
        self.sk = PrivateKey.generate()
        self.pk = self.sk.public_key
      if not self.snonce:
        self.snonce = nacl.utils.random(Box.NONCE_SIZE)
      self.dump({"pk": self.pk, "sk": self.sk}, function="keypair")
      self.dump({"snonce": self.snonce}, function="snonce")
    elif event["type"] == "send" or event["type"] == "recv":
      if event["messageid"] == 10100:
        self.log("-> {}".format(event["messageid"]))
        event.update({"message": event["buffer"]})
        self.dump(event)
      elif event["messageid"] == 20100:
        self.log("<- {}".format(event["messageid"]))
        event.update({"message": event["buffer"]})
        self.dump(event)
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
                event.update({"pk": self.pk, "serverkey": self.serverkey, "nonce2": nonce})
                try:
                  s = Box(self.sk, self.serverkey)
                  event.update({"s2": s})
                  ciphertext = s.encrypt(message, nonce)[24:]
                  event.update({"ciphertext2": ciphertext})
                except:
                  self.dump(event)
                  self.log("-> Warning: failed to encrypt {}".format(event["messageid"]))
                  raise
                else:
                  self.dump(event)
                  self.dump({"snonce": message[24:48]}, function="snonce2")
                  if message[24:48] != self.snonce:
                    raise Exception("Client nonce mismatch ({}).".format(message[24:48].encode("hex")))
                  self.snonce = message[24:48]
                  self.dump({"type": "snonce", "snonce": self.snonce})
                  if ciphertext != event["ciphertext"]:
                    self.log("-> Warning: {} ciphertext does not match".format(event["messageid"]))
              elif self.snonce:
                if event["messageid"] == 20104:
                  b2 = blake2b(digest_size=24)
                  b2.update(bytes(self.snonce))
                  b2.update(bytes(self.pk))
                  b2.update(bytes(self.serverkey))
                  nonce = b2.digest()
                  ciphertext = event["ciphertext"]
                  event.update({"snonce": self.snonce, "pk": self.pk, "serverkey": self.serverkey, "nonce2": nonce})
                  try:
                    s = Box(self.sk, self.serverkey)
                    event.update({"s2": s})
                    message = s.decrypt(ciphertext, nonce)
                    event.update({"message2": message})
                  except:
                    self.dump(event)
                    self.log("<- Warning: failed to decrypt {}".format(event["messageid"]))
                    raise
                  else:
                    self.dump(event)
                    self.rnonce = message[:24]
                    self.dump({"type": "rnonce", "rnonce": self.rnonce})
                    self.k = Box.decode(message[24:56])
                    self.dump({"type": "k", "k": self.k})
                    if message != event["message"]:
                      self.log("<- Warning: {} message does not match".format(event["messageid"]))
                else:
                  if self.rnonce:
                    if self.k:
                      if event["type"] == "send":
                        self.snonce = self.increment_nonce(self.snonce)
                        message = event["message"]
                        event.update({"k2": self.k, "snonce": self.snonce})
                        try:
                          ciphertext = self.k.encrypt(message, self.snonce)[24:]
                          event.update({"ciphertext2": ciphertext})
                        except:
                          self.dump(event)
                          self.log("-> Warning: failed to encrypt {}".format(event["messageid"]))
                        else:
                          self.dump(event)
                          if ciphertext != event["ciphertext"]:
                            self.log("-> Warning: {} ciphertext does not match".format(event["messageid"]))
                      elif event["type"] == "recv":
                        self.rnonce = self.increment_nonce(self.rnonce)
                        ciphertext = event["ciphertext"]
                        event.update({"k2": self.k, "rnonce": self.rnonce})
                        try:
                          message = self.k.decrypt(ciphertext, self.rnonce)
                          event.update({"message2": message})
                        except:
                          self.dump(event)
                          self.log("<- Warning: failed to decrypt {}".format(event["messageid"]))
                        else:
                          self.dump(event)
                          if message != event["message"]:
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
      self.dump({"serverkey": self.serverkey}, function="serverkey")
    elif event["type"] == "close":
      self.tee.flush()
      self.tee.close()
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

  def dump(self, event, function=None):
    message = []
    if not function:
      function = event["type"]
    message.append(function)
    message.append("--------------------".rjust(31))
    ordered = ["messageid", "serverkey", "pk", "sk", "s", "s2", "k", "k2", "nonce", "nonce2", "snonce", "rnonce", "message", "message2", "ciphertext", "ciphertext2"]
    skipped = ["from", "type", "buffer"]
    intersection = [x for x in ordered if x in event.keys()]
    for key in intersection:
      if type(event[key]) in {Box, PrivateKey, PublicKey}:
        value = bytes(event[key]).encode("hex")
      elif type(event[key]) in {dict, bool}:
        value = str(event[key])
      elif type(event[key]) in {str, unicode}:
        value = event[key].encode("hex")
      else:
        value = event[key]
      message.append("".join(["".rjust(15), key.ljust(20), str(value)]))
    message.append("")
    self.log("\n".join(message))
    extra = set(event.keys()) - set(ordered) - set(skipped)
    if extra:
      self.log("Warning: Missed key(s) ({})".format(", ".join(extra)))
