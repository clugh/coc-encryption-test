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
    self.serverkey = PublicKey("47d1416f3cf982d2b510cab32ecc4f1a04971345446cb1af326f304f63da6264".decode("hex"))

  def handle_event(self, event):
    for key in event:
      if key in {"type", "from"}:
        continue
      elif key == "messageid":
        event[key] = int(event[key], 16)
      elif type(event[key]) is bool:
        continue
      elif type(event[key]) in {str, unicode}:
        event[key] = event[key].decode("hex")
    if event["type"] == "socket":
      self.tee = Tee(os.path.join(self.BASE_DIR, "session-{}.log".format(event["threadid"])))
      self.log("session started")
    elif event["type"] == "keypair":
      self.sk = PrivateKey(event["sk"])
      self.dump({"sk": self.sk}, function="PrivateKey")
    elif event["type"] == "send" or event["type"] == "recv":
      if event["messageid"] == 10100:
        event.update({"message": event["buffer"]})
        self.dump(event)
      elif event["messageid"] == 20100:
        event.update({"message": event["buffer"]})
        self.dump(event)
      else:
        if self.serverkey:
          if self.sk:
            if event["messageid"] == 10101:
              self.pk = PublicKey(event["buffer"][:32])
              self.dump({"pk": bytes(self.pk)}, function="PublicKey")
              event["buffer"] = event["buffer"][32:]
            if self.pk:
              if event["messageid"] == 10101 or self.snonce:
                if event["messageid"] in {10101, 20104} or self.rnonce:
                  if event["messageid"] in {10101, 20104} or self.k:
                    if event["messageid"] in {10101, 20104}:
                      k = Box(self.sk, self.serverkey)
                      self.dump({"s": k}, function="Box")
                      b2 = blake2b(digest_size=24)
                      if event["messageid"] == 20104:
                        b2.update(bytes(self.snonce))
                      b2.update(bytes(self.pk))
                      b2.update(bytes(self.serverkey))
                      nonce = b2.digest()
                      if event["messageid"] == 10101:
                        self.dump({"pk": self.pk, "serverkey": self.serverkey, "nonce": nonce}, function="blake2b")
                      elif event["messageid"] == 20104:
                        self.dump({"snonce": self.snonce, "pk": self.pk, "serverkey": self.serverkey, "nonce": nonce}, function="blake2b")
                    else:
                      k = self.k
                      if event["type"] == "send":
                        self.snonce = self.increment_nonce(self.snonce)
                        nonce = self.snonce
                      elif event["type"] == "recv":
                        self.rnonce = self.increment_nonce(self.rnonce)
                        nonce = self.rnonce
                    ciphertext = event["buffer"]
                    event.update({"k": k, "nonce": nonce, "ciphertext": event["buffer"]})
                    try:
                      message = k.decrypt(ciphertext, nonce)
                    except:
                      self.dump(event, error=True)
                      self.log("Warning: failed to decrypt {}".format(event["messageid"]), error=True)
                      if event["messageid"] in {10101, 20104}:
                        raise
                    else:
                      if event["messageid"] == 10101:
                        self.snonce = message[24:48]
                        self.dump({"snonce": self.snonce}, function="slice")
                        message = message[48:]
                      elif event["messageid"] == 20104:
                        self.rnonce = message[:24]
                        self.k = Box.decode(message[24:56])
                        self.dump({"rnonce": self.rnonce, "k": self.k}, function="slice")
                        message = message[56:]
                      event.update({"message": message})
                      self.dump(event)
                  else:
                    raise Exception("Missing shared key ({}).".format(event["messageid"]))
                else:
                  raise Exception("Missing server nonce ({}).".format(event["messageid"]))
              else:
                raise Exception("Missing client nonce ({}).".format(event["messageid"]))
            else:
              raise Exception("Missing public key ({}).".format(event["messageid"]))
          else:
            raise Exception("Missing secret key ({}).".format(event["messageid"]))
        else:
          raise Exception("Missing server key ({}).".format(event["messageid"]))
    elif event["type"] == "closing":
      self.log("session closed")
    elif event["type"] == "close":
      self.tee.flush()
      self.tee.close()
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

  def log(self, message, error=False):
    if error:
      print message
    else:
      self.script.post_message({"type": "log", "message": message})

  def dump(self, event, function=None, error=False):
    message = []
    if not function:
      function = event["type"]
    if error:
      function = function.rjust(31)
    message.append(function)
    message.append("--------------------".rjust(31))
    ordered = ["messageid", "snonce", "rnonce", "pk", "sk", "serverkey", "s", "k", "nonce", "message", "ciphertext"]
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
    self.log("\n".join(message), error=error)
    extra = set(event.keys()) - set(ordered) - set(skipped)
    if extra:
      self.log("Warning: Missed key(s) ({})".format(", ".join(extra)), error=error)
