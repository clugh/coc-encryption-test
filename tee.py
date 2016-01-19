import sys
import re
class Tee(object):
     def __init__(self, name, mode="w"):
         self.file = open(name, mode)
         self.stdout = sys.stdout
         self.encoding = self.stdout.encoding
         sys.stdout = self
         self.ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
     def close(self):
         if self.stdout is not None:
             sys.stdout = self.stdout
             self.stdout = None
         if self.file is not None:
             self.file.close()
             self.file = None
     def write(self, data):
         self.file.write(self.ansi_escape.sub('', data))
         self.stdout.write(data)
     def flush(self):
         self.file.flush()
         self.stdout.flush()
     def __del__(self):
         self.close()
