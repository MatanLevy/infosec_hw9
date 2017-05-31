from Crypto import Random
from Crypto.Cipher import AES
import base64

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()
unpad = lambda s: s[:-ord(s[len(s)-1:])]

class CryptoMessage(object):
	def __init__(self,key):
		self.key = key

	
	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		cipher = AES.new(self.key, AES.MODE_CBC, chr(0)*16)
		dec = cipher.decrypt(enc)
		return unpad(dec).decode('utf-8')

	def encrypt(self,message):
		message = message.encode()
		raw = pad(message)
		cipher = AES.new(self.key, AES.MODE_CBC, chr(0)*16)
		enc = cipher.encrypt(raw)
		return base64.b64encode(enc).decode('utf-8')
