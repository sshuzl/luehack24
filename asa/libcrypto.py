from os import urandom
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES

def iv_gen():
  return urandom(16)

def encrypt(message, key):
  msg = message.encode('ascii')
  iv = iv_gen()
  aes_cfb = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
  return b64encode(iv + aes_cfb.encrypt(msg)).decode('ascii')

def decrypt(ciphertext, key):
  ctx = b64decode(ciphertext.encode('ascii'))
  iv, ct = ctx[:16], ctx[16:]
  aes_cfb = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
  return aes_cfb.decrypt(ct).decode('ascii')

