import json
import numpy
import base64
import random
import hashlib
import requests
from math import sqrt
from Crypto.Cipher import AES

def xor(a, b):
    """ Computes the bitwise-XOR for two byte arrays a and b. """
    return bytearray((b1 ^ b2) for (b1, b2) in zip(a, b))

def unmarshal(qubit):
    """ Convert the qubit dict to complex number """
    return complex(float(qubit['real']), float(qubit['imag']))

def rotate_45(qubit):
    """ Rotate the qubit by 45 degrees """
    return qubit * complex(0.707,-0.707)

def measure(q, b):
    """ Measure the qubit using the basis """
    q = unmarshal(q)
    if b == 'x':
        q = rotate_45(q)
    probability_zero = round(pow(q.real, 2), 1)
    probability_one = round(pow(q.imag, 2), 1)
    return str(numpy.random.choice(numpy.arange(0, 2), p=[probability_zero, probability_one]))

def generateQubits(n):
    qubits = dict()
    b = 'basis'; q = 'qubits'; r = 'real'; i = 'imag'
    qubits[b] = [random.choice('+x') for _ in range(n)]
    qubits[q] = list()
    for basis in qubits[b]:
        if basis == '+':
            qubits[q].append(random.choice([{'real': 1, 'imag': 0}, {'real': 0, 'imag': 1}]))
        else:
            qubits[q].append(random.choice([{'real': sqrt(2)/2, 'imag': sqrt(2)/2}, {'real': -sqrt(2)/2, 'imag': sqrt(2)/2}]))
    return qubits

def dec_flag(enc_flag, key):
    aes = AES.new(key, AES.MODE_CBC, b'\x00'*16)
    return aes.decrypt(base64.b64decode(enc_flag.encode('ascii'))).decode('ascii')
    
url = 'https://challenges.sshuzl.de/bb84/qubits'
data = generateQubits(512)
print('Sending qubits...')
r = requests.post(url, json=data, verify=True) # change verify to False if server uses self-signed certs
print(r.text)
ans = json.loads(r.text)
if 'error' in ans:
    print('[ERROR]', ans['error'])
    exit(1)
announcement = bytearray.fromhex(ans['announcement'])

print('Calculating shared secret...')
key = ''
for m_b, s_b, q in zip(data['basis'], ans['basis'], data['qubits']):
    if m_b == s_b:
        key += measure(q, m_b)
key = int(key[:128],2).to_bytes(16, 'big')
print('shared secret:', key.hex())

print('Decrypting flag encryption key...')
fek = xor(announcement, key)
print('flag encryption key:', fek.hex())

print('Decrypting flag...')
enc_flag = 'G5ixOmyzpGS0WTmNXHcpP08rAG2vtTLmV7SfcYg/VsMlOJ8kFhkcGsS/au+ehYJR'
print('flag:', dec_flag(enc_flag, fek))
