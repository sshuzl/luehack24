import sys
from base64 import b64decode
from libcrypto import decrypt

ciphertexts = list()
with open(sys.argv[1], 'r') as fin:
  for line in fin:
    ciphertexts.append(line[:-1])
    #print(line[:-1])
    pass
  pass
ciphertetxts = ciphertexts[:-1]
#print()

key = bytearray(16)
idxs = dict()
for i in range(16):
  idxs[i] = 0
  pass
for tmp in ciphertexts:
  try:
    ctx = b64decode(tmp)
    iv = ctx[:16]
    ct = ctx[16:]
    if (ct[0] & 0x0F) == 0:
      print('Miss on this one...')
      continue
    idx = ct[0] & 0x0F
    key[idx] = ct[idx]
    idxs[idx] += 1
    pass
  except:
    pass
  pass

recover = [i for i in idxs if idxs[i] > 0]
missing = [i for i in idxs if idxs[i] == 0]
print('recovered key:', key.hex())
print('recovered indices:', recover)
print('missing indices:', missing)

def test(key):
  try:
    for ct in ciphertexts:
      decrypt(ct, key)
      pass
    pass
  except UnicodeDecodeError:
    return False
  except:
    pass
  return True

print((1 << (8*len(missing))), 'keys remaining.')
print('Running brute force...')
for i in range(1 << (8*len(missing))):
  k = key
  for j in range(len(missing)):
    k[missing[j]] = (i >> (8*j)) & 0xFF
    pass
  if not test(k):
    continue
  key = k
  print('Key candidate found:', k.hex())
  print('Decrypting ciphertextst...')
  print()
  for ct in ciphertetxts:
    print(decrypt(ct, k))
    pass
  pass

ans = input('Show frequency analysis of ctx bytes per position in first block? [y/N] ')
if ans.lower() == 'y':
  import matplotlib.pyplot as plt
  freqs = list()
  for i in range(16):
    freqs.append(list())
    for j in range(256):
      freqs[i].append(0)
      pass
    pass
  for ctx in ciphertexts:
    ct = b64decode(ctx)[16:32]
    for i in range(len(ct)):
      freqs[i][ct[i]] += 1
      pass
    pass
  fig, axes = plt.subplots(16, 1, sharex=True, sharey=True)
  idx = [i for i in range(256)]
  for i in range(16):
    axes[i].bar(idx, freqs[i], width=0.2)
    pass
  print()
  print('Key in decimal:')
  for i in range(len(key)):
    print(i, key[i])
    pass

  plt.show()
  pass
