import pwn

HOST = 'challenges.sshuzl.de'
PORT = 12375
#p = pwn.process("intro_pwn")
p = pwn.remote(HOST, PORT)

for i in range(10):
    n = int(p.recvline())
    p.send(pwn.p32(n))

p.interactive() # keep connection open and display the received data
