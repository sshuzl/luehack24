We write a simple python pwntools script to solve the task:
```python
import pwn

p = pwn.process("intro_pwn")
# alternatively use `p = pwn.remote(ADDRESS, PORT)` for remote connection

for i in range(10):
    n = int(p.recvline())
    p.send(pwn.p32(n))

p.interactive() # keep connection open and display the received data
```
