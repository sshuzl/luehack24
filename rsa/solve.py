import pwn
from Cryptodome.Util.number import getPrime

HOST = 'challenges.sshuzl.de'
PORT = 12374

def keygen():
    p = getPrime(2048)
    q = getPrime(2048)
    n = p * q
    assert n.bit_length() >= 2048
    phi = (p-1) * (q-1)
    e = 0x10001
    d = pow(e, -1, phi)
    return n, e, d

def send_key(conn, n, e):
    conn.recvuntil(b'> ')
    conn.sendline(b'1')
    conn.recvuntil(b'n > ')
    conn.sendline(hex(n)[2:].encode())
    conn.recvuntil(b'e > ')
    conn.sendline(hex(e)[2:].encode())
    return

def recv_enc_flag(conn):
    conn.recvuntil(b'> ')
    conn.sendline(b'2')
    conn.recvline()
    return conn.recvline()

def close(conn):
    conn.recvuntil(b'> ')
    conn.sendline(b'3')
    conn.recvall()
    conn.close()
    return

def decrypt_flag(c: bytes, d: int, n: int) -> str:
    c = int(c.strip().decode('ascii'), 16)
    p = pow(c, d, n)
    return bytes.fromhex(hex(p)[2:]).decode('ascii')

def main():
    n, e, d = keygen()

    conn = pwn.remote(HOST, PORT)
    send_key(conn, n, e)
    line = recv_enc_flag(conn)
    close(conn)

    flag = decrypt_flag(line, d, n)
    print(f"[+] Flag: {flag}")
    return

if __name__ == '__main__':
    main()
    pass