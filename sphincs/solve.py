import pwn

HOST = "challenges.sshuzl.de"
PORT = 12369
conn = pwn.remote(HOST, PORT)

def read_msg() -> int:
    conn.recvuntil(b'Message: ')
    return bytes.fromhex(conn.recvline().strip().decode())

def read_menu() -> None:
    conn.recvuntil(b'num > ')
    return

def sign_message(msg: bytes) -> bytes:
    read_menu()
    conn.sendline(b'2')
    conn.recvuntil(b'msg > ')
    conn.sendline(msg.hex().encode())
    conn.recvuntil(b'Signature: ')
    return bytes.fromhex(conn.recvline().strip().decode())

def hash(val: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(val).digest()

def send_signature(sig: bytes) -> bytes:
    read_menu()
    conn.sendline(b'1')
    conn.recvuntil(b'sig > ')
    conn.sendline(sig.hex().encode())
    if b'Well done!' in conn.recvline():
        return conn.recvline().strip().split(b' ')[1]
    return b'FAIL'

def main():
    msg = read_msg()
    msg_p = bytes([msg[0], msg[1] + 1])
    sig_p = sign_message(msg_p)
    sig = hash(sig_p)
    flag = send_signature(sig)
    print(f"Flag: {flag.decode()}")
    conn.close()
    return

if __name__ == '__main__':
    main()
    pass
