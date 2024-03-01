class Random:
    def __init__(self, seed: int):
        from ctypes import CDLL
        self.libc = CDLL('libc.so.6')
        self.seed(seed)
        pass

    def seed(self, seed: int) -> None:
        self.libc.srandom(seed & 0xFFFFFFFF)
        return
    
    def rand(self) -> int:
        return self.libc.random() & 0xFFFFFFFF
    
    pass # Random

def get_iv_ctx(path: str) -> tuple[bytes, bytes]:
    with open(path, 'rb') as f:
        ctx = f.read()
        pass
    return ctx[:16], ctx[16:]

def get_time(path: str) -> int:
    from datetime import datetime
    with open(path, 'r') as f:
        data = f.read()
        pass
    for line in data.split('\n'):
        if 'flag' in line:
            d = line.split()
            dt = datetime.fromisoformat(f'{d[5]}T{d[6]}{d[7]}')
            return int(dt.timestamp())
        pass
    return -1

def get_rand16(rand: Random) -> bytes:
    rr = [rand.rand() for _ in range(4)]
    return b''.join([i.to_bytes(4, 'little') for i in rr])

def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(data), AES.block_size)

def main():
    print(f"[+] Loading encrypted file...")
    iv, ctx = get_iv_ctx('../dist/flag.txt.crypt')
    print(f"[+]   IV:  {iv.hex()}")
    print(f"[+]   CTX: {ctx.hex()}")

    print(f"[+] Loading approximate timestamp...")
    tsc = get_time('../dist/info.txt')
    print(f"[+]   TSC: {tsc}")
    print(f"[+] Searching for correct timestamp...")
    key = None
    for i in range(100):
        rand = Random(tsc - i)
        if get_rand16(rand) == iv:
            key = get_rand16(rand)
            print(f"[+]   TSC: {tsc - i}")
            print(f"[+]   KEY: {key.hex()}")
            break
        pass
    if not key:
        print(f"[-]   Failed to find key")
        return
    print(f"[+] Decrypting file...")
    flag = decrypt(key, iv, ctx)
    print(f"[+]   CONTENT: {flag.decode()}")
    return

if __name__ == '__main__':
    main()
    pass