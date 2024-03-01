import requests
from html.parser import HTMLParser

URL = "https://challenges.sshuzl.de"
INDEX = "/morph/"
VOUCHER = f"{INDEX}vouchers/"
INFO = f"{INDEX}how/"

class PKParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.n = None
        self.e = None
        self.status = 0
        pass

    def handle_starttag(self, tag, attrs):
        if self.status == 0 and tag == "samp":
            self.status = 1
            pass
        return
    
    def handle_data(self, data):
        if self.status == 1:
            rows = data.strip().split("\n")
            self.n = int(rows[0].split(' = ')[1])
            self.e = int(rows[1].split(' = ')[1])
            self.status = 2
            pass
        return
    pass # PKParser

class VoucherParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.voucher = None
        self.status = 0
        pass

    def handle_starttag(self, tag, attrs):
        if self.status == 0 and tag == "code":
            self.status = 1
            pass
        return
    
    def handle_data(self, data):
        if self.status == 1:
            self.voucher = int(data.strip())
            self.status = 2
            pass
        return
    pass # VoucherParser

def rsa_validate(n: int, e: int, s: int, m: int) -> bool:
    return pow(s, e, n) == m+1

def get_public_key() -> tuple[int, int]:
    response = requests.get(URL + INFO)
    response.raise_for_status()
    p = PKParser()
    p.feed(response.text)
    if p.status != 2:
        raise ValueError("Failed to parse public key")
    return p.n, p.e

def get_voucher(id: int) -> int:
    response = requests.post(URL + VOUCHER, data={'cmd': id})
    response.raise_for_status()
    p = VoucherParser()
    p.feed(response.text)
    if p.status != 2:
        raise ValueError("Failed to parse voucher")
    return p.voucher

def forge_voucher(n: int, target_id: int) -> int:
    x = 2
    i = target_id + 1
    id0 = (i * x - 1) % n
    id1 = (pow(x, -1, n) - 1) % n
    v0 = get_voucher(id0)
    v1 = get_voucher(id1)
    return (v0 * v1) % n

def get_flag(target_id: int, voucher: int) -> str:
    import re
    response = requests.post(URL + INDEX, data={'cmd': target_id, 'sig': voucher})
    response.raise_for_status()
    return re.search(r'SSH{.*}', response.text).group()

def main():
    TARGET_ID = 6
    n, e = get_public_key()
    print(f"n: {n}")
    print(f"e: {e}")
    voucher = forge_voucher(n, TARGET_ID)
    assert rsa_validate(n, e, voucher, TARGET_ID)
    print(f"voucher: {voucher}")
    flag = get_flag(TARGET_ID, voucher)
    print(f"flag: {flag}")
    return

if __name__ == '__main__':
    main()
    pass