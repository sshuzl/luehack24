import os
import re

from keycodes import KEY_CODES_DE, KeyStroke

def get_usb_data(file: str) -> list[bytes]:
    os.system(f"tshark -r {file} -Y 'usb.capdata && usb.data_len == 9' -T fields -e usb.capdata > keyboard.txt")
    with open("keyboard.txt", "r") as f:
        data = [bytes.fromhex(line) for line in f.readlines()]
        pass
    os.system("rm keyboard.txt")
    return data

def main():
    print(f"[+] Reading USB data from usb.pcapng...")
    data = get_usb_data(input('PCAP: '))

    print(f"[+] Converting USB data to keystrokes...")
    lst = [str(KeyStroke(d, KEY_CODES_DE)) for d in data]
    text = ''.join(lst)
    print('------ extracted text begin ------')
    print(text, end='')
    print('------ extracted text end ------')

    print(f"[+] Extracting flag...")
    flag = re.search(r'SSH{.*}', text).group(0)
    print(f'[+] Flagge: {flag}')
    return

if __name__ == '__main__':
    main()
    pass
