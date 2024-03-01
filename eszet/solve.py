import re
import requests

HOST = 'https://challenges.sshuzl.de/eszet'

def main():
    passwd = '👁🎔ẞ'
    resp = requests.post(f"{HOST}/eszet", data={'eszet': passwd})
    flag = re.search(r'SSH{.*}', resp.text).group(0)
    print(f'[+] Flagge: {flag}')
    return

if __name__ == '__main__':
    main()
    pass
