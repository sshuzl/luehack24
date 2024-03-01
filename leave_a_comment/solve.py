import re
import requests

URL = 'https://challenges.sshuzl.de/leaveacomment/'

def main():
    r = requests.get(URL)
    flag = re.search(r'SSH{.*}', r.text).group(0)
    print(f"[+] Flag: {flag}")
    return

if __name__ == '__main__':
    main()
    pass