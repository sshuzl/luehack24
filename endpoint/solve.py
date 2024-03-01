import re
import requests
from html.parser import HTMLParser

PROTO = 'https'
DOMAIN = 'challenges.sshuzl.de'
INDEX = 'endpoint'


class MyHTMLParser(HTMLParser):
    state = 0
    script = ''

    def handle_starttag(self, tag: str, attrs: list[str, str]):
        global img
        if self.state != 0 or tag != 'script':
            return
        for key, value in attrs:
            if key == 'id' and value == 'endpoint':
                self.state = 1
                return
            pass
        return
    
    def handle_data(self, data: str) -> None:
        if self.state == 1:
            self.state = 2
            self.script = data
            return
        return
    
    pass # MyHTMLParser

def main():
    url = f"{PROTO}://{DOMAIN}/{INDEX}/"
    print(f"[+] GET: {url}")
    r = requests.get(url)
    print(f"[+]   status: {r.status_code}")
    p = MyHTMLParser()
    p.feed(r.text)
    uuid_regex = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    endpoint = re.search(uuid_regex, p.script).group(0)
    print(f"[+] endpoint: {endpoint}")
    url = f"{PROTO}://{DOMAIN}/{INDEX}/{endpoint}"
    headers = {'Content-type': 'application/json'}
    print(f"[+] GET: {url}")
    r = requests.get(url, headers=headers)
    print(f"[+]   status: {r.status_code}")
    flag = r.json()['name']
    print(f"[+] Flag: {flag}")
    return

if __name__ == '__main__':
    main()
    pass