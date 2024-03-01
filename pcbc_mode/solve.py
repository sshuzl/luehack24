import io
import base64
import requests
from html.parser import HTMLParser
from PIL import Image, ImageDraw
import pytesseract

HOST = 'https://challenges.sshuzl.de/pcbcmode/'
img = None

class MyHTMLParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        global img
        if tag != 'img':
            return
        for key, value in attrs:
            if key == 'src':
                if not 'base64' in value:
                    return
                b64img = base64.b64decode(value.split(',')[1])
                break
            pass
        img = Image.open(io.BytesIO(b64img))
        return

def get_enc_flag_img() -> None:
    r = requests.get(HOST + '/flag')
    parser = MyHTMLParser()
    parser.feed(r.text)
    return

def alter_enc_flag_img() -> None:
    global img
    draw = ImageDraw.Draw(img)
    draw.point((img.width-1, img.height-1), fill=(255, 255, 255))
    return

def decrypt_flag_img():
    global img
    filestream = io.BytesIO()
    img.save(filestream, format='PNG')
    filestream.seek(0)
    r = requests.post(HOST, files={'file': ('image.png', filestream)})
    parser = MyHTMLParser()
    parser.feed(r.text)
    return

def main():
    global img
    get_enc_flag_img()
    alter_enc_flag_img()
    decrypt_flag_img()
    img.show()
    text = pytesseract.image_to_string(img)
    print(text)
    return

if __name__ == '__main__':
    main()
    pass
