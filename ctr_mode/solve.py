import io
import base64
import requests
from html.parser import HTMLParser
from PIL import Image, ImageDraw
import pytesseract

HOST = 'https://challenges.sshuzl.de/ctrmode/'
img = None
flag = None
white = None

def image2bytes(img: Image) -> bytes:
    pixels = list(img.getdata())
    return b''.join([bytes(rgb) for rgb in pixels])

def bytes2image(mode, size: tuple[int, int], data: bytes) -> list[tuple[int, int, int]]:
    if mode in ['L', 'P']:
        plen = 1
        pass
    elif mode in ['RGB',  'YCbCr', 'LAB', 'HSV']:
        plen = 3
        pass
    elif mode in ['RGBA', 'CMYK', 'I', 'F']:
        plen = 4
        pass
    else:
        raise ValueError('Invalid mode')
    img = Image.new(mode, size)
    img.putdata([tuple(data[i:i+plen]) for i in range(0, len(data), plen)])
    return img

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
    pass # MyHTMLParser

def get_enc_flag_img() -> None:
    global flag, img
    r = requests.get(HOST + '/flag')
    parser = MyHTMLParser()
    parser.feed(r.text)
    flag = img
    return

def get_enc_white_img() -> None:
    global white, img, flag
    ii = Image.new('RGB', (flag.width, flag.height))
    filestream = io.BytesIO()
    ii.save(filestream, format='PNG')
    filestream.seek(0)
    r = requests.post(HOST, files={'file': ('image.png', filestream)})
    parser = MyHTMLParser()
    parser.feed(r.text)
    white = img
    return

def decrypt_flag_img() -> None:
    global flag, white, img
    ff = image2bytes(flag)
    ww = image2bytes(white)
    dd = bytes([x^y for x,y in zip(ff, ww)])
    img = bytes2image('RGB', (flag.width, flag.height), dd)
    return

def main():
    global img
    get_enc_flag_img()
    get_enc_white_img()
    decrypt_flag_img()
    img.show()
    text = pytesseract.image_to_string(img)
    print(text)
    return

if __name__ == '__main__':
    main()
    pass
