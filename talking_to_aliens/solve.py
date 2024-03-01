CHAR  = '#'
WIDTH = 73

def main():
    with open('../dist/talking_to_aliens.txt', 'r') as f:
        data = f.read().strip()
        pass
    print(f"digits: {len(data)}")
    data = data.replace('0', ' ')
    for width in range(2, len(data)//2):
        if (len(data) % width) == 0:
            print(f"width: {width}")
            for i in range(0, len(data), width):
                print(data[i:i+WIDTH])
                pass
            pass
        pass
    return

if __name__ == '__main__':
    main()
    pass
