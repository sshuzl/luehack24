from .keycodes import KEY_CODES_US, KEY_CODES_DE

KEY_MOD_LCTRL   = 0x01
KEY_MOD_LSHIFT  = 0x02
KEY_MOD_LALT    = 0x04
KEY_MOD_LMETA   = 0x08
KEY_MOD_RCTRL   = 0x10
KEY_MOD_RSHIFT  = 0x20
KEY_MOD_RALT    = 0x40
KEY_MOD_RMETA   = 0x80
KEY_MOD_CTRL    = KEY_MOD_LCTRL | KEY_MOD_RCTRL
KEY_MOD_SHIFT   = KEY_MOD_LSHIFT | KEY_MOD_RSHIFT
KEY_MOD_ALT     = KEY_MOD_LALT | KEY_MOD_RALT
KEY_MOD_META    = KEY_MOD_LMETA | KEY_MOD_RMETA

class KeyModifier:
    def __init__(self, mod: int):
        self.raw    = mod
        self.lctrl  = bool(mod & KEY_MOD_LCTRL)
        self.lshift = bool(mod & KEY_MOD_LSHIFT)
        self.lalt   = bool(mod & KEY_MOD_LALT)
        self.lmeta  = bool(mod & KEY_MOD_LMETA)
        self.rctrl  = bool(mod & KEY_MOD_RCTRL)
        self.rshift = bool(mod & KEY_MOD_RSHIFT)
        self.ralt   = bool(mod & KEY_MOD_RALT)
        self.rmeta  = bool(mod & KEY_MOD_RMETA)
        self.ctrl   = bool(mod & KEY_MOD_CTRL)
        self.shift  = bool(mod & KEY_MOD_SHIFT)
        self.alt    = bool(mod & KEY_MOD_ALT)
        self.meta   = bool(mod & KEY_MOD_META)
        self.any    = self.ctrl or self.shift or self.alt or self.meta
        self.mod    = [self.lctrl, self.lshift, self.lalt, self.lmeta,
                       self.rctrl, self.rshift, self.ralt, self.rmeta]
        self.repr   = ['LCTRL', 'LSHIFT', 'LALT', 'LMETA',
                       'RCTRL', 'RSHIFT', 'RALT', 'RMETA']
        pass

    def __int__(self) -> int:
        if self.ralt: return 2
        elif self.shift: return 1
        else: return 0

    def __str__(self) -> str:
        pressed = [self.repr[i] for i in range(len(self.mod)) if self.mod[i]]
        return "+".join(pressed)

    def __repr__(self) -> str:
        return f"KeyModifier({self.__str__()})"

    pass # KeyModifier

class KeyStroke:
    def __init__(self, data: bytes, mapping: dict[int, tuple[str|None,str|None,str|None,str|None]]):
        self.data = data
        self.map = mapping
        if len(self.data) == 8:
            self.mod = KeyModifier(data[0])
            self.key = data[2]
            pass
        elif len(self.data) == 9:
            self.mod = KeyModifier(data[1])
            self.key = data[3]
            pass
        self.char = self.map[self.key][int(self.mod)]
        pass

    def __str__(self) -> str:
        if self.key == 0:
            return ''
        if self.char is not None:
           return f"{self.char}"
        if self.map[self.key][0] is not None:
            char = self.map[self.key][0]
            pass
        else:
            char = f"0x{self.key:02x}"
            pass
        if self.mod.any:
            return '+'.join([str(self.mod), char])
        return char

    def __repr__(self) -> str:
        return f"KeyModifier({self.__str__()})"

    pass # Keystroke

if __name__ == '__main__':
    print("This module is not meant to be executed directly.")
    for i in range(256):
        print(f"{i:02x}: {KeyModifier(i)}")
    pass
