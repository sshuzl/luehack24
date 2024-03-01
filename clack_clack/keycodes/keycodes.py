# https://www.usb.org/hid
# Currently: https://www.usb.org/sites/default/files/hut1_5.pdf
KEY_CODES = {
    0x00: ['',      '',     '',     ''],   # No key pressed
    0x01: [None,    None,   None,   None], # Keyboard Error Roll Over
    0x02: [None,    None,   None,   None], # Keyboard POST Fail
    0x03: [None,    None,   None,   None], # Keyboard Error Undefined
    0x04: ['a',     'A',    None,   None],
    0x05: ['b',     'B',    None,   None],
    0x06: ['c',     'C',    None,   None],
    0x07: ['d',     'D',    None,   None],
    0x08: ['e',     'E',    None,   None],
    0x09: ['f',     'F',    None,   None],
    0x0A: ['g',     'G',    None,   None],
    0x0B: ['h',     'H',    None,   None],
    0x0C: ['i',     'I',    None,   None],
    0x0D: ['j',     'J',    None,   None],
    0x0E: ['k',     'K',    None,   None],
    0x0F: ['l',     'L',    None,   None],
    0x10: ['m',     'M',    None,   None],
    0x11: ['n',     'N',    None,   None],
    0x12: ['o',     'O',    None,   None],
    0x13: ['p',     'P',    None,   None],
    0x14: ['q',     'Q',    None,   None],
    0x15: ['r',     'R',    None,   None],
    0x16: ['s',     'S',    None,   None],
    0x17: ['t',     'T',    None,   None],
    0x18: ['u',     'U',    None,   None],
    0x19: ['v',     'V',    None,   None],
    0x1A: ['w',     'W',    None,   None],
    0x1B: ['x',     'X',    None,   None],
    0x1C: ['y',     'Y',    None,   None],
    0x1D: ['z',     'Z',    None,   None],
    0x1E: ['1',     '!',    None,   None],
    0x1F: ['2',     '@',    None,   None],
    0x20: ['3',     '#',    None,   None],
    0x21: ['4',     '$',    None,   None],
    0x22: ['5',     '%',    None,   None],
    0x23: ['6',     '^',    None,   None],
    0x24: ['7',     '&',    None,   None],
    0x25: ['8',     '*',    None,   None],
    0x26: ['9',     '(',    None,   None],
    0x27: ['0',     ')',    None,   None],
    0x28: ['\n',    '\n',   None,   None], # Enter
    0x29: ['␛',     '␛',    None,   None], # Escaoe
    0x2a: ['⌫',     '⌫',    None,   None], # Delete (Backspace)
    0x2b: ['\t',    '\t',   None,   None], # Tab
    0x2c: [' ',     ' ',    None,   None], # Space
    0x2d: ['-',     '_',    None,   None],
    0x2e: ['=',     '+',    None,   None],
    0x2f: ['[',     '{',    None,   None],
    0x30: [']',     '}',    None,   None],
    0x31: ['\\',    '|',    None,   None], # Keyboard \ and |
    0x32: ['#',     '~',    None,   None], # Keyboard Non-US # and ~
    0x33: [';',     ':',    None,   None],
    0x34: ["'",     '"',    None,   None],
    0x35: ['`',     '~',    None,   None],
    0x36: [',',     '<',    None,   None],
    0x37: ['.',     '>',    None,   None],
    0x38: ['/',     '?',    None,   None],
    0x39: ['⇪',     '⇪',    None,   None], # Caps Lock
    0x3a: [None,    None,   None,   None], # F1
    0x3b: [None,    None,   None,   None], # F2
    0x3c: [None,    None,   None,   None], # F3
    0x3d: [None,    None,   None,   None], # F4
    0x3e: [None,    None,   None,   None], # F5
    0x3f: [None,    None,   None,   None], # F6
    0x40: [None,    None,   None,   None], # F7
    0x41: [None,    None,   None,   None], # F8
    0x42: [None,    None,   None,   None], # F9
    0x43: [None,    None,   None,   None], # F10
    0x44: [None,    None,   None,   None], # F11
    0x45: [None,    None,   None,   None], # F12
    0x46: [None,    None,   None,   None], # Printscreen
    0x47: [None,    None,   None,   None], # Scroll Lock
    0x48: [None,    None,   None,   None], # Pause
    0x49: [None,    None,   None,   None], # Insert
    0x4a: [None,    None,   None,   None], # Home
    0x4b: [None,    None,   None,   None], # Page Up
    0x4c: [None,    None,   None,   None], # Delete Forward
    0x4d: [None,    None,   None,   None], # End
    0x4e: [None,    None,   None,   None], # Page Down
    0x4f: [u'→',    u'→',   None,   None], # Right Arrow
    0x50: [u'←',    u'←',   None,   None], # Left Arrow
    0x51: [u'↓',    u'↓',   None,   None], # Down Arrow
    0x52: [u'↑',    u'↑',   None,   None],  # Up Arrow
    0x53: [None,    None,   None,   None], # Num Lock
    0x54: ['/',     '/',    None,   None], # Keypad /
    0x55: ['*',     '*',    None,   None], # Keypad *
    0x56: ['-',     '-',    None,   None], # Keypad -
    0x57: ['+',     '+',    None,   None], # Keypad +
    0x58: ['\n',    '\n',   None,   None], # Keypad EEnter
    0x59: ['1',     None,   None,   None], # Keypad 1 and End
    0x5a: ['2',     u'↓',   None,   None], # Keypad 2 and Down Arrow
    0x5b: ['3',     None,   None,   None], # Keypad 3 and Page Down
    0x5c: ['4',     u'←',   None,   None], # Keypad 4 and Left Arrow
    0x5d: ['5',     None,   None,   None], # Keypad 5
    0x5e: ['6',     u'→',   None,   None], # Keypad 6 and Right Arrow
    0x5f: ['7',     None,   None,   None], # Keypad 7 and Home
    0x60: ['8',     u'↑',   None,   None], # Keypad 8 and Up Arrow
    0x61: ['9',     None,   None,   None], # Keypad 9 and Page Up
    0x62: ['0',     None,   None,   None], # Keypad 0 and Insert
    0x63: ['.',     None,   None,   None], # Keypad . and Delete
    0x64: ['\\',    '|',    None,   None], # Keyboard Non-US \ and |
    0x65: [None,    None,   None,   None], # Keyboard Application
    0x66: [None,    None,   None,   None], # Keyboard Power
    0x67: ['=',     None,   None,   None], # Keypad =
    0x68: [None,    None,   None,   None], # Keyboard F13
    0x69: [None,    None,   None,   None], # Keyboard F14
    0x6a: [None,    None,   None,   None], # Keyboard F15
    0x6b: [None,    None,   None,   None], # Keyboard F16
    0x6c: [None,    None,   None,   None], # Keyboard F17
    0x6d: [None,    None,   None,   None], # Keyboard F18
    0x6e: [None,    None,   None,   None], # Keyboard F19
    0x6f: [None,    None,   None,   None], # Keyboard F20
    0x70: [None,    None,   None,   None], # Keyboard F21
    0x71: [None,    None,   None,   None], # Keyboard F22
    0x72: [None,    None,   None,   None], # Keyboard F23
    0x73: [None,    None,   None,   None], # Keyboard F24
    0x74: [None,    None,   None,   None], # Keyboard Execute
    0x75: [None,    None,   None,   None], # Keyboard Help
    0x76: [None,    None,   None,   None], # Keyboard Menu
    0x77: [None,    None,   None,   None], # Keyboard Select
    0x78: [None,    None,   None,   None], # Keyboard Stop
    0x79: [None,    None,   None,   None], # Keyboard Again
    0x7a: [None,    None,   None,   None], # Keyboard Undo
    0x7b: [None,    None,   None,   None], # Keyboard Cut
    0x7c: [None,    None,   None,   None], # Keyboard Copy
    0x7d: [None,    None,   None,   None], # Keyboard Paste
    0x7e: [None,    None,   None,   None], # Keyboard Find
    0x7f: [None,    None,   None,   None], # Keyboard Mute
    0x80: [None,    None,   None,   None], # Keyboard Volume Up
    0x81: [None,    None,   None,   None], # Keyboard Volume Down
    0x82: [None,    None,   None,   None], # Keyboard Locking Caps Lock
    0x83: [None,    None,   None,   None], # Keyboard Locking Num Lock
    0x84: [None,    None,   None,   None], # Keyboard Locking Scroll Lock
    0x85: [None,    None,   None,   None], # Keypad Comma
    0x86: [None,    None,   None,   None], # Keypad Equal Sign
    0x87: [None,    None,   None,   None], # Keyboard International1
    0x88: [None,    None,   None,   None], # Keyboard International2
    0x89: [None,    None,   None,   None], # Keyboard International3
    0x8a: [None,    None,   None,   None], # Keyboard International4
    0x8b: [None,    None,   None,   None], # Keyboard International5
    0x8c: [None,    None,   None,   None], # Keyboard International6
    0x8d: [None,    None,   None,   None], # Keyboard International7
    0x8e: [None,    None,   None,   None], # Keyboard International8
    0x8f: [None,    None,   None,   None], # Keyboard International9
    0x90: [None,    None,   None,   None], # Keyboard LANG1
    0x91: [None,    None,   None,   None], # Keyboard LANG2
    0x92: [None,    None,   None,   None], # Keyboard LANG3
    0x93: [None,    None,   None,   None], # Keyboard LANG4
    0x94: [None,    None,   None,   None], # Keyboard LANG5
    0x95: [None,    None,   None,   None], # Keyboard LANG6
    0x96: [None,    None,   None,   None], # Keyboard LANG7
    0x97: [None,    None,   None,   None], # Keyboard LANG8
    0x98: [None,    None,   None,   None], # Keyboard LANG9
    0x99: [None,    None,   None,   None], # Keyboard Alternate Erase
    0x9a: [None,    None,   None,   None], # Keyboard SysReq/Attention
    0x9b: [None,    None,   None,   None], # Keyboard Cancel
    0x9c: [None,    None,   None,   None], # Keyboard Clear
    0x9d: [None,    None,   None,   None], # Keyboard Prior
    0x9e: [None,    None,   None,   None], # Keyboard Return
    0x9f: [None,    None,   None,   None], # Keyboard Separator
    0xa0: [None,    None,   None,   None], # Keyboard Out
    0xa1: [None,    None,   None,   None], # Keyboard Oper
    0xa2: [None,    None,   None,   None], # Keyboard Clear/Again
    0xa3: [None,    None,   None,   None], # Keyboard CrSel/Props
    0xa4: [None,    None,   None,   None], # Keyboard ExSel
    0xa5: [None,    None,   None,   None], # Reserved
    0xa6: [None,    None,   None,   None], # Reserved
    0xa7: [None,    None,   None,   None], # Reserved
    0xa8: [None,    None,   None,   None], # Reserved
    0xa9: [None,    None,   None,   None], # Reserved
    0xaa: [None,    None,   None,   None], # Reserved
    0xab: [None,    None,   None,   None], # Reserved
    0xac: [None,    None,   None,   None], # Reserved
    0xad: [None,    None,   None,   None], # Reserved
    0xae: [None,    None,   None,   None], # Reserved
    0xaf: [None,    None,   None,   None], # Reserved
    0xb0: [None,    None,   None,   None], # Keypad 00
    0xb1: [None,    None,   None,   None], # Keypad 000
    0xb2: [None,    None,   None,   None], # Thousands Separator
    0xb3: [None,    None,   None,   None], # Decimal Separator
    0xb4: [None,    None,   None,   None], # Currency Unit
    0xb5: [None,    None,   None,   None], # Currency Sub-unit
    0xb6: ['(',     None,   None,   None], # Keypad (
    0xb7: [')',     None,   None,   None], # Keypad )
    0xb8: ['{',     None,   None,   None], # Keypad {
    0xb9: ['}',     None,   None,   None], # Keypad }
    0xba: ['\t',    None,   None,   None], # Keypad Tab
    0xbb: ['\n',    None,   None,   None], # Keypad Backspace
    0xbc: ['A',     None,   None,   None], # Keypad A
    0xbd: ['B',     None,   None,   None], # Keypad B
    0xbe: ['C',     None,   None,   None], # Keypad C
    0xbf: ['D',     None,   None,   None], # Keypad D
    0xc0: ['E',     None,   None,   None], # Keypad E
    0xc1: ['F',     None,   None,   None], # Keypad F
    0xc2: [None,    None,   None,   None], # Keypad XOR
    0xc3: ['^',     None,   None,   None], # Keypad ^
    0xc4: ['%',     None,   None,   None], # Keypad %
    0xc5: ['<',     None,   None,   None], # Keypad <
    0xc6: ['>',     None,   None,   None], # Keypad >
    0xc7: ['&',     None,   None,   None], # Keypad &
    0xc8: ['&&',    None,   None,   None], # Keypad &&
    0xc9: ['|',     None,   None,   None], # Keypad |
    0xca: ['||',    None,   None,   None], # Keypad ||
    0xcb: [':',     None,   None,   None], # Keypad :
    0xcc: ['#',     None,   None,   None], # Keypad #
    0xcd: [' ',     None,   None,   None], # Keypad Space
    0xce: ['@',     None,   None,   None], # Keypad @
    0xcf: ['!',     None,   None,   None], # Keypad !
    0xd0: [None,    None,   None,   None], # Keypad Memory Store
    0xd1: [None,    None,   None,   None], # Keypad Memory Recall
    0xd2: [None,    None,   None,   None], # Keypad Memory Clear
    0xd3: [None,    None,   None,   None], # Keypad Memory Add
    0xd4: [None,    None,   None,   None], # Keypad Memory Subtract
    0xd5: [None,    None,   None,   None], # Keypad Memory Multiply
    0xd6: [None,    None,   None,   None], # Keypad Memory Divide
    0xd7: [None,    None,   None,   None], # Keypad +/-
    0xd8: [None,    None,   None,   None], # Keypad Clear
    0xd9: [None,    None,   None,   None], # Keypad Clear Entry
    0xda: [None,    None,   None,   None], # Keypad Binary
    0xdb: [None,    None,   None,   None], # Keypad Octal
    0xdc: [None,    None,   None,   None], # Keypad Decimal
    0xdd: [None,    None,   None,   None], # Keypad Hexadecimal
    0xde: [None,    None,   None,   None], # Reserved
    0xdf: [None,    None,   None,   None], # Reserved
    0xe0: [None,    None,   None,   None], # Keyboard LeftControl
    0xe1: [None,    None,   None,   None], # Keyboard LeftShift
    0xe2: [None,    None,   None,   None], # Keyboard LeftAlt
    0xe3: [None,    None,   None,   None], # Keyboard Left GUI
    0xe4: [None,    None,   None,   None], # Keyboard RightControl
    0xe5: [None,    None,   None,   None], # Keyboard RightShift
    0xe6: [None,    None,   None,   None], # Keyboard RightAlt
    0xe7: [None,    None,   None,   None], # Keyboard Right GUI
    0xe8: [None,    None,   None,   None], # Keyboard Media Play/Pause
    0xe9: [None,    None,   None,   None], # Keyboard Media Stop CD
    0xea: [None,    None,   None,   None], # Keyboard Media Previous Song
    0xeb: [None,    None,   None,   None], # Keyboard Media Next Song
    0xec: [None,    None,   None,   None], # Keyboard Media Eject CD
    0xed: [None,    None,   None,   None], # Keyboard Media Volume Up
    0xee: [None,    None,   None,   None], # Keyboard Media Volume Down
    0xef: [None,    None,   None,   None], # Keyboard Media Mute
    0xf0: [None,    None,   None,   None], # Keyboard Media WWW
    0xf1: [None,    None,   None,   None], # Keyboard Media Back
    0xf2: [None,    None,   None,   None], # Keyboard Media Forward
    0xf3: [None,    None,   None,   None], # Keyboard Media Stop
    0xf4: [None,    None,   None,   None], # Keyboard Media Find
    0xf5: [None,    None,   None,   None], # Keyboard Media Scroll Up
    0xf6: [None,    None,   None,   None], # Keyboard Media Scroll Down
    0xf7: [None,    None,   None,   None], # Keyboard Media Edit
    0xf8: [None,    None,   None,   None], # Keyboard Media Sleep
    0xf9: [None,    None,   None,   None], # Keyboard Media Coffee
    0xfa: [None,    None,   None,   None], # Keyboard Media Refresh
    0xfb: [None,    None,   None,   None], # Keyboard Media Calculator
    0xfc: [None,    None,   None,   None], # Keyboard Media Play/Pause
    0xfd: [None,    None,   None,   None], # Keyboard Media Play
    0xfe: [None,    None,   None,   None], # Keyboard Media Pause
    0xff: [None,    None,   None,   None], # Reserved
}

KEY_CODES_US = KEY_CODES.copy()

KEY_CODES_DE = KEY_CODES.copy()
KEY_CODES_DE[0x08] = ['e',      'E',    '€',    None]
KEY_CODES_DE[0x10] = ['m',      'M',    'µ',    None]
KEY_CODES_DE[0x14] = ['q',      'Q',    '@',    None]
KEY_CODES_DE[0x1c] = ['z',      'Z',    None,   None]
KEY_CODES_DE[0x1d] = ['y',      'Y',    None,   None]
KEY_CODES_DE[0x1e] = ['1',      '!',    None,   None]
KEY_CODES_DE[0x1f] = ['2',      '"',    '²',    None]
KEY_CODES_DE[0x20] = ['3',      '§',    '³',    None]
KEY_CODES_DE[0x21] = ['4',      '$',    None,   None]
KEY_CODES_DE[0x22] = ['5',      '%',    None,   None]
KEY_CODES_DE[0x23] = ['6',      '&',    None,   None]
KEY_CODES_DE[0x24] = ['7',      '/',    '{',    None]
KEY_CODES_DE[0x25] = ['8',      '(',    '[',    None]
KEY_CODES_DE[0x26] = ['9',      ')',    ']',    None]
KEY_CODES_DE[0x27] = ['0',      '=',    '}',    None]
KEY_CODES_DE[0x2d] = ['ß',      '?',    '\\',   None]
KEY_CODES_DE[0x2e] = ['´',      '`',    None,   None]
KEY_CODES_DE[0x2f] = ['ü',      'Ü',    None,   None]
KEY_CODES_DE[0x30] = ['+',      '*',    '~',    None]
KEY_CODES_DE[0x32] = ['#',      "'",    None,   None]
KEY_CODES_DE[0x33] = ['ö',      'Ö',    None,   None]
KEY_CODES_DE[0x34] = ['ä',      'Ä',    None,   None]
KEY_CODES_DE[0x35] = ['^',      '°',    None,   None]
KEY_CODES_DE[0x36] = [',',      ';',    None,   None]
KEY_CODES_DE[0x37] = ['.',      ':',    None,   None]
KEY_CODES_DE[0x38] = ['-',      '_',    None,   None]
KEY_CODES_DE[0x64] = ['<',      '>',    '|',    None]
