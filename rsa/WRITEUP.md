# rsa - Writeup

The server asks us to send a public RSA key which consists of numbers `e` and `n`.
Then, the server will send us the flag encrypted with the given public key.
If we correctly generated the private key, we can decrypt the flag and get the flag.

We can read on [Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Operation) how the RSA crypto system works.

We use Python3 to generate an RSA key pair:

```python
def keygen():
    from Cryptodome.Util.number import getPrime
    p = getPrime(2048)
    q = getPrime(2048)
    n = p * q
    assert n.bit_length() >= 2048
    phi = (p-1) * (q-1)
    e = 0x10001
    d = pow(e, -1, phi)
    return n, e, d
```

We can use this code to generate a key pair and send `n` and `e` to the server by chosing menu entry `1`.

When we now choose menu option `2`, we get the flag encrypted with the public key we sent to the server.
We can decrypt the flag using the private key `d` and get the flag.

```python
def decrypt_flag(c: str, d: int, n: int) -> str:
    c = int(c, 16)
    p = pow(c, d, n)
    return bytes.fromhex(hex(p)[2:]).decode('ascii')
```

It is important to note that we receive the encrypted flag as a hexadecimal string.
We first have to convert the string to an integer and then decrypt it using the private key `d` and the modulus `n`.
The resulting number we get represents the flag.
To be able to read it, we have to convert the integer back to a string by taking the hexadecimal representation of the number and converting it to a byte string.
Finally, we can decode the byte string to a string using the ASCII encoding.
