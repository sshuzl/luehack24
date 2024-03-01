# ransomware - Writeup

We are given a binary called `ransomware.elf`, an encrypted file `flag.txt.crypt` and a file `info.txt` with some information about these two files. We need to decrypt the file `flag.txt.crypt` to get the flag. The challenge description tells us that the flag was encrypted by the ransomware so we need to reverse engineer the ransomware to get the flag.

## Step 1: Analyzing the ransomware

We load the ransomware into Ghidra and let it analyze the binary. Luckily, the binary is not stripped, so we can see the function names and the strings in the binary. 
Jumping to the `main` function, we can see that the ransomware is actually not too dangerous as it only encrypts files that are explicitly given to it and it does not necessarily overwrite the original files.

```c
undefined8 main(int param_1,undefined8 *param_2)
{
  if (param_1 < 3) {
    printf("Usage: %s <path/to/input/file> <path/to/output/file>\n",*param_2);
    uVar3 = 0;
  }
```

If the binary is called with sufficiently many parameters, it checks whether some CPU instructions are available in the machine it executes on. If not, it prints an error message and exits.

```c
  else {
    lVar1 = cpuid_Version_info(1);
    if ((*(uint *)(lVar1 + 0xc) & 0x2000000) == 0) {
      puts("[-] Error: Missing CPU instructions");
    }
```

Otherwise it asks the user for permission to continue its operation.

```c
    else {
      __filename = (char *)param_2[1];
      __filename_00 = (char *)param_2[2];
      printf("[+] Encrypting file: %s\n",__filename,(ulong)*(uint *)(lVar1 + 8));
      printf("[?] Do you want to continue? (y/N): ");
      iVar2 = getc(stdin);
      if (((byte)iVar2 & 0xdf) != 0x59) {
        puts("[+] Operation cancelled");
        return 0;
      }
```

If the user gives their consent, the ransomware opens the input file (`__filename`) and the output path (`__filename00`) and passes both file streams to the `encrypt_file` function.

```c
      __stream = fopen(__filename,"rb");
      if (__stream == (FILE *)0x0) {
        printf("[-] Error: Unable to open file: %s\n",__filename);
      }
      else {
        __stream_00 = fopen(__filename_00,"w+b");
        if (__stream_00 != (FILE *)0x0) {
          encrypt_file(__stream,__stream_00);
          fclose(__stream);
          fclose(__stream_00);
          puts("[+] File encrypted successfully");
          return 0;
        }
```

Let's see what the `encrypt_file` function actually does.

The function starts by initializing a pseudorandom number generator with the current time represented as the seconds-granular [UNIX timestamp](https://www.unixtimestamp.com/).

```c
  tVar4 = time((time_t *)0x0);
  srand((uint)tVar4);
```

Then, random integers are generated and written into a buffer of 16 bytes length. Those random integers are a deterministic sequence depending on the seed that was fed into `srand` earlier. If we know the seed, then we also need the random integers that are returned by the `random()` function. The random integers are written sequentially into the buffer. Since the buffer is 16 bytes long and each integer consists of 4 bytes, we know that four integers are written into the buffer.

```c
  puVar7 = (undefined4 *)local_118;
  do {
    lVar2 = random();
    puVar6 = puVar7 + 1;
    *puVar7 = (int)lVar2;
    puVar7 = puVar6;
  } while (local_108 != puVar6);
```

After this is done, we see the same thing happening again for another 16 bytes buffer.

```c
  puVar7 = local_108;
  do {
    lVar2 = random();
    puVar6 = puVar7 + 1;
    *puVar7 = (int)lVar2;
    puVar7 = puVar6;
  } while ((undefined4 *)local_f8 != puVar6);
```

Directly afterwards, we observe a function call to `expand_key` that gets the second buffer that was filled with random integers as an input argument.

```c
  expand_key(local_108,local_f8,2);
```

Inspecting the `expand_key()` function, we see that we have to deal with [AES encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard). This is because the code uses the `AESKEYGENASSIST` CPU instruction of the AES-NI instruction set extension available in modern x86 CPUs. That probably is the instruction set the ransomware checked for earlier.

```c
  auVar22 = *param_1;
  auVar23 = aeskeygenassist(auVar22,1);
```

Because the input buffer to the `expand_key()` function is 16 bytes long, we can assume, that the binary uses AES-128 to encrypt files. AES-128 uses 10 rounds of encryption, which means that the output buffer that holds all round keys, must hold 16*(10+1) bytes. The +1 is needed, because the first round key gets added to the plaintext before the first round of encryption. So we can correct Ghidras assumption about the function header and also rename the buffers `local_108` to `key` and `local_f8` to `round_keys`.

```c
  piVar7 = (int *)iv;
  do {
    lVar3 = random();
    puVar7 = piVar7 + 1;
    *piVar7 = (int)lVar3;
    piVar7 = puVar7;
  } while ((int *)key != puVar7);
  piVar7 = (int *)key;
  do {
    lVar3 = random();
    piVar8 = piVar7 + 1;
    *piVar7 = (int)lVar3;
    piVar7 = piVar8;
  } while ((int *)round_keys != piVar8);
  expand_key(key,round_keys,2);
```

The next three rows are a typical sequence to detect the length of a file. In this case, the length of the input file is determined.

```c
  fseek(param_1,0,__whence);
  in_file_len = ftell(param_1);
  fseek(param_1,0,0);
```

The next lines are a little cryptic. Some value in `uVar9` is added to `in_file_len` and the result is stored in `__size`. Then, `malloc` gets called twice to allocate memory for two buffers `__ptr` and `__ptr_00`. The first buffer is `__size` bytes long. The second buffer is 16 bytes longer. `plVar11` stores a pointer into the first buffer at the end of `in_file_len` bytes. Then, the input file is read into the first buffer.

```c
  uVar9 = (((ulong)((long)in_file_len >> 0x3f) >> 0x3c) -
          (ulong)((int)in_file_len + ((uint)((long)in_file_len >> 0x3f) >> 0x1c) & 0xf)) + 0x10;
  __size = uVar9 + in_file_len;
  __ptr = malloc(__size);
  __ptr_00 = (char (*) [16])malloc(__size + 0x10);
  plVar11 = (long *)(in_file_len + (long)__ptr);
  fread(__ptr,in_file_len,1,param_1);
```

So the first buffer is quite likely the plaintext buffer. The additional space at the end might be used for some padding to make the input length a multiple of the AES block size, which is 16 bytes. We rename the variables accordingly.

```c
  uVar9 = (((ulong)((long)in_file_len >> 0x3f) >> 0x3c) -
          (ulong)((int)in_file_len + ((uint)((long)in_file_len >> 0x3f) >> 0x1c) & 0xf)) + 0x10;
  ptx_buf_len = uVar9 + in_file_len;
  ptx_buf = (char *)malloc(ptx_buf_len);
  ctx_buf = (char *)malloc(ptx_buf_len + 0x10);
  padding_ptr = ptx_buf + in_file_len;
  fread(ptx_buf,in_file_len,1,param_1);
```

Then, some crazy stuff is going on that depends on the padding bytes. Basically, some padding values are appended to the input data.

```c
  lVar3 = (uVar9 & 0xff) * 0x101010101010101;
  uVar10 = (uint)uVar9;
  if (uVar10 < 8) {
    if ((uVar9 & 4) == 0) {
      if ((uVar10 != 0) && (*padding_ptr = (char)lVar3, (uVar9 & 2) != 0)) {
        *(short *)(padding_ptr + ((uVar9 & 0xffffffff) - 2)) = (short)lVar3;
      }
    }
    else {
      *(int *)padding_ptr = (int)lVar3;
      *(int *)(padding_ptr + ((uVar9 & 0xffffffff) - 4)) = (int)lVar3;
    }
  }
  else {
    *(long *)padding_ptr = lVar3;
    *(long *)(padding_ptr + ((uVar9 & 0xffffffff) - 8)) = lVar3;
    uVar10 = uVar10 + ((int)padding_ptr - (int)((ulong)(padding_ptr + 8) & 0xfffffffffffffff8)) &
             0xfffffff8;
    if (7 < uVar10) {
      uVar9 = 0;
      do {
        uVar6 = (int)uVar9 + 8;
        *(long *)(((ulong)(padding_ptr + 8) & 0xfffffffffffffff8) + uVar9) = lVar3;
        uVar9 = (ulong)uVar6;
      } while (uVar6 < uVar10);
    }
  }
```

Then, finally, the encryption takes place.

```c
  *(char (*) [16])ctx_buf = iv;
  if ((ptx_buf_len & 0xf) == 0) {
    uVar9 = ptx_buf_len >> 4;
    if (uVar9 == 0) goto LAB_0010180e;
  }
  else {
    uVar9 = (ptx_buf_len >> 4) + 1;
  }
  lVar3 = 0;
  do {
    auVar11 = (undefined  [16])iv ^ round_keys._0_16_ ^ *(undefined (*) [16])(ptx_buf + lVar3);
    pauVar4 = (undefined (*) [16])(round_keys + 0x10);
    do {
      auVar11 = aesenc(auVar11,*pauVar4);
      pauVar5 = pauVar4 + 3;
      auVar11 = aesenc(auVar11,pauVar4[1]);
      auVar11 = aesenc(auVar11,pauVar4[2]);
      pauVar4 = pauVar5;
    } while ((undefined (*) [16])(round_keys + 0xa0) != pauVar5);
    iv = (char  [16])aesenclast(auVar11,round_keys._160_16_);
    *(char (*) [16])(ctx_buf + lVar3 + 0x10) = iv;
    lVar3 = lVar3 + 0x10;
  } while (uVar9 * 0x10 != lVar3);
```

As we can see, the first random buffer from the beginning gets written into `ctx_buf` this is probably the initialization vector `iv` that is required by the block mode that is in use.
Then the number of blocks is computed and stored in `uVar9` and a `do while` loop runs over all blocks. The current block is computed in the `pauVar3` pointer. At the beginnig of the block encryption, the `iv` is XOR'ed with the input and the first round key. This is an indicator that the CBC block mode is used because the `iv` is not used again during the encryption of the block.
The inner `do while` loop now performs all of the 10 AES encryption rounds. After the loop, the final ciphertext block is stored in `iv` to be used with the next block and also gets written to the `ctx_buf` at the respective offset.

After renaming some variables properly, the encryption looks like this.

```c
  *(char (*) [16])ctx_buf = iv;
  if ((ptx_buf_len & 0xf) == 0) {
    num_blocks = ptx_buf_len >> 4;
    if (num_blocks == 0) goto LAB_0010180e;
  }
  else {
    num_blocks = (ptx_buf_len >> 4) + 1;
  }
  block_offset = 0;
  do {
    current_block =
         (char  [16])
         ((undefined  [16])iv ^ round_keys._0_16_ ^ *(undefined (*) [16])(ptx_buf + block_offset));
    round_key = (char (*) [16])(round_keys + 0x10);
    do {
      auVar8 = aesenc((undefined  [16])current_block,(undefined  [16])*round_key);
      pacVar3 = round_key + 3;
      auVar8 = aesenc(auVar8,(undefined  [16])round_key[1]);
      current_block = (char  [16])aesenc(auVar8,(undefined  [16])round_key[2]);
      round_key = pacVar3;
    } while ((char (*) [16])(round_keys + 0xa0) != pacVar3);
    iv = (char  [16])aesenclast((undefined  [16])current_block,round_keys._160_16_);
    *(char (*) [16])(ctx_buf + block_offset + 0x10) = iv;
    block_offset = block_offset + 0x10;
  } while (num_blocks * 0x10 != block_offset);
```

Because the ciphertext block is always used as the iv for the next block, we can now be certain that AES is being used in CBC mode.

Eventually, the computed ciphertext is written to the output file.

```c
LAB_0010180e:
  fwrite(ctx_buf,ptx_buf_len + 0x10,1,param_2);
```

# Step 2: Decrypting the flag

We learned the following things during step 1:

* The flag is AES-128-CBC encrypted
* The first 16 bytes of the encrypted file are the initialization vector that was randomly generated during encryption
* The initialization vector and the encryption key are generated using a pseudorandom number generator that was seeded with the current system time in the form of a UNIX timestamp

Well, that's all we need! We can write a Python script that performs AES-128-CBC decryption for us. From the `info.txt` file we know the time when `flag.txt.crypt` was created. Presumably, the timestamp used during encryption is only some seconds before the creation of the file. Because we are given the initialization vector, we can test some timestamps whether they result in generating the same IV. If so, we can also generate the key and decrypt the flag.

We can use the same libc pseudorandom number generator in Python with the help of `ctypes`. Additionally, we write a function that generates random 16 byte sequences like the ransomware does.

```python
class Random:
    def __init__(self, seed: int):
        from ctypes import CDLL
        self.libc = CDLL('libc.so.6')
        self.seed(seed)
        pass

    def seed(self, seed: int) -> None:
        self.libc.srandom(seed & 0xFFFFFFFF)
        return
    
    def rand(self) -> int:
        return self.libc.random() & 0xFFFFFFFF
    
    pass # Random

def get_rand16(rand: Random) -> bytes:
    rr = [rand.rand() for _ in range(4)]
    return b''.join([i.to_bytes(4, 'little') for i in rr])
```

We use the following functions to extract the IV and ciphertext from `flag.txt.crypt` and the timestamp from `info.txt`.

```python
def get_iv_ctx(path: str) -> tuple[bytes, bytes]:
    with open(path, 'rb') as f:
        ctx = f.read()
        pass
    return ctx[:16], ctx[16:]

def get_time(path: str) -> int:
    from datetime import datetime
    with open(path, 'r') as f:
        data = f.read()
        pass
    for line in data.split('\n'):
        if 'flag' in line:
            d = line.split()
            dt = datetime.fromisoformat(f'{d[5]}T{d[6]}{d[7]}')
            return int(dt.timestamp())
        pass
    return -1
```

And finally, we use `pycryptodomex` to perform AES-128-CBC decryption.

```python
def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(data), AES.block_size)
```
