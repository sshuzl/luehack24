# pcbc_mode - Writeup

We are given a website that decrypts images in pcbc mode and an encrypted image that shows the flag when decrypted.

Reading about [propagating cipherblock chaining mode on Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#PCBC) we learn that changing one bit in the ciphertext will change the decryption of the current and all following blocks.
The idea for a solution is therefore to change a pixel in the last block. Fortunately, the server computes a hash over the image to check if we uploaded the encrypted flag, so we can circumvent this check by changing a single pixel as well.
