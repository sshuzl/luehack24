# ecb_mode - Writeup

We are given a website that decrypts a given image if its pixel count is a multiple of 16.
And we are given an image that shows the flag but was encrypted with AES-256-ECB.

Unfortunately, uploading the encrypted flag image to the decryptor website does not work to get the image decrypted.
If we read about [ECB mode on Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)), we see that ECB mode is not secure because it encrypts each block independently.
This means that we can decrypt each block independently as well, so changing one pixel in the encrypted image will only change 16 pixels in the decrypted image.
The upper half of the encrypted image looks very regular, so we can assume that the flag is in the lower half.
So we change a pixel in the upper half and test whether the websites decrypts that image for us.
And yes, it does!
The decrypted image shows the flag.

