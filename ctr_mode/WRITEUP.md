# ctr_mode - Writeup

We are given a website that encrypts images in counter mode and an encrypted image that shows the flag when decrypted.

Reading about [counter mode on Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR) shows that the nonce should not be reused for the same key. However, the website uses the same nonce for every image. This can be verified by encrypting an image several times. The resulting image always looks the same. That means that if we encrypt any image of the same size as the flag image and XOR both encrypted images, we get the XOR of the flag and the other image. If the other image is all the same color, we can easily read the flag. XORing two images can, e.g., be done with [ImageMagick](https://imagemagick.org/index.php) or [G'MIC]().
How to use these tools for this specific usecase is described in [a StackOverflow article](https://stackoverflow.com/questions/8504882/searching-for-a-way-to-do-bitwise-xor-on-images).

