This module provides pure Python implementation of
authenticated encryption mode OCB (Offset Codebook Mode)
using AES block cipher.

Examples:

	>>> aes = AES(128)
	>>> ocb = OCB(aes)
	>>> nonce = range(16)         # AES block size
	>>> key = [0] * (128/8)       # AES keysize used here
	>>> plaintext = range(10)      # arbitrary length plaintext for encryption
	>>> header = [1] * 5          # arbitrary length "header" plaintext
	>>> ocb.setNonce(nonce)       # nonce MUST NOT be used more than once
	>>> ocb.setKey(key)           # AES key for encryption
	>>> (tag,ciphertext) = ocb.encrypt(plaintext, header)

Ciphertext is same length as plaintext. Header block remains unencrypted,
but its integrity is protected. Tag is 16 bytes long message authentication 
code (not secret).
 
	>>> print tag, ciphertext
	[112, 241, 108, 123, 21, 7, 119, 43, 239, 210, 156, 158, 111, 17, 42, 46] [180, 107, 115, 96, 69, 33, 217, 56, 249, 65]
	>>> (is_authentic, plaintext2) = ocb.decrypt(header, ciphertext, tag)
 
The flag is_authentic is True if ciphertext matches "tag" and is authentic.
Otherwise plaintext is empty.
 
	>>> print is_authentic, plaintext2
	True [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]