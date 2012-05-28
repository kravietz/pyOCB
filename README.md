This module provides pure Python implementation of authenticated encryption mode OCB (Offset Codebook Mode) using AES block cipher. OCB offers confidentiality, integrity and authenticity of data in single encryption step and using single interface. It's alternative to traditional modes (like CTR or CBC) with separate HMAC calculation.

Usage
=====

Loading a block cipher. The OCB module provides built-in AES implementation, but other block ciphers can be used as well.

	>>> from ocb.aes import AES
	>>> from ocb import OCB

Initalize OCB-AES cipher objects:

	>>> aes = AES(128)
	>>> ocb = OCB(aes)
	
Initialize cipher parameters. Nonce *must* must be selected as a new value for each message encrypted.	

	>>> nonce = range(16)
	>>> ocb.setNonce(nonce)
	
AES 128 bit key: 

	>>> key = [0] * (128/8)
	>>> ocb.setKey(key)
	
Input plaintext of arbitrary length. This block will be encrypted and its integrity protected:

	>>> plaintext = range(10) 
	
Optional, plaintext header of arbitrary length. This block will *not* be encrypted, but its integrity will be protected:

	>>> header = [1] * 5

Encryption method over _plaintext_ and _header_ returns ciphertext and *authentication tag*. The tag protects integrity of both plaintext and header.

	>>> (tag,ciphertext) = ocb.encrypt(plaintext, header)
	>>> print(tag)
	[112, 241, 108, 123, 21, 7, 119, 43, 239, 210, 156, 158, 111, 17, 42, 46] 
	>>> print(ciphertext)
	[180, 107, 115, 96, 69, 33, 217, 56, 249, 65]

The decrypt method takes _header_, _ciphertext_ and _tag_ on input. It returns a tuple of decrypted plaintext and flag indicating whether input data was not tampered with. 
	
	>>> (is_authentic, plaintext2) = ocb.decrypt(header, ciphertext, tag)
	>>> print(is_authentic, plaintext2)
	True [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

The flag will be set to _False_ and plaintext will be empty if either header or ciphertext were modified:

	>>> ciphertext[3] = 97
	>>> ocb.decrypt(header, ciphertext, tag)
	(False, [])
	>>> header[3] = 0
	>>> ocb.decrypt(header, ciphertext, tag)
	(False, [])

References
==========
* [The OCB Authenticated-Encryption Algorithm](http://datatracker.ietf.org/doc/draft-krovetz-ocb/?include_text=1) (Internet draft)
* [OCB Mode](http://en.wikipedia.org/wiki/OCB_mode) (Wikipedia)