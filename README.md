This module provides pure Python implementation of authenticated encryption mode OCB (Offset Codebook Mode) using AES block cipher. OCB offers confidentiality, integrity and authenticity of data in single encryption step and using single interface. It's alternative to traditional modes (like CTR or CBC) with separate HMAC calculation.

Usage
=====
Data
----
The module operates on byte arrays represented as array of integers (0 > i > 255). This will be eventually changed to Python _bytearray_ objects, for now you can use two utility functions to convert from and to real data.

	>>> from ocb.util import h2a, a2h
	>>> data = h2a('000102030405060708090A0B0C0D0E0F')
	>>> data
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
	>>> a2h(data)
	'000102030405060708090A0B0C0D0E0F'
	
Loading
-------
Load a block cipher and OCB mode:

	>>> from ocb.aes import AES
	>>> from ocb import OCB

The OCB module provides built-in AES implementation, but other block ciphers can be used as well. 

Initalize OCB-AES cipher objects:

	>>> aes = AES(128)
	>>> ocb = OCB(aes)

Parameters
----------
OCB has two parameters: _key_ and _nonce_. 

Dumb 128 bit key for AES: 

	>>> key = range(16)
	>>> ocb.setKey(key)

Nonce **must** be selected as a new value for each message encrypted. Nonce has to be the same length as key:	

	>>> nonce = range(16)
	>>> ocb.setNonce(nonce)
		
Encryption
----------
Input _plaintext_ of arbitrary length. This block will be encrypted and its integrity protected:

	>>> plaintext = range(10) 
	
Optional, plaintext _header_ of arbitrary length. This block will **not** be encrypted, but its integrity will be protected:

	>>> header = [1] * 5

Encryption method over _plaintext_ and _header_ returns ciphertext and _authentication tag_. The tag protects integrity of both plaintext and header.

	>>> (tag,ciphertext) = ocb.encrypt(plaintext, header)
	>>> print(tag)
	[112, 241, 108, 123, 21, 7, 119, 43, 239, 210, 156, 158, 111, 17, 42, 46] 
	>>> print(ciphertext)
	[180, 107, 115, 96, 69, 33, 217, 56, 249, 65]

Decryption
----------
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