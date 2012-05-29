This module provides pure Python implementation of authenticated encryption mode OCB (Offset Codebook Mode) using AES block cipher. OCB offers confidentiality, integrity and authenticity of data in single encryption step and using single interface. It's alternative to traditional modes (like CTR or CBC) with separate HMAC calculation.

Data representation
-------------------
The module operates on _bytearray_ objects. Key, nonce, header and plaintext should be passed to OCB as bytearrays. 

	>>> plaintext = bytearray('The Magic Words are Squeamish Ossifrage')
	>>> header = bytearray('Recipient: john.doe@example.com')
	>>> key = bytearray().fromhex('A45F5FDEA5C088D1D7C8BE37CABC8C5C')
	>>> nonce = bytearray(range(16))
	
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
OCB has two parameters: _key_ and _nonce_. Key will be typically 128, 192 or 256 bit AES key: 

	>>> key = bytearray().fromhex('A45F5FDEA5C088D1D7C8BE37CABC8C5C')
	>>> ocb.setKey(key)

Nonce doesn't need to be random and it can be based on counter. Nonce **must** be selected as a new value for each message encrypted. Nonce has to be the same length as underlying cipher block length, typically 128 bits:

	>>> nonce = bytearray(range(16))
	>>> ocb.setNonce(nonce)
		
Encryption
----------
Input _plaintext_ of arbitrary length. This block will be encrypted and its integrity protected:

	>>> plaintext = bytearray('The Magic Words are Squeamish Ossifrage')
	
Optional, plaintext _header_ of arbitrary length. This block will **not** be encrypted, but its integrity will be protected:

	>>> header = bytearray('Recipient: john.doe@example.com')

Encryption method over _plaintext_ and _header_ returns ciphertext and _authentication tag_. The tag protects integrity of both plaintext and header.

	>>> (tag,ciphertext) = ocb.encrypt(plaintext, header)
	>>> tag
	bytearray(b')\xc9vx\xda\xc9Z\x80)\xfe@\xd9)\x8d\x86\x91')
	>>> ciphertext
	bytearray(b'3D\xdf\x01\xf3;\xe8\x87\x84@\xef\xac\xbcyK:J_3} \x9e\x889\xcd\xa4NvW\x88\xc1}5\x9a\x8b\xc3\x82\xd9Z')

Encryption will reset _nonce_ status, so that it needs to be set to a new value.

Decryption
----------
Decryption needs OCB object with _key_ and _nonce_ set. The decrypt method takes _header_, _ciphertext_ and _tag_ on input. It returns a tuple of decrypted plaintext and flag indicating whether input data was not tampered with. 
	
	>>> (is_authentic, plaintext2) = ocb.decrypt(header, ciphertext, tag)
	>>> is_authentic
	True
	>>> str(plaintext2)
	'The Magic Words are Squeamish Ossifrage'

The flag will be set to _False_ and plaintext will be empty if ciphertext is modified:

	>>> ciphertext[3] = 0
	>>> ocb.decrypt(header, ciphertext, tag)
	(False, [])

The same happens if header is modified (even ciphertext was not):

	>>> header[3] = 0
	>>> ocb.decrypt(header, ciphertext, tag)
	(False, [])

References
==========
* [The OCB Authenticated-Encryption Algorithm](http://datatracker.ietf.org/doc/draft-krovetz-ocb/?include_text=1) (Internet draft)
* [OCB Mode](http://en.wikipedia.org/wiki/OCB_mode) (Wikipedia)