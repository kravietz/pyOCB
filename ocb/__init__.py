#!/usr/bin/env python
#
# Author:
#     Pawel Krawczyk (http://ipsec.pl)
# Parts based on C implementation by:
#     Ted Krovetz (tdk@acm.org)
#
# Licensed under GNU General Public License (GPL)
# Version 3, 29 June 2007
# http://www.gnu.org/licenses/gpl.html

import math

class OCB:
    """
    Class implementing OCB authentication-encryption mode based on AES cipher in pure Python.
    
    Input: 
        arbitrary length array of 0..255 integers for encryption ("plaintext")
        arbitrary length array of 0..255 integers that will remain unencrypted,
            but will be covered by authentication protection ("header")
    Output:
        array of integers of same length as plaintext ("ciphertext",
            no block size alignment or padding)
        array of integers for authentication ("authentication tag")
    Interface:
        aes = AES(128)
        ocb = OCB(aes)
        nonce = range(16)         # AES block size
        key = [0] * (128/8)       # AES keysize used here
        plaintext = [0] * 100     # arbitrary length plaintext for encryption
        header = [1] * 100        # arbitrary length "header" plaintext
        ocb.setNonce(nonce)       # nonce MUST NOT be used more than once
        ocb.setKey(key)           # AES key for encryption
        (tag,ciphertext) = ocb.encrypt(plaintext, header)
        # ciphertext is same length as plaintext
        # header remains unencrypted
        # tag is 16 bytes long message authentication code (not secret)
        
        (is_authentic, plaintext2) = ocb.decrypt(header, ciphertext, tag)
        # is_authentic is True if ciphertext matches "tag" and is authentic
        # otherwise plaintext is empty
     
    """
    def __init__(self, cipher):
        self.cipher = cipher
        self.cipherKeySize = cipher.getKeySize()
        self.cipherRounds = cipher.getRounds()
        self.cipherBlockSize = cipher.getBlockSize()
        self.cipherKey = [] # XXX do we need this?
        self.nonce = []

    def _onlyBytes(self, table):
        """
        Check if table contains only values 0-255.
        """
        for i in range(len(table)):
            if table[i] > 255:
                print("*** offender:", table[i])
                return False
        return True

    def setNonce(self, nonce):
        """
        Configure nonce N for current OCB instance.
        Input: array of integers
        Lengths must be same as cipher block number
        """
        assert len(nonce) == self.cipherKeySize
        assert self._onlyBytes(nonce)

        self.nonce = nonce

    def setKey(self, key):
        """
        Configure key K for current OCB instance.
        Input: array of integers
        Length must be 16, 24, 32 depending on keys size.
        """
        assert len(key) == self.cipherKeySize
        assert self._onlyBytes(key)

        self.cipherKey = key # XXX do we need this?
        self.cipher.setKey(key)

        # These routines manipulate the offsets which are used for pre- and
        # post-whitening of blockcipher invocations. The offsets represent
        # polynomials, and these routines multiply the polynomials by other
        # constant polynomials. Note that as an optimization two consecutive
        # invocations of "three_times" can be efficiently replaced:
        #    3(3(X)) == (2(2(X))) xor X
    def _times2(self, input_data):
        """
        >>> from aes import AES
        >>> aes = AES(128)
        >>> ocb = OCB(aes)
        >>> ocb._times2([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30]
        >>> ocb._times2([127, 128, 127, 128, 127, 128, 127, 200, 210, 220, 230, 240, 250, 251, 252, 255])
        [255, 0, 255, 0, 255, 0, 255, 145, 165, 185, 205, 225, 245, 247, 249, 254]
        """
        blocksize = self.cipherBlockSize
        assert len(input_data) == blocksize
        # set carry = high bit of src
        output = [0] * blocksize
        carry = input_data[0] >> 7 # either 0 or 1
        for i in range(len(input_data) - 1):
            output[i] = ((input_data[i] << 1) | (input_data[i + 1] >> 7)) % 256
        output[-1] = ((input_data[-1] << 1) ^ (carry * 0x87)) % 256
        assert len(output) == blocksize
        return output

    def _times3(self, input_data):
        """
        >>> from aes import AES
        >>> aes = AES(128)
        >>> ocb = OCB(aes)
        >>> ocb._times3([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        [0, 3, 6, 5, 12, 15, 10, 9, 24, 27, 30, 29, 20, 23, 18, 17]
        >>> ocb._times3([127, 128, 127, 128, 127, 128, 127, 200, 210, 220, 230, 240, 250, 251, 252, 255])
        [128, 128, 128, 128, 128, 128, 128, 89, 119, 101, 43, 17, 15, 12, 5, 1]
        """
        assert len(input_data) == self.cipherBlockSize
        output = self._times2(input_data)
        output = self._xor_block(output, input_data)
        assert len(output) == self.cipherBlockSize
        return output

    def _xor_block(self, input1, input2):
        """
        Return block made of two XORed blocks. Don't need to be of "blocksize"
        lenght, must be  equal length.
        >>> from aes import AES
        >>> aes = AES(128)
        >>> ocb = OCB(aes)
        >>> i1 = [127, 128, 127, 128, 127, 128, 127, 200, 210, 220, 230, 240, 250, 251, 252, 255]
        >>> i2 = [128, 128, 128, 128, 128, 128, 128, 89, 119, 101, 43, 17, 15, 12, 5, 1]
        >>> ocb._xor_block(i1, i2)
        [255, 0, 255, 0, 255, 0, 255, 145, 165, 185, 205, 225, 245, 247, 249, 254]
        """
        assert len(input1) == len(input2)
        output = []
        for i in range(len(input1)):
            output.append(input1[i] ^ input2[i])
        return output

    def _pmac(self, header):
        """
        Calculates PMAC of optional user submitted header.
        
            Input: header, array of integers of arbitrary lenght
            Output: header authentication tag, array of integers
        
        >>> from aes import AES
        >>> aes = AES(128)
        >>> ocb = OCB(aes)
        >>> key = [0] * 16
        >>> nonce = [0] * 16
        >>> header = range(30)
        >>> ocb.setNonce(nonce)
        >>> ocb.setKey(key)
        >>> header = range(30)
        >>> ocb._pmac(header)
        [170, 167, 93, 215, 89, 168, 168, 248, 222, 127, 42, 231, 123, 50, 212, 230]
        >>> nonce = [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47]
        >>> key = range(16)
        >>> ocb.setNonce(nonce)
        >>> ocb.setKey(key)
        >>> header = range(90)
        >>> ocb._pmac(header)
        [203, 23, 188, 81, 237, 161, 108, 134, 119, 64, 232, 75, 68, 126, 127, 187]
        """
        assert len(header)
        assert self.cipherKey
        assert self.cipherBlockSize

        blocksize = self.cipherBlockSize

        # Break H into blocks
        m = int(max(1, math.ceil(len(header) / float(blocksize))))

        # Initialize strings used for offsets and checksums
        offset = self.cipher.encrypt([0] * blocksize)
        offset = self._times3(offset)
        offset = self._times3(offset)
        checksum = [0] * blocksize

        # Accumulate the first m - 1 blocks
        # skipped if m == 1
        for i in range(m - 1):
            offset = self._times2(offset)
            H_i = header[(i * blocksize):(i * blocksize) + blocksize]
            assert len(H_i) == blocksize
            xoffset = self._xor_block(H_i, offset)
            encrypted = self.cipher.encrypt(xoffset)
            checksum = self._xor_block(checksum, encrypted)

        # Accumulate the final block
        offset = self._times2(offset)
        # check if full block
        H_m = header[((m - 1) * blocksize):]
        assert len(H_m) <= blocksize
        if len(H_m) == blocksize:
            # complete last block
            # this is only possible if m is 1
            offset = self._times3(offset)
            checksum = self._xor_block(checksum, H_m)
        else:
            # incomplete last block
            # pad with separator binary 1
            # then pad with zeros until full block
            H_m.append(int('10000000', 2))
            while len(H_m) < blocksize:
                H_m.append(0)
            assert len(H_m) == blocksize
            checksum = self._xor_block(checksum, H_m)
            offset = self._times3(offset)
            offset = self._times3(offset)

        # Compute PMAC result
        final_xor = self._xor_block(offset, checksum)
        auth = self.cipher.encrypt(final_xor)
        return auth

    def encrypt(self, plaintext, header):
        """
        Encrypt a message of arbitrary length and optional header in OCB mode.
        
            Input: plaintext (array of integers), header (array of integers)
            Output: (tag, ciphertext)
        >>> aes = AES(128)
        >>> ocb = OCB(aes)
        >>> key = h2a('000102030405060708090A0B0C0D0E0F')
        >>> nonce = h2a('000102030405060708090A0B0C0D0E0F')
        >>> ocb.setKey(key)
        >>> ocb.setNonce(nonce)
        >>> plaintext = []
        >>> header    = []
        >>> (tag,ciphertext) = ocb.encrypt(plaintext, header)
        >>> print a2h(tag)
        BF3108130773AD5EC70EC69E7875A7B0
        """
        assert self.cipherKey
        assert self.cipherBlockSize
        assert self.nonce
        assert self._onlyBytes(plaintext)
        assert self._onlyBytes(header)

        blocksize = self.cipherBlockSize

        # Break H into blocks
        m = int(max(1, math.ceil(len(plaintext) / float(blocksize))))

        # Initialize strings used for offsets and checksums
        offset = self.cipher.encrypt(self.nonce)
        checksum = [0] * blocksize
        ciphertext = []

        # Encrypt and accumulate first m - 1 blocks
        # skipped if m == 1
        #for i = 1 to m - 1 do           // Skip if m < 2
        #    Offset = times2(Offset)
        #    Checksum = Checksum xor M_i
        #    C_i = Offset xor ENCIPHER(K, M_i xor Offset)
        #end for
        for i in range(m - 1):
            offset = self._times2(offset)
            M_i = plaintext[(i * blocksize):(i * blocksize) + blocksize]
            assert len(M_i) == blocksize
            checksum = self._xor_block(checksum, M_i)
            xoffset = self.cipher.encrypt(self._xor_block(M_i, offset))
            ciphertext += self._xor_block(offset, xoffset)
            assert len(ciphertext) % blocksize == 0

        # Encrypt and accumulate final block        
        M_m = plaintext[((m - 1) * blocksize):]
        # Offset = times2(Offset)
        offset = self._times2(offset)
        #  b = bitlength(M_m) // Value in 0..BLOCKLEN
        bitlength = len(M_m) * 8
        assert bitlength <= blocksize * 8
        # num2str(b, BLOCKLEN)
        tmp = [0] * blocksize
        tmp[-1] = bitlength
        # Pad = ENCIPHER(K, num2str(b, BLOCKLEN) xor Offset)
        pad = self.cipher.encrypt(self._xor_block(tmp, offset))
        tmp = []
        # C_m = M_m xor Pad[1..b]         // Encrypt M_m
        # this MAY be a partial size block
        C_m = self._xor_block(M_m, pad[:len(M_m)])
        ciphertext += C_m
        # Tmp = M_m || Pad[b+1..BLOCKLEN]
        tmp = M_m + pad[len(M_m):]
        assert len(tmp) == blocksize
        # Checksum = Checksum xor Tmp
        checksum = self._xor_block(tmp, checksum)

        # Compute authentication tag
        offset = self._times3(offset)
        tag = self.cipher.encrypt(self._xor_block(checksum, offset))
        if len(header) > 0:
            tag = self._xor_block(tag, self._pmac(header))

        return (tag, ciphertext)


    def decrypt(self, header, ciphertext, tag):
        assert self.cipherKey
        assert self.cipherBlockSize
#        assert nonce
        assert self._onlyBytes(ciphertext)
        assert self._onlyBytes(tag)

        blocksize = self.cipherBlockSize

        # Break C into blocks
        m = int(max(1, math.ceil(len(ciphertext) / float(blocksize))))

        # Initialize strings used for offsets and checksums
        offset = self.cipher.encrypt(self.nonce)
        checksum = [0] * blocksize
        plaintext = []

#        for i = 1 to m - 1 do           // Skip if a < 2
#            Offset = times2(Offset)
#            M_i = Offset xor DECIPHER(K, C_i xor Offset)
#            Checksum = Checksum xor M_i
#        end for
        for i in range(m - 1):
            offset = self._times2(offset)
            C_i = ciphertext[(i * blocksize):(i * blocksize) + blocksize]
            assert len(C_i) == blocksize
            tmp = self.cipher.decrypt(self._xor_block(C_i, offset))
            M_i = self._xor_block(offset, tmp)
            checksum = self._xor_block(checksum, M_i)
            plaintext += M_i
            assert len(plaintext) % blocksize == 0

            # Decrypt and accumulate final block 
#         Offset = times2(Offset)
#         b = bitlength(C_m)              // Value in 0..BLOCKLEN
#         Pad = ENCIPHER(K, num2str(b, BLOCKLEN) xor Offset)
#         M_m = C_m xor Pad[1..b]
#         Tmp = M_m || Pad[b+1..BLOCKLEN]
#         Checksum = Checksum xor Tmp
        offset = self._times2(offset)
        C_m = ciphertext[((m - 1) * blocksize):]
        bitlength = len(C_m) * 8
        assert bitlength <= blocksize * 8
        tmp = [0] * blocksize
        tmp[-1] = bitlength
        pad = self.cipher.encrypt(self._xor_block(tmp, offset))
        tmp = []
        M_m = self._xor_block(C_m, pad[:len(C_m)])
        plaintext += M_m
        tmp = M_m + pad[len(M_m):]
        assert len(tmp) == blocksize
        checksum = self._xor_block(tmp, checksum)

        # Compute valid authentication tag
#         Offset = times3(Offset)
#         FullValidTag = ENCIPHER(K, Offset xor Checksum)
#         if bitlength(H) > 0 then
#            FullValidTag = FullValidTag xor PMAC(K, H)
#         end if
        offset = self._times3(offset)
        full_valid_tag = self.cipher.encrypt(self._xor_block(offset, checksum))
        if len(header) > 0:
            full_valid_tag = self._xor_block(full_valid_tag, self._pmac(header))

        # Compute results
        if tag == full_valid_tag:
            return (True, plaintext)
        else:
            return (False, [])

def h2a(v):
    return [ int('0x%s' % str(v[i * 2:(i + 1) * 2]), 16) for i in range(int(math.ceil(len(v) / 2.0)))]
def a2h(a):
    return ''.join(['%02X' % a[i] for i in range(len(a))])

import unittest
import doctest
from aes import AES

class H2aTestCase(unittest.TestCase):
    def setUp(self):
        pass
    def test_h2a(self):
        self.assertEqual(h2a('10'), [16])
        self.assertEqual(h2a('0101'), [1, 1])
        self.assertEqual(h2a('0101ffaabbccddee'), [1, 1, 255, 170, 187, 204, 221, 238])
        self.assertEqual(h2a('0101ffaabbccddee0101ffaabbccddee'), [1, 1, 255, 170, 187, 204, 221, 238, 1, 1, 255, 170, 187, 204, 221, 238])
    def test_a2h(self):
        self.assertEqual(a2h([1, 1, 255, 170, 187, 204, 221, 238, 1, 1, 255, 170, 187, 204, 221, 238]), '0101FFAABBCCDDEE0101FFAABBCCDDEE')
        self.assertEqual(a2h([1, 1, 255, 170, 187, 204, 221, 238]), '0101FFAABBCCDDEE')
        self.assertEqual(a2h([1, 1]), '0101')
        self.assertEqual(a2h([16]), '10')

class OcbTestCase(unittest.TestCase):
    def setUp(self):
        # draft-krovetz-ocb-00.txt, page 11
        self.vectors = (# header, plaintext, expected tag, expectec ciphertext
        ('', '', 'BF3108130773AD5EC70EC69E7875A7B0', ''),
        ('', '0001020304050607', 'A45F5FDEA5C088D1D7C8BE37CABC8C5C', 'C636B3A868F429BB'),
        ('', '000102030405060708090A0B0C0D0E0F', 'F7EE49AE7AA5B5E6645DB6B3966136F9', '52E48F5D19FE2D9869F0C4A4B3D2BE57'),
        ('', '000102030405060708090A0B0C0D0E0F1011121314151617', 'A1A50F822819D6E0A216784AC24AC84C', 'F75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB'),
        ('', '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', '09CA6C73F0B5C6C5FD587122D75F2AA3', 'F75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27'),
        ('', '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627', '9DB0CDF880F73E3E10D4EB3217766688', 'F75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C'),
        ('0001020304050607', '0001020304050607', '8D059589EC3B6AC00CA31624BC3AF2C6', 'C636B3A868F429BB'),
        ('000102030405060708090A0B0C0D0E0F', '000102030405060708090A0B0C0D0E0F', '4DA4391BCAC39D278C7A3F1FD39041E6', '52E48F5D19FE2D9869F0C4A4B3D2BE57'),
        ('000102030405060708090A0B0C0D0E0F1011121314151617', '000102030405060708090A0B0C0D0E0F1011121314151617', '24B9AC3B9574D2202678E439D150F633', 'F75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB'),
        ('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', '41A977C91D66F62C1E1FC30BC93823CA', 'F75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27'),
        ('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627', '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627', '65A92715A028ACD4AE6AFF4BFAA0D396', 'F75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C'),
               )
        self.key = h2a('000102030405060708090A0B0C0D0E0F')
        self.nonce = h2a('000102030405060708090A0B0C0D0E0F')

        self.aes = AES(128) # krovetz vectors are for 128 AES only
        self.ocb = OCB(self.aes)
        self.ocb.setNonce(self.nonce)
        self.ocb.setKey(self.key)

    def test_ocb(self):
        for vec in self.vectors:
            (header, plaintext, expected_tag, expected_ciphertext) = vec
            (tag, ciphertext) = self.ocb.encrypt(h2a(plaintext), h2a(header))
            (dec_valid, dec_plaintext) = self.ocb.decrypt(h2a(header), h2a(expected_ciphertext), h2a(expected_tag))
            self.assertEqual(a2h(tag), expected_tag)
            self.assertEqual(a2h(ciphertext), expected_ciphertext)
            self.assertEqual(dec_valid, True)
            self.assertEqual(a2h(dec_plaintext), plaintext)
#            print('H=', header, 'M=', plaintext)
#            print('T=', expected_tag, 'C=', expected_ciphertext, '(expected)')
#            print('T\'=', a2h(tag), 'C\'=', a2h(ciphertext), '(returned)')
#            print("Enc T==T\':", a2h(tag) == expected_tag, "C==C\':", a2h(ciphertext) == expected_ciphertext)
#            print("Dec Valid=", dec_valid, ", Plaintext equal=", a2h(dec_plaintext) == plaintext)

    def test_wrong(self):
        (header, plaintext, expected_tag, expected_ciphertext) = ('0001020304050607', '0001020304050607', '8D059589EC3B6AC00CA31624BC3AF2C6', 'C636B3A868F429BB')
        # Tamper with tag
        (dec_valid, dec_plaintext) = self.ocb.decrypt(h2a(header), h2a(expected_ciphertext), h2a(expected_tag.replace('0', '1')))
        self.assertEqual(dec_valid, False)
        # Tamper with ciphertext
        (dec_valid, dec_plaintext) = self.ocb.decrypt(h2a(header), h2a(expected_ciphertext.replace('3', '1')), h2a(expected_tag))
        self.assertEqual(dec_valid, False)
        # Tamper with header
        (dec_valid, dec_plaintext) = self.ocb.decrypt(h2a(header.replace('0', '1')), h2a(expected_ciphertext), h2a(expected_tag))
        self.assertEqual(dec_valid, False)

if __name__ == "__main__":
    unittest.main()
    doctest.testmod()
