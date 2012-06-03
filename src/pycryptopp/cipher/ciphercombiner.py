from binascii import a2b_hex, b2a_hex
import random
import xsalsa20, aes
from pycryptopp.hash import sha256, hkdf, comp4p

def randstr(n):
    return ''.join(map(chr, map(random.randrange, [0]*n, [256]*n)))

class CipherCombiner(object):
    def __init__(self, key = None, iv = None):
	self.cipher1 = aes.AES
	self.cipher2 = xsalsa.XSalsa
	self.keyhash = sha256.SHA256
	self.info = "pycryptopp cipher combiner"
	self.salt = None

	if key is not None:
            self.key = key
	    self.keylen = len(key)
	    pos = self.keylen - 32
	    self.key1 = key[:pos]
	    self.key2 = key[pos:]
	    
        self.iv1 = None
        self.iv2 = None
	    
        if iv is not None:
            assert len(iv) == 40
            self.iv1 = iv[:16]
            self.iv2 = iv[16:]

    def setHKDFHash(self, hash):
        self.keyhash = hash

    def setHKDFInfo(self, info):
        self.info = info

    def setHKDFIkm(self, ikm):
        self.ikm = ikm

    def setHKDFSalt(self, salt):
        self.salt = salt
 
    def generate_key(self, ikm, keylen):
        hk = hkdf.new(ikm, keylen, self.salt, self.info, self.keyhash)
        hk.extract()
        self.key = hk.expand()
	self.keylen = len(key)
	pos = self.keylen - 32
	self.key1 = key[:pos]
	self.key2 = key[pos:]

    def setCombinerIV(self, iv):
        assert len(iv) == 40
	self.iv1 = iv[:16]
	self.iv2 = iv[16:]
    
    def process(self, plaintext):
#       stage1_cipher = self.c1(self.key1, self.iv1).process(plaintext)
#	    cipher = self.c2(self.key2, self.iv2).process(stage1_cipher)
	if self.iv1 is None:
            stage1_cipher = self.cipher1(self.key1).process(plaintext)
        else:
            stage1_cipher = self.cipher1(self.key1, self.iv1).process(plaintext)

        if self.iv2 is None:
            cipher = self.cipher2(self.key2).process(stage1_cipher)
        else:
            cipher = self.cipher2(self.key2, self.iv2).process(stage1_cipher)

        return cipher


def start_up_self_test():
    """
    This is a quick test intended to detect major errors such as the library being miscompiled and segfaulting.
    """
    enc0 = "884fecf1f3945eaae55d3892eb79170b"
    from binascii import a2b_hex, b2a_hex

    key = "\x00"*16 + a2b_hex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
    iv = "\x00"*16 + a2b_hex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
    cryptor= CipherCombiner(key, iv)
    ct = cryptor.process("\x00"*16)
    if enc0 != b2a_hex(ct):
        raise Exception("pycryptopp failed startup self-test. Please run pycryptopp unit test.")

    enc1 = "35e2091fcbaf2793132f34a704d83518e945d4ad340fc39c926df59960acb4cbeaab29cdec65e2df079f9dbfb1dd4439197ed3aabbac2bb95bce77971d476a59"
    key = "2b7e151628aed2a6abf7158809cf4f3ca6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff88030"
    iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff9e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c"
    cryptor = CipherCombiner(a2b_hex(key),a2b_hex(iv))
    ct = cryptor.process(a2b_hex("62fde0b7ab1709b3da46adba120e767dcef54fe53aabf78190496114e241986b8bcb6a143c90edab50fd0701fb36b5982eb31eac0ee96265793d43fc2d9257af"))
    if enc1 != b2a_hex(ct):
        raise Exception("pycryptopp failed startup self-test. Please run pycryptopp unit test.")

    enc2 = "ab6b7bbef841450800c800fd8fb2b58ba7cd3f10cbdf92cd1586f77d82a5dc64a3600f43ab23d1860422bf167959e75ebcddf16ed3670255a84e4bfbad16120e"
    key = "2b7e151628aed2a6abf7158809cf4f3c9e1da239d155f52ad37f75c7368a536668b051952923ad44f57e75ab588e475a"
    iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeffaf06f17859dffa799891c4288f6635b5c5a45eee9017fd72"
    cryptor = CipherCombiner(a2b_hex(key),a2b_hex(iv))
    ct = cryptor.process(a2b_hex("956d23b6d2cc8ecc0b7aa7b69a8aca5c61e64d7a2cc94808d6d7eed0f8540255d679c3300239f3dcd63730b5c09854d7680115ca86295b846298ad56788ee995"))
    if enc2 != b2a_hex(ct):
        raise Exception("pycryptopp failed startup self-test. Please run pycryptopp unit test.")

    enc3 = "a0f5ae79a23644451a127688f3402fa9c86f44b15e063e9f5d0cc791c5f55beccbdacfc97dda3f5a8a516cf0dbfe"
    key = "2b7e151628aed2a6abf7158809cf4f3cd5c7f6797b7e7e9c1d7fd2610b2abf2bc5a7885fb3ff78092fb3abe8986d35e2"
    iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff744e17312b27969d826444640e9c4a378ae334f185369c95"
    cryptor = CipherCombiner(a2b_hex(key),a2b_hex(iv))
    ct = cryptor.process(a2b_hex("1c99976e4cce2c325fab4245367c71bdbc0f340a044974a5efea7e2442b8b7e64c0efc1bf74c1d7243baa67b8d5d"))
    if enc3 != b2a_hex(ct):
        raise Exception("pycryptopp failed startup self-test. Please run pycryptopp unit test.")

    enc4 = "089abe"
    key = "2b7e151628aed2a6abf7158809cf4f3c6799d76e5ffb5b4920bc2768bafd3f8c16554e65efcf9a16f4683a7a06927c11"
    iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff61ab951921e54ff06d9b77f313a4e49df7a057d5fd627989"
    cryptor = CipherCombiner(a2b_hex(key),a2b_hex(iv))
    ct = cryptor.process(a2b_hex("2ce6d8"))
    if enc4 != b2a_hex(ct):
        raise Exception("pycryptopp failed startup self-test. Please run pycryptopp unit test.")

    enc5 = "b15b6f196570e60fa1a1b3c5e2cffb4262cc6c6df9c34c0311d81b88dea4873c5b2c5c9857d2c89b1182dab437449c7c319b438bd668099d06f5f10fe3b2609b"
    key = "2b7e151628aed2a6abf7158809cf4f3cf68238c08365bb293d26980a606488d09c2f109edafa0bbae9937b5cc219a49c"
    iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff5190b51e9b708624820b5abdf4e40fad1fb950ad1adc2d26"
    cryptor = CipherCombiner(a2b_hex(key),a2b_hex(iv))
    ct = cryptor.process(a2b_hex("2c2dd5fd5d842869bb49deaea46748ace63f420d0cf867a0b24fcc454959e29e1e64a9674414d22d920eefad3ca4054f3058ab30703eb352c4ccdc6174957eb9"))
    if enc5 != b2a_hex(ct):
        raise Exception("pycryptopp failed startup self-test. Please run pycryptopp unit test.")

    


    
    



