#!/usr/bin/env python

import random, re

import unittest

from binascii import a2b_hex, b2a_hex

from pycryptopp.cipher import aes, xsalsa, ciphercombiner

from os.path import join

from base64 import b32encode

NIST_G1_RE = re.compile("\nKEY=([0-9a-f]+)\nIV=([0-9a-f]+)\nPLAINTEXT=([0-9a-f]+)\nCIPHERTEXT=([0-9a-f]+)\n")
TEST_XSALSA_RE = re.compile("\nCOUNT=([0-9]+)\nKEY=([0-9a-f]+)\nIV=([0-9a-f]+)\nPLAINTEXT=([0-9a-f]+)\nCIPHERTEXT=([0-9a-f]+)")

class CipherOfCombinerTest(unittest.TestCase):
    enc0 = "884fecf1f3945eaae55d3892eb79170b"

    def test_enc_zeros(self):
        key = "\x00"*16 + a2b_hex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
	iv = "\x00"*16 + a2b_hex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
	cipher = ciphercombiner.CipherCombiner(key, iv).process('\x00'*16)
	self.failUnlessEqual(self.enc0, b2a_hex(cipher))

    def test_CipherOfCombiner(self):
        curfile1 = open( '../testvectors/AESCTRMsg.txt', 'r')
        curfile2 = open( '../testvectors/XSalsaMsg.txt', 'r')
        s1 = curfile1.read()
        s2 = curfile2.read()

#       i = 1
        for mo1 in NIST_G1_RE.finditer(s1):
            for mo2 in TEST_XSALSA_RE.finditer(s2):
#		print i, "  "
#		i += 1
                key1 = a2b_hex(mo1.group(1))
                iv1 = a2b_hex(mo1.group(2))
                plaintext1 = a2b_hex(mo1.group(3))
                ciphertext1 = a2b_hex(mo1.group(4))
                computedciphertext1 = aes.AES(key1, iv1).process(plaintext1)

                key2 = a2b_hex(mo2.group(2))
                iv2 = a2b_hex(mo2.group(3))
                plaintext2 = a2b_hex(mo2.group(4))
                ciphertext2 = a2b_hex(mo2.group(5))
                computedciphertext2 = xsalsa.XSalsa(key2, iv2).process(plaintext2)

                key = key1 + key2
                iv = iv1 + iv2
                text1len = len(plaintext1)
                text2len = len(plaintext2)
                textlen = text1len if text1len <= text2len else text2len
                plaintext = "".join(chr(ord(plaintext1[i])^ord(plaintext2[i])) for i in xrange(textlen))
    #           computedciphertext = "".join(chr(ord(computedciphertext1[i])^ord(computedciphertext2[i])) for i in xrange(textlen))
                computedciphertext = ciphercombiner.CipherCombiner(key, iv).process(plaintext)
                ciphertext = "".join(chr(ord(ciphertext1[i])^ord(ciphertext2[i])) for i in xrange(textlen))

                self.failUnlessEqual(ciphertext, computedciphertext, "ciphertext: %s, computedciphertext: %s, key: %s, plaintext: %s" % (b2a_hex(ciphertext), b2a_hex(computedciphertext), b2a_hex(key), b2a_hex(plaintext)))


if __name__ == "__main__":
	unittest.main()
