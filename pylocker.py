# -*- coding: utf-8 -*-
#qpy:console
#
"""
Created on Tue Dec 31 15:59:17 2013

@author: Kjetil Wormnes

The AES implementation used in this script is based on the code by Bo Zhu, 
http://about.bozhu.me, the only changes are in the interface with it and 
no credit is taken for its implementation, nor any responsability for any flaws
it may contain.

This script is a standalone password locker encrypted using AES. It came about
in an attempt to:
   1) Make a cross-platform portable password locker, with
   2) Easily inspectable code (so as to guarantee no backdoors are present),
   3) Single file for incorporating both the algorithm and the data,
   4) Can be decrypted both by iteself and by external programs,
   5) Uses strong encryption (*)
   5) Minimises the risk of side channel attacks (**)
   
(*)  The data in this file is encrypted using AES-128 CBC. 
(**) I do not claim to be a cryptography expert, but I wanted to eliminate, or
  at least minimise, the possibility for anyone to insert modifications into
  this file with the purpose of introducing a weakness in the encryption. I 
  therefore wanted it to be impossible to decrypt the data if even a single bit
  was changed in this file. 
  Additionlly I wanted each block to be encryptable/decryptable separately so
  as not to have to keep more secret data in cleartext in memory than absolutely
  necessary.
  
Descriptionof encryption/decryption scheme:
Data is stored in this file between the BEGIN ENCRYPTED BLOCK and END
DECRYPTED BLOCK markers. 
Each block has a number (in plaintext)
1. Block 0 contains a random string, encrypted.
2. A SHA2 hash of this string prepended to the text in this file is xor'ed with
   the SHA2 hash of the user password in order to obtain the key used to decrypt
   all the subsequent blocks.
3. Block 1 onwards contain the secret data.
4. The data in each code is encoded uing base64, and the first 128 bits are the IV,
which is a random number - different for each block.

The idea behind 1. and 2. is that it should be impossible to decrypt this file
if slight changes have been made to it. It will never be possible to completely
eliminate the possibility of someone tampering with this file, but this scheme
should be good enough since very substantial changes to the file need to be
made in order for the file to still be able to decrypt (i.e. a full copy of
the original file must be available to hash), and such changes should be 
easily detectable to anyone inspecting this code.

This file is Copyright (C) 2013 Kjetil Wormnes:

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.



TODO LIST:
  * Check input for only valid characters
  * Fix the way multi-line passwords are cropped

"""


class DefConfig:
    """
       Class with a set of default configuration defines for this file.
       It may be used by several of the classes.
    """
    
    #
    # Time before closing script from timeout
    # TIMEOUT = None disables timeout
    #
    TIMEOUT = 60.0
    
    #
    # Field widths in the display 
    #
    FIELDW_TOTAL = 78   # width of display (characters)
    FIELDW_ID    = 2    # width of ID field
    FIELDW_DESC  = 30   # width of description field
    FIELDW_UNAME = 25   # width of username field
    FIELDW_PASSW = 15   # width of password field 
    FIELDW_SPACE = 2    # space between fields


#
# Modules to import - should all be part of any standard Python distribution
#
import base64
import random
import hashlib
import os
import getpass
import time
import sys
import threading

random.seed()




    
    



#
# Function to convert a 128 bit integer to an 4x4 array of 8 bit integers
# ... it is not really used in this code except in a few locations in which
# a simple integer->single array list would be better. so a TODO is to
# remove it.
#
def num2matrix(text):
    matrix = []
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i // 4].append(byte)
    return matrix    


#
# Converts list of 8 bit integers to a single 128 bit integer
#
def list2num(x):
    y = 0
    for i in range(len(x)):
        y |= (x[i] << (120 - 8 * i))
    return y      

class AES128:
    """
        The code in this class has ben taken from Bo Zhu's impementation,
        and has not been commented any further than in that implementation.
        
        There are virtually no moifications except to implement it all in a 
        single class in which the input is he password, and two functions are
        implemented:

           __init__
               input: key (128 bit integer) [TODO: change to array ?]
           encrypt
               input:  single plaintext block (16x(8 bit int) array)
               output: single 128-bit ciphertext block (16x(8 bit int) array)
           decrypt
               input:  single ciphertext block (16x(8 bit int) array)
               output: single 128-bit plaintext block (16x(8 bit int) array)
           
    """
    
    #testvectors: plain text, key, iv, ciphertext
    #This is a useful page for generating more: http://people.eku.edu/styere/Encrypt/JS-AES-Chain.html
    #format: plaintext, password, IV, ciphertext as a list of 128bit blocks
    TESTVECT=[\
               ["Single block msg", 0x06a9214036b8a15b512e03d534120006, 0x3dafba429d9eb430b422da802c9fac41, [0xe353779c1079aeb82708942dbe77181a]],\
               ["This is a 48-byte message (exactly 3 AES blocks)", 0x6c3ea0477630ce21a2ce334aa746c2cd, 0xc782dc4c098c66cbd9cd27d825682c81, [0xd0a02b3836451753d493665d33f0e886,0x2dea54cdb293abc7506939276772f8d5,0x021c19216bad525c8579695d83ba2684]],\
               ["This is a test for how this stuf", 0x0f1571c947d9e8590cb7add6af7f6798, 0xd1671e68ea1f0f231918309301d36a49, [0x26eab9dffd13f10f166b7c5ead6d9be6,0x9eebe978b7babcd8c1fd03709e8419c5]]\
             ]    
    Sbox = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )
    
    InvSbox = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    )
    
    Rcon = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )        

    def add_round_key(self, s, k):
        for i in range(4):
            for j in range(4):
                s[i][j] ^= k[i][j]

    def sub_bytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = self.Sbox[s[i][j]]
    
    
    def inv_sub_bytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = self.InvSbox[s[i][j]]
    
    
    def shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]
    
    
    def inv_shift_rows(self,s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]
        
    # learnt from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
    def xtime(self, a):
        return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

    def mix_single_column(self, a):
        # please see Sec 4.1.2 in The Design of Rijndael
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ self.xtime(a[0] ^ a[1])
        a[1] ^= t ^ self.xtime(a[1] ^ a[2])
        a[2] ^= t ^ self.xtime(a[2] ^ a[3])
        a[3] ^= t ^ self.xtime(a[3] ^ u)
    
    
    def mix_columns(self, s):
        for i in range(4):
            self.mix_single_column(s[i])
    
    
    def inv_mix_columns(self, s):
        # see Sec 4.1.3 in The Design of Rijndael
        for i in range(4):
            u = self.xtime(self.xtime(s[i][0] ^ s[i][2]))
            v = self.xtime(self.xtime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v
    
        self.mix_columns(s)
    
    
    def round_encrypt(self, state_matrix, key_matrix):
        self.sub_bytes(state_matrix)
        self.shift_rows(state_matrix)
        self.mix_columns(state_matrix)
        self.add_round_key(state_matrix, key_matrix)
    
    
    def round_decrypt(self, state_matrix, key_matrix):
        self.add_round_key(state_matrix, key_matrix)
        self.inv_mix_columns(state_matrix)
        self.inv_shift_rows(state_matrix)
        self.inv_sub_bytes(state_matrix)
    

    def change_key(self, master_key0):
        #<-- todo: should master_key also be a 16x(8 bit integer) array ?
        # for consistency with encrypt and decrypt functions(?)
        if type(master_key0) == str:
            master_key = [ord(k) for k in master_key0]
            while (len(master_key) < 16):
                master_key.append(0)
            self.round_keys = [master_key[0:4],master_key[4:8],master_key[8:12],master_key[12:16]]
        else:
            master_key = master_key0
            self.round_keys = num2matrix(master_key)

        for i in range(4, 4 * 11):
            self.round_keys.append([])
            if i % 4 == 0:
                byte = self.round_keys[i - 4][0]        \
                     ^ self.Sbox[self.round_keys[i - 1][1]]  \
                     ^ self.Rcon[i // 4]
                self.round_keys[i].append(byte)

                for j in range(1, 4):
                    byte = self.round_keys[i - 4][j]    \
                         ^ self.Sbox[self.round_keys[i - 1][(j + 1) % 4]]
                    self.round_keys[i].append(byte)
            else:
                for j in range(4):
                    byte = self.round_keys[i - 4][j]    \
                         ^ self.round_keys[i - 1][j]
                    self.round_keys[i].append(byte)
 
    #
    # encrypt message block (should be 16x8 bit integer array)
    #
    def encrypt(self, plaintext):
        plain_state = [plaintext[0:4], plaintext[4:8], plaintext[8:12], plaintext[12:16]]

        self.add_round_key(plain_state, self.round_keys[:4])

        for i in range(1, 10):
            self.round_encrypt(plain_state, self.round_keys[4 * i : 4 * (i + 1)])

        self.sub_bytes(plain_state)
        self.shift_rows(plain_state)
        self.add_round_key(plain_state, self.round_keys[40:])

        return plain_state[0] + plain_state[1] + plain_state[2] + plain_state[3]
        
    #
    # decrypt message block (should be 16x8-bit integer array)
    #
    def decrypt(self, ciphertext):
        cipher_state = [ciphertext[0:4], ciphertext[4:8], ciphertext[8:12], ciphertext[12:16]]
        self.add_round_key(cipher_state, self.round_keys[40:])
        self.inv_shift_rows(cipher_state)
        self.inv_sub_bytes(cipher_state)

        for i in range(9, 0, -1):
            self.round_decrypt(cipher_state, self.round_keys[4 * i : 4 * (i + 1)])

        self.add_round_key(cipher_state, self.round_keys[:4])

        return cipher_state[0] + cipher_state[1] + cipher_state[2] + cipher_state[3]


                   
    def __init__(self, master_key):
        self.change_key(master_key)


class CBC:
    """
        This class implements Cipher-Block-Chaining in order to encrypt or
        decrypt text of arbitrary length. It's main input is any 128 bit block
        cipher 
    """
    def __init__(self, ciph):
        self.cipher = ciph
        
    
    #
    # Encrypt nearly arbitrary length arrays of 8 bit integers (ie bytes).
    #
    # The functiondoes not do any padding so the messages must be arrays of legth
    # a multiple of 16.
    #
    # The initialisation vector (IV) can either be supplied or not. If not,
    # a random IV will be generated.
    #
    # The returned ciphertext will have as its first 128 bit the IV.
    #
    def encrypt(self, plaintext, iv=None):
        ciphertext = []
        if iv==None:
            IV = [random.getrandbits(8) for i in range(0,16)]
        else:
            if type(iv) == int:
                iv = num2matrix(iv)
                iv = iv[0] + iv[1] + iv[2] + iv[3]
            IV = iv

        ciphertext = IV
       
       
        for i in range(0, len(plaintext))[0::16]:
            nb = [plaintext[k] ^ ciphertext[k] for k in range(i,i+16)]
            ciphertext += self.cipher.encrypt(nb)
        
        return ciphertext
        
    #
    # Decrypt nearly arbitrary length arrays of 8 bit integers (ie bytes)
    #
    # The functiondoes not do any padding so the messages must be arrays of legth
    # a multiple of 16.
    #
    # The initialisation vector (IV) can either be supplied or not, If not,
    # it is assumed that the firt 128 bits of the ciphertext will be the IV.
    #
    def decrypt(self, ciphertext0, iv=None):

        ciphertext = []
        if iv==None:
            IV = ciphertext0[0:16]
            ciphertext = ciphertext0[16::]
        else:
            if type(iv) == int:
                iv = num2matrix(iv)
                iv = iv[0] + iv[1] + iv[2] + iv[3]
            
            IV = iv
            ciphertext = ciphertext0

        nb = self.cipher.decrypt(ciphertext[0:16])
        plaintext = [nb[i] ^ IV[i] for i in range(0,16)]
        for i in range(16, len(ciphertext))[0::16]:
            nb = self.cipher.decrypt(ciphertext[i:i+16])
            plaintext += [nb[k] ^ ciphertext[i-16+k] for k in range(0,16)]
        
        return plaintext    
    #
    # Encrypt arbitrary length strings
    #
    # It will convert to unicode (if not already) and then encrypt using
    # the encrypt function above. The output will be base64 encoded.
    #
    # The initialisation vector (IV) can either be supplied or not. If not,
    # a random IV will be generated.
    #
    #
    def strencrypt(self, plaintext, iv=None):

        #
        # If not alread, convert from utf-8
        #
        #plaintext = plaintext.encode('utf-8')
        
        
        #
        # Pad text to make a multiiple of 16
        #    
        if len(plaintext) % 16 != 0:
            npad = (16-len(plaintext)%16)
        else:
            npad = 0
        plaintext += npad*chr(0)
        
        #
        # Create numerical array
        #
        dec = [ord(c) for c in plaintext]
        
        #
        # Encrypt
        #
        enc = bytes(self.encrypt(dec, iv))
        
        #
        # Encode binary output in base64
        #
        #ciphertxt = base64.b64encode(''.join([chr(x) for x in enc]).encode())
        ciphertxt = base64.b64encode(enc)

        return ciphertxt    
   
   
    #
    # Decrypt arbitrary length strings. 
    #
    # It will assume base64 encoding on the input, and return a unicode string.
    #
    # The initialisation vector (IV) can either be supplied or not, If not,
    # it is assumed that the first 128 bits of the ciphertext will be the IV.
    #
    def strdecrypt(self, ciphertext, iv=None):
        
        #
        # Recover byte array, and convert to ascii values
        #
        enc0 = base64.b64decode(ciphertext)
        enc  = [int(i) for i in enc0]

        #
        # Decrypt
        #
        dec = self.decrypt(enc)
        
        #
        # Create byte array
        #
        plaintext = ''.join([chr(x) for x in dec])
        
        #
        # And remove padding
        #
        if (plaintext.find(chr(0)) >= 0):
            plaintext = plaintext[0:plaintext.find(chr(0))]
        
        #
        # Convert to utf-8
        #
        return plaintext
        #return plaintext.decode('utf-8', errors='ignore')        
        





        
        
class App():
    """
        This class is the application itself. It does not provide a user
        interface, but rather the layer between the encryption engine and
        the user interface.
        
    """

    #
    # Character to use as record separator
    #
    separator = '\30'


    def __init__(self, pwd):
        """
            Initialisation routine
        """

        pwd1 = self.hash_pwd(pwd)

        #
        # Create raw decryptio/encryption object
        #
        self.raw_cipher = CBC(AES128(pwd1))
               
        #
        # Load data
        #
        self.data = self.load_data()

        #
        # Create cipher. 
        #
        self.cipher = CBC(AES128(self.compute_key(pwd1)))
        
        #
        # sort indices
        #
        self.sort_idx = list(range(1, len(self.data)))

        #
        # applied filters (for reference only)
        #
        self.filters = []

    def get_vals(self, itemno):
        assert(itemno > 0)

        if itemno > len(self.sort_idx):
            return False

        itemno2 = self.sort_idx[itemno - 1]
        if itemno2 in list(self.data.keys()):
            vals = self.cipher.strdecrypt(self.data[itemno2])
            vals = vals.split(self.separator)
            return vals
        else:
            return False

    def set_vals(self, itemno, desc, uname, paswd):
        assert (itemno > 0 and itemno <= len(self.sort_idx))
        itemno2 = self.sort_idx[itemno - 1]
        if itemno2 in list(self.data.keys()):
            self.data[itemno2] = self.cipher.strencrypt(desc + self.separator + uname + self.separator + paswd)
            self.save_data()
            return True
        else:
            return False
    
    def new_vals(self, desc, uname, paswd):
        self.sort_idx.append(len(self.data))
        self.data[len(self.data)] = self.cipher.strencrypt(desc + self.separator + uname + self.separator + paswd)
        self.save_data()


    def sort(self, col):
        
        assert (col in ['desc', 'uname', 'pwd', 'orig'])

        #
        # clear all filters
        #
        self.filters = []


        sort_vals = []        
   
        if col == 'desc':
            cN = 0
        elif col == 'uname':
            cN = 1
        elif col == 'pwd':
            cN = 2
        elif col == 'orig':
            self.sort_idx = list(range(1,len(self.data)))
            return
        else:
            return     
        
        #
        # Need to unsort first, or it won't work        
        #
        self.sort('orig')
        
        for i in range(1, len(self.data)):
            vals = self.get_vals(i)
            sort_vals.append(vals[cN].lower())

        self.sort_idx = sorted(list(range(1, len(sort_vals)+1)), key=lambda k: sort_vals[k - 1])
        
       
    def search_items(self, searchstr, fuzzy=False):
        """
        Search all items (description +  return matching indices
        """
        searchstr = searchstr.strip().lower()

        all_desc=[]
        all_uname=[]
        # self.sort('orig')
        for i in range(len(self.sort_idx)):
            val = self.get_vals(i+1)
            all_desc.append(val[0].lower())
            all_uname.append(val[1].lower())


        match_desc = [searchstr in s.strip().lower() for s in all_desc]
        match_uname = [searchstr in s.strip().lower() for s in all_uname]
        matches = [a | b for a,b in zip(match_desc, match_uname)]

        sort_idx = [v for i,v in enumerate(self.sort_idx) if matches[i]]

        if len(sort_idx) > 0:
            self.sort_idx = sort_idx
            self.filters += [searchstr]
        else:
            return False


        return True


   
            
            
        

    def hashme(self, init=None, fname=None):
        #
        # to test, use another file
        #
        if fname != None:
            me = os.path.dirname(__file__) + '/test.txt'
        else:
            me = __file__
            
        m = hashlib.sha256()
        m.update(init.encode())
        
        #
        # For now ignore encrypted blockss
        # Todo: work out a way to also include encrypted blocsk
        #
        encblock = False
        
        with open(me, 'rb') as f:
            for line in f:
                if line.strip().find(b'BEGIN ENCRYPTED BLOCKS') == 0:
                    encblock = True
                elif line.strip().find(b'BEGIN ENCRYPTED BLOCKS') == 0:
                    encblock = False
                
                if not encblock:
                    m.update(line)
                
             
        return m.hexdigest()


    def change_password(self, pwd):
        """
            Function to change the password. Note this function decrypts
            everything before re-encrypting, thus for a short moment keeping
            everything in memory in clear text
        """ 
        relock = False
        if self.locked:
            relock = True
            self.unlock_file()

        #
        # Unsort, otherwise original sort order is lost
        #
        self.sort('orig')

        vals = []
        for i in range(1, len(self.data)):
            vals.append(self.get_vals(i))
            
        pwd1 = self.hash_pwd(pwd)
        self.raw_cipher = CBC(AES128(pwd1))
        self.cipher = CBC(AES128(self.compute_key(pwd1)))
        self.data = {0:self.data[0]}

        for v in vals:
            self.new_vals(v[0],v[1],v[2])

        if relock:
            self.lock_file(pwd)

    def lock_file(self, pwd):
        """
            Function to lock the file. When the file is locked, decryption
            depends not just on the password but also on the content of the
            non-data part of the file (i.e. this script). When it is locked,
            any change to this script will make it impossible to decrypt
            the data
        """

        pwd1 = self.hash_pwd(pwd)

        #
        # Verify password by checking that the new cipher is thesame as raw_cipher
        #
        testIV = random.getrandbits(128)
        testcipher = CBC(AES128(pwd1))
        if (self.raw_cipher.strencrypt('testing1234', iv=testIV) != testcipher.strencrypt('testing1234', iv=testIV)):
            #
            # revert
            #
            self.locked = False
            self.data[0] = b'UNLOCKED'
            
            return False
        else:
            #
            # Create cipher. 
            #
            self.cipher = CBC(AES128(self.compute_key(pwd1, newlock=True)))
            
            #                    
            # reencrypt everything with locked cipher
            #
            for k,v in list(self.data.items()):
                if (k == 0):
                    continue
                
                self.data[k] = self.cipher.strencrypt(self.raw_cipher.strdecrypt(v))                    
            
            #
            # Then save
            #
            self.save_data(fname='test.txt')
            
            return True
        
    def unlock_file(self):
        """
            Function to unlock the file. When the file is unlocked, Decryption
            depends only on the password. This script can be changed.
        """
        self.data[0] = b'UNLOCKED'
            
        #                    
        # reencrypt everything with raw cipher
        #
        for k,v in list(self.data.items()):
            if (k == 0):
                continue
            
            self.data[k] = self.raw_cipher.strencrypt(self.cipher.strdecrypt(v))
        
        #
        # Then get rid of locked cipher and sve
        #
        self.cipher = self.raw_cipher
        self.save_data()
        
        self.locked = False       

    def hash_pwd(self, pwd):
        """
            Function to convert any password to a 128 bit number
            usable for the cipher. It does so by using sha2 the 256 bit version
            and keeping only every second nibble.
            
        """
        return int((hashlib.sha256(pwd)).hexdigest()[0::2], 16)
        
        
    def verify_ciphers(self):
        """
            Method to check whether the password entered is correct
        """

        printable='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c' + self.separator
        
        ##
        # First check block 0 - if UNLOCKED we won't try to check for
        # file changes
        #
        if not self.data[0] == b'UNLOCKED':
            c = self.raw_cipher.strdecrypt(self.data[0]).split(self.separator)
            
            if len(c) != 2:
                return 2
                
            if self.hashme(c[0]) != c[1]:
                return 1
            
        #
        # Check for strange characters
        #
        n = 0
        if len(self.data) > 1:
            testdata = self.cipher.strdecrypt(self.data[1])
            for d in testdata:
                if d not in printable:
                    n += 1
        else:
            return 0

        #
        # Assume that if there  more than 10% of characters are unprintable, we
        # have incorrect decryption
        # 
        if n >= 0.1*len(testdata) :
            return 2
            
        return 0    

    def compute_key(self, pwd, newlock = False):
        #
        # Compute hash and compute the encryption key from it
        #
        # Note: At the moment, the random string used to generate the
        #       hash seed will never change. Consider having separate
        #       Encryption/Decryption ciphers and change it every time???
        # 
        self.locked = True
        if len(self.data) != 0 and not newlock:
            if self.data[0] == b'UNLOCKED':
                self.locked = False
            else:
                rand_str = self.raw_cipher.strdecrypt(self.data[0]).split(self.separator)[0]
        else:
            rand_str = ''.join([chr(random.randint(32,126)) for a in range(0,random.randint(32,128))]) 
            self.data[0] = CBC(AES128(pwd)).strencrypt(rand_str+ self.separator + self.hashme(rand_str)) 
            
        if self.locked:            
            hsh = self.hashme(rand_str)[0::2]
            key = int(hsh, 16) ^ pwd
        else:
            key = pwd
        
        return key

    def delete_item(self, item_no):
        """
            Functionto delete an item from the database
        """
        
        assert(item_no > 0 and item_no <= len(self.sort_idx))

        item_no2 = self.sort_idx[item_no - 1]
        
        if item_no2 in list(self.data.keys()):
            for k,v in list(self.data.items()):
                if k > item_no2:
                    self.data[k-1] = v
                
            del(self.data[k])
            self.save_data()
            
            del(self.sort_idx[item_no - 1])
            
            for i in range(len(self.sort_idx)):
                if self.sort_idx[i] > item_no2:
                    self.sort_idx[i] -= 1

            return True
        else:
            return False

    #
    # Load data blocks from file. The file loaded from is this very python
    # file. The datablocks are stored anywhere in the file in a comment string
    # between the BEGIN ENCRYPTED BLOCKS and END ENCRYPTED BLOCKS markers.
    #
    def load_data(self, fname=None):
        me = __file__
        data = dict()
        i = 0;
    
        #
        # to test, use another file
        #
        if fname != None:
            me = os.path.dirname(__file__) + '/test.txt'
        else:
            me = __file__
    
        
        #
        # Read file
        #
        with open(me, 'rb') as f:
            curblock = 0;
            
            for line in f:
                
    
                #
                # Look for start of data field
                #
                if line.strip().find(b'BEGIN ENCRYPTED BLOCKS') == 0:
                    curblock += 1
                    continue
    
                if curblock == 0:
                    continue
                
                if line.strip().find(b'END ENCRYPTED BLOCKS') == 0:
                    break
                
    
                
                if curblock > 0:
                    #
                    # Start new datablock if numerical identifier is detected
                    #
                    if (line[0:10]).strip()!=b'':
                        i = int(line[0:10])
                        data[i] = b''
                    
                    #
                    # Read data block
                    #
                    data[i] += (line[10::]).strip()
                
    
        return data
    
    #
    # Save data blocks to file. The file saved to is this very python
    # file. The datablocks are stored anywhere in the file in a comment string
    # between the BEGIN ENCRYPTED BLOCKS and END ENCRYPTED BLOCKS markers.
    #
    def save_data(self, idata=None, fname=None):
        #
        # Just a define to set the length of the file to write to.
        #
        LINLEN = 65
        
        if idata == None:
            data = self.data
        
        #
        # to test, use another file (DOES NOT WORK)
        #
        # if fname != None:
        #     me = os.path.dirname(__file__) + '/test.txt'
        # else:
        #     me = __file__
        me = __file__

        startblock = ''
        endblock = ''
        curblock = 0;
        
        #
        # Open file and find location to write to
        #
        with open(me, 'r') as f:
            for line in f:
                
                #
                # Look for start of data field
                #
                if line.strip().find('BEGIN ENCRYPTED BLOCKS') == 0:
                    curblock += 1
                    continue        
                
                if line.strip().find('END ENCRYPTED BLOCKS') == 0:
                    curblock += 1
                    
                if curblock == 0:
                    startblock += line
                elif curblock == 2:
                    endblock += line
                
        
        with open(me, 'w') as f:
            f.write(startblock)
            f.write('    BEGIN ENCRYPTED BLOCKS\n')
            
            for i in range(0, len(data)):

                d  = data[i][0:LINLEN].decode()
                for k in range(LINLEN,len(data[i]))[0::LINLEN]:
                    d += '\n'+(' '*11) + data[i][k:k+LINLEN].decode()

                f.write(' '*4 + '%06d '%(i) + d + '\n')
            
            f.write(endblock)



class UI_Txt:
    """
        This class is the user interface itself. It provides a simple
        text based UI that allows the user to enter/read data to/from all
        the blocks.
    """
    
    UNPRINTABLE = '#'
    PRINTABLE   = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '


    def reset_timeout(self):
        """
           Resets watchdog timer. Needs to be caled within the predetermined
           timeout period or the timeout thred will kill the process.
        """
        self.t0 = time.time()

    def timeout_thread(self):
        """
            Supervising (Watchdog) thread. Will kill the process after
            a predetermined period of inactivity.
        """        
        while(1):
            time.sleep(0.5)
            if (time.time() - self.t0) > self.timeout:
                self.clear()
                print('TIMEOUT ... exiting.')
                time.sleep(2)
                os._exit(0)
    
    
    def __init__(
        self, 
        timeout=None, 
        fw_total = 80, 
        fw_id=4, 
        fw_desc=20, 
        fw_uname=20,
        fw_passw=20,
        fw_space=1):


        #
        # Start timeut thread
        # 
        if timeout != None:
            self.timeout = timeout
            self.t = threading.Thread(target=self.timeout_thread)
            self.t.daemon = True
            self.reset_timeout()
            self.t.start()

        #
        # Field widths
        #
        self.fw_total = fw_total
        self.fw_id = fw_id
        self.fw_desc = fw_desc
        self.fw_uname = fw_uname
        self.fw_passw = fw_passw
        self.fw_space = fw_space

        #
        # Variable to hold error messages to display
        #
        self.errormsg = ''

        #
        # Get the password from user. The 128 bit password is computed
        # by taking the sha256 hash, and discarding every second nibble
        #
        print("Password locker version 0.1")
        pwd = getpass.getpass("Enter master password:").encode()



        #
        # Create appliction
        #
        self.app = App(pwd)
        
        #
        # Check passwords
        #
        verify = self.app.verify_ciphers()
        if verify == 1:
            print('It looks like the file has changed. This could mean that someone is attemping a side-channel attack')
        elif verify == 2:
            print('It looks like the password may be incorrect')

        if verify > 0:
            x = input("Ignore and try to decrypt anyway ? y/[n]")
            if x != 'y':
                sys.exit(1)
        
 
       
        #
        # Wait for input
        #
        self.input_loop()


    def clear(self):
        """
           Function to clear console in  portable way
        """        
        os.system('cls' if os.name == 'nt' else 'printf "\033c"')
    

    def display_data(self, page=1, selected=-1):
        """
            Method to print data to screen
        """
        #
        # Print header
        #
        self.clear()
        if self.errormsg != '':
            print('** {} **'.format(self.errormsg))

        if len(self.app.filters) != 0:
            print('Filtering by "' + '" AND "'.join(self.app.filters) + '"')
            print('To clear filters: re-sort')
        print(( ('%'+str(self.fw_id)+'s %-'+str(self.fw_desc + self.fw_space)+'s%-'+str(self.fw_uname + self.fw_space)+'s%-'+str(self.fw_passw)+'s')%('ID', 'Description', 'Username', 'Password')))

        lockstr = ' - UNLOCKED' if not self.app.locked else ' - locked'
        
        print(('-'*self.fw_total))

        pagestr = ' page %d / %d'%(page, self.pages) + lockstr
        id_no = 0
        for k in range(1, len(self.app.sort_idx)+1): #,v in self.app.data.items():
            #
            # Description, Username and Password should be three tab separated
            # fields. Decrypt, split them, and pad with empty fields if anythin is missing
            #

            #
            # k = 0 is the special case of the hash, ignore it.
            #
            if k == 0:
                continue

            #
            # Skip all items not in the current page
            #
            if ((k - 1)//10 + 1 ) != page:
                continue

            vals = self.app.get_vals(k)

            while (len(vals) < 3):
                vals.append('')

            #
            # Ensure that password is only displayed if asked to be revealed
            # otherwise display stars
            #
            if k == selected:
                sel = '*'
            else:
                sel = ' '
                vals[2] = '*'*8


            #
            # Identify non-printable entries, and change them to a special
            # symbol
            #
            for i in range(0,3):
                vals[i] = ''.join([vals[i][k] if vals[i][k] in self.PRINTABLE else self.UNPRINTABLE for k in range(0, len(vals[i])) ])


            v0 = vals[0][0:self.fw_desc]
            v1 = vals[1][0:self.fw_uname]
            v2 = vals[2][0:self.fw_passw]

            print((('%1s%'+str(self.fw_id)+'s %-'+str(self.fw_desc+ self.fw_space)+'s%-'+str(self.fw_uname+ self.fw_space)+'s%-'+str(self.fw_passw)+'s')%(sel, id_no, v0, v1, v2)))

            #
            # Split long entries over multiple lines
            #
            i_d = self.fw_desc
            i_u = self.fw_uname
            i_p = self.fw_passw
            while (True):
                v0 = vals[0][i_d:i_d+self.fw_desc]
                v1 = vals[1][i_u:i_u+self.fw_uname]
                v2 = vals[2][i_p:i_p+self.fw_passw]
                if (v0  == '' and v1 == '' and v2 == ''):
                    break

                print((('      %-'+str(self.fw_desc)+'s%-'+str(self.fw_uname)+'s%-'+str(self.fw_passw)+'s')%(v0,v1,v2)))
                i_d += self.fw_desc
                i_u += self.fw_uname
                i_p += self.fw_passw

            id_no += 1

        if page == self.pages:
            print(('%3d'%(id_no)))

        #
        # Print footer
        #
        print(('-'*(self.fw_total - len(pagestr))+pagestr))
        print('n: next, p: prev, e: end, b:beginning, l: (un)lock, c: change password')
        print('<N><C>: Select item <N> and <C> where d: delete, e: edit, r: reveal')
        print('s<C>: Sort by column <C> where d: descr, u:uname, p:passwd, o:original')
        print('f<S>: Find (search) for a search term <S>.')
            
        
    def input_loop(self):
        
        pageno = 1
        while (True):
            self.pages = (len(self.app.sort_idx) - 1)//10 + 1
            assert(self.pages > 0)
            self.display_data(pageno)
            self.errormsg = ''
            self.reset_timeout()
            
            cmd = input('> ')
            
            if len(cmd) == 0:
                continue

            if cmd[0] >= '0' and cmd[0] <= '9':
                if len(cmd) == 2:

                    item = (int(cmd[0])) + (pageno-1)*10 + 1

                    if item <= (len(self.app.data)):
                        cmd2 = cmd[1]

                        #
                        # Edit an item
                        #
                        if cmd2 == 'e':
                            self.edit_item(item)
                            continue

                        #
                        # Delete an item
                        #
                        #
                        if cmd2 == 'd':
                            verify = input('\rAre you sure you want to delete item %s? yes/[no]'%(cmd[0]))
                            if verify == 'yes':
                                self.app.delete_item(item)
                            continue

                        #
                        # Reveal password for an item
                        #
                        if cmd2 == 'r':
                            self.display_data(pageno, item)
                            time.sleep(1)
                            continue

            if cmd[0] == 'f':
                if not self.app.search_items(cmd[1:]):
                    self.errormsg = "no results"
                else:
                    pageno=1

                continue

            if cmd[0] == 'l':
                if self.app.locked == True:
                    verify = input('Unlock file? yes/[no]')
                    if verify == 'yes':
                        self.app.unlock_file()
                else:
                    pwd = getpass.getpass("Re-enter password to lock:").encode()
                    
                    if not(self.app.lock_file(pwd)):
                        print('Incorrect password')
                        time.sleep(1)
                      
                    #
                    # Paranoia
                    #
                    pwd = 'X'*len(pwd)

                continue

            if cmd[0] == 'n':
                if pageno < self.pages:
                    pageno += 1
                continue

            if cmd[0] == 'e':
                pageno = self.pages
                continue

            if cmd[0] == 'b':
                pageno = 1
                continue

            if cmd[0] == 'p':
                if pageno > 1:
                    pageno -= 1
                continue
            
            if cmd[0] == 'q':
                self.clear()
                break
            
            if cmd[0] == 'c':
                pwd0 = getpass.getpass("Enter new password:")
                pwd = getpass.getpass("Re-enter new password:")
                if pwd == pwd0:
                    self.app.change_password(pwd)
                pwd = 'X' *len(pwd)
                pwd0 = 'X' * len(pwd0)
                continue
                
            if cmd[0] == 's':
                if len(cmd) == 2:
                    if cmd[1] == 'd':
                        self.app.sort('desc')
                        continue

                    if cmd[1] == 'u':
                        self.app.sort('uname')
                        continue

                    if cmd[1] == 'p':
                        self.app.sort('pwd')
                        continue

                    if cmd[1] == 'o':
                        self.app.sort('orig')
                        continue

            #
            # This code should only be reachable in case of an incorrect command
            #
            self.errormsg = 'Can not understand command "{}"'.format(cmd)
                

    # def search_items(self, searchstr):
    #     """
    #         Search through items by searching all desctiption and username
    #         fields and only displaying resulting items
    #     """
    #     if not self.app.search_items(searchstr):
    #         self.errormsg = 'no results'

    def edit_item(self, itemno):
        """
            Edit or create a new item
        """
        #tip: can move cursor to 6,3   print('\033[6;3H')
    
        newval = False
        vals = self.app.get_vals(itemno)
        if vals == False:
            vals = ['NEW', 'NEW', 'NEW']
            newval = True
            
            
        desc =  input('Description [%20s]: '%(vals[0]))
        uname = input('User name  [%20s]: '%(vals[1]))
        paswd = input('Password   [%20s]: '%(vals[2]))
        
        if len(desc) == 0 :
            desc = vals[0]
        if len(uname) == 0:
            uname = vals[1]
        if len(paswd) == 0:
            paswd = vals[2]
        
        if newval:
            self.app.new_vals(desc,uname,paswd)
        else:
            assert self.app.set_vals(itemno, desc,uname,paswd)
            
        #self.pages = len(self.app.data)/10 + 1





if __name__ == '__main__':

    
    #
    # Start User Interface application
    # 
    app = UI_Txt(
        #timeout     = DefConfig.TIMEOUT,
        fw_total    = DefConfig.FIELDW_TOTAL,
        fw_id       = DefConfig.FIELDW_ID,
        fw_desc     = DefConfig.FIELDW_DESC,
        fw_uname    = DefConfig.FIELDW_UNAME,
        fw_passw    = DefConfig.FIELDW_PASSW,
        fw_space    = DefConfig.FIELDW_SPACE)

"""
    BEGIN ENCRYPTED BLOCKS
    000000 UNLOCKED
    000001 qCSLu70tt8eBcLb37ujj+NluxiLu8dXwOAiLqsw6UmoU5H647S4Egp/PiuxhnRr/
    000002 nRlnNVD8VjNjVDkKbnkdtMKw4WXg3rjnRroZ4/e3iTwykEZt8HMKcM7yG2b789Kbv
           GcLmvlGK6Mr+VV47r3UbQ==
    000003 9vb3UO8OLPELCkiCmLWY1QJOKJpG+EqrY0Yuw63lZviIot0tEF+qvlmcDtF70mXs
    000004 xVoC5NGlW5uxmj+Jco5zKg4a3h7UQXesp7cRa4oYivOkEacclOjzO13nmyJetMvq
    000005 UHHwQ9fCpHb8WQ47kL3IKEeurevNNUYolgEjmSi4RZRW29R51ybM9Lln9X/dj20S6
           tF/B6Ym0jFaKZ/7B4nJLA==
    000006 PhQcxvbGyzWftBGuvxJYxo1vQt2w1pTVfP/zAhGKlOLQrU7/sY1B21p17M/fI4rz
    000007 2QCwirFcsg6XnNsmBhAiUgZaCl0favVLQi1E4kRJOOL2hivD68l66FMwl7BCEJqd
    000008 hIJhL2loXJlJ/ihqHHzTo8yWoBYLltjjWOT88yIu+RhHcN1PzTBI8A9VG73dE88zj
           GDKC7NRhQUbHeUbqzPsswIpJkux0205+XVFrpjhKCU=
    000009 fp0AgZFh+h/7iHG/lk+V7Tbiq/9R2JqipSRJLQ1iIUwqzDDU+xcHJCaHFwwt0ZIbc
           KX46tG7k4sT4Sqcl5Gxuw==
    000010 ggMx2N2CvzwYwuBhY5V7iarQhbpQSm4kEgV6DsJepxgFImXWz2P+9MiiEi6NSU6J6
           jXMwBvSD0I/dqDbX9x7Qk07z5QjcziYqvo2sOAlp08=
    000011 GZfcjKtRKUmxpoLhyBLuzPub9YaxI/YSmrcBQ04mLiwR/gimb4x1Q3nyqsxpVmQq
    000012 HqLVWlzmgHwqBGuQj+aUsqvNdH/4jBrjjbfXlNUsgPbgYaJPD/qwZhQf4wlbRJozK
           gLa123d/8AIdxKW7AcCeg==
    000013 DhGx8LVFQ6Z8BOakqVGQJpoBkRNJQ7uJQtIQlOqUyBWesEYSOqAg7uTtete3eLWt
    000014 vie1T7/i6+y4gE12yrjxlBtiQPB3ZgX2Rv13yRknyWQ4qoYyDG0mEdibopztEZ5ZC
           6n/JORZwT7mEyYldczCpA==
    000015 Wj4KYqAJHvwOYA9SqMdeNVFy/HHwgVnIF+31Lext5pwqLNepd6wFYdLjomWDV1iv
    000016 gTHJ9Jm9yT0cO349gI4RfVPpb4hoh14AJMmJQtPQ/SR6u3vUGIzTg/We/lflOGwl
    000017 s/mPf0lA4Zi38ldOZOE9OHWr+PHEQtRR1aR/SkazQ+OFXIu/HGlBkWNpjZR9rIu3
    000018 2w3HTOGyt25+wgw8Mx8m7aJkXFJK1dTWmJBhu9ZO/5WvEThQCOwkOsD3xk0A9IWe0
           FSBA2oExCDTawnGe1DQbg==
    000019 4LtTBHgRLxthHbS7HSgvYaF6ubSTYxxPvRpE2euGAAbDus7KmWNEYER+1o4bMor/9
           w5OyCSo7KnkpEp1LKIlsw==
    000020 rsfE2ojgXOckou85QHgExgOxUBHWKH1klCn9VxaRGulJ8aoj69TbDcuMU5FlgRnLs
           T5Tbqf097Vlqi4KQ0JTDQ==
    000021 R0ZeDHxjRPuUvg19gYd191HxgdPe2dzMX4NUS4ItMbDe2eBicsfZUT7NUQqi2+YP0
           ZcC5F6+/15Uxraai69kIA==
    000022 aH65Hz4xmMBfxkJlLVTyNd/93W48tI+iIEfbc3xQeBBctQROg4Bxp2hiN6FBtHNbF
           6F1d40PNVpoU5LMBxuuNA==
    000023 hVqFUb0GYXA58Hq42MPptvAF32nDavDbcWgqF8GR0SmJHoisfk1NzQDBw4lUkHT7
    000024 df9U/lJMAkBwQZuwzNK8eIpo9h6kDkCb503+/ggbC7d8wF35hNw4GA//g5kEG9ZfZ
           oz8uQ614XKknexQCIothPaEw/mdGGz68p60GwRq9fA=
    000025 +c0bFv9HIgqKEuAouGobWdOcaAe88KDzV9fdMijXqmMwRfeyk1+Dtn4jGnFBqncaa
           oKtpPzYlTEnVkZZQhoDlg==
    000026 FVAd9edZD+Dcbl35lLCrLf5JiZONWdcWDqu3VsgRYegJ1lQGiv4VjwwOTc655xgkB
           MMNdfQHllepBkmKuwhuJg==
    000027 imrUS8vT6L1bExPBh/RAAqzANWcTilSQ9n3E4QEoeHknCza+Wjg2i0vWw8OID+5C5
           zJ7XQXem39pWDzoQiM2uA==
    000028 cG0pbTU57zosafcalmKnQs/czInRE2QCUiHWTlWwMLf9Z6/QEFWlyJcZraW65Vb50
           qWovJ9K+Bmd71AWOm8WKHGtZfuF25HdiTn/HvnLjok=
    000029 R848EoAqW7aV28q54HdAGZac93H+Wrjo9sgguDZEZKQwAuIHz/mXXmRXptcqPtVMf
           GHeg8Q8JHVBzNr1FYpawrktye0071LfBaqzocnYXW0=
    000030 hlLIXD03O9zTvkxDn1hhHDM8O+VqOqe8xR4XAMECN6q743a1e/mpcUhy1tRex4eUb
           9nwvUS12IGgCyFF8BsNYVquX0phBYN3CGfZjttBE/uRRX7th+Cbcg5DU/MX3/Qy
    000031 A2NZhMKNVcBThm/U6cIyaQVhOdzdB3JPo+mAgAgAPN3ZeBs4XqJ6IHqeTMe2t3nmH
           ggEk6xHRUxsGYBNDCgUW2746haKWbF44ZzneOM66ps=
    000032 1LIPc97PGPTRg3cKQMb7Rf66evQweUmQDd7E2v/y+4ofm+syz3tClKwRiglHKOdT
    END ENCRYPTED BLOCKS
"""