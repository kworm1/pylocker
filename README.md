# pylocker
Single python file password locker.

Created on Tue Dec 31 15:59:17 2013

@author: Kjetil Wormnes


This script is a standalone password locker encrypted using AES. It came about
in an attempt to:
   1) Make a cross-platform portable password locker, with
   2) Easily inspectable code (so as to guarantee no backdoors are present),
   3) Single file for incorporating both the algorithm and the data,
   4) Can be decrypted both by iteself and by external programs,
   5) Uses strong encryption (*)
   5) Minimises the risk of side channel attacks (**)
    
(*)  The data in this file is encrypted using AES-128 CBC. The AES implementation
  used in this script is based on the code by Bo Zhu, http://about.bozhu.me, the
  only changes are in the interface with it and no credit is taken for its
  implementation, nor any responsability for any flaws it may contain.
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
