# This program accepts an arbitrary file as input and encrypts it using
# AES in CTR mode. We provide additional security and message authenticity
# by employing the SHA256 hashing function. We first create a new text 
# file with a time stamp inserted to the beginning of the file. This
# aids in preventing replay attacks. We then hash this new copy file
# with SHA256 and output the hash as a digest text file. Ideally, 
# this hash could be accessed in multiple places instead of this 
# transmission scheme. 

# Functions come in pairs of encrypt and decryption, one function
# will generate a file for output, while the other will perform the
# actual encryption/decryption. So each algo used here has 4 functions
# to go with it. 

# Author: Dustin Ray
# TCSS 581
# Spring 2020

import base64
import hashlib
import os
import time
import array
from Crypto import Random
from Crypto.Util import Counter
from Crypto.Cipher import AES
import Crypto
import binascii

from datetime import datetime

# main function defines keys to use for various algorithms.
# contains calls to encryption and decryption functions, and
# provides runtimes in Seconds for each call.

def main():

    key32 = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'

    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    

    # create a copy of existing file, add a time stamp to prevent 
    # anti replay attack
    copy_file = open("MESSAGE.txt", "w")
    copy_file.write("ANTI-REPLAY ATTACK TIME STAMP (H:M:S): " + str(current_time) + "\n" + "\n")
    
    with open("bible.txt", "r") as f:
        copy_file.write(f.read())
    
    copy_file.close()


    #encrypt with AES in CTR mode
    time0 = time.time()
    encrypt_file_AES_CTR("MESSAGE.txt", key32)
    time1 = time.time()
    
    print("Elapsed time to encrypt using AES in CTR mode: " + str(time1 - time0) + " Seconds")

    #Hash message with Sha256, output as digest file
    print("\n" + "Sha256 Hash of encrypted message: " + "\n" + sha256Sum("MESSAGE.AES_ENC_CTR") + "\n")
    digestFile = open("MESSAGE_DIGEST.txt", "w")
    digestFile.write("Sha256 Hash of encrypted message: " + "\n" + sha256Sum("MESSAGE.AES_ENC_CTR"))
    digestFile.close()



# pad function for AES algos. Brings block size to required block size
# by AES.
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def encrypt_file_AES_CTR(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt_AES_CTR(plaintext, key)
    with open("MESSAGE.AES_ENC_CTR", 'wb') as fo:
        fo.write(enc)
    fo.close()


def encrypt_AES_CTR(message, key, key_size=256):
    
    iv = b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
    ctr = Crypto.Util.Counter.new(128, initial_value=int(binascii.hexlify(iv), 16))
    
    crypto = AES.new(key, AES.MODE_CTR, counter=ctr)
    encrypted = crypto.encrypt(message)
    return encrypted


#Sha256 Sum hash function 
def sha256Sum(inFile):

    sha256_hash = hashlib.sha256()
    with open(inFile,"rb") as f:
    
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    f.close()

main()