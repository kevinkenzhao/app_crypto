from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii
import json
from nacl.secret import SecretBox
import secrets
import os
import sys
import re

def xor_bytes(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def AES_encrypt_block(key, block):
    assert len(key) == 16
    assert len(block) == 16
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)

def AES_decrypt_block(key, block):
    assert len(key) == 16
    assert len(block) == 16
    return Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(block)

def AES_encrypt_block_CTR(nonce, key, plaintext, counter):
    assert len(key) == 16
    assert len(nonce) == 12
    counter = counter.to_bytes(4, 'big')
    assert len(nonce+counter) == 16
    block = nonce+counter
    cipherblock = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)
    plaintext = bytes(plaintext,encoding='utf-8')
    cipherblock = cipherblock[:16-(16-len(plaintext))] #slices block cipher output to a length consistent with that of plaintext
    #print("lengths:")
    #print(len(cipherblock))
    #print(len(plaintext))
    return (int.from_bytes(counter, "big"))+1 , xor_bytes(cipherblock, plaintext)


#f = open('example_input.json')
#inputs = json.loads(json.dumps(json.load(f)))
inputs = json.loads(json.dumps(json.load(sys.stdin)))
outputs = {}

# Problem 1
blk = bytes(inputs["problem1"],encoding='utf-8')
key = b'A' * 16

outputs["problem1"] = AES_encrypt_block(key, blk).hex()

# Problem 2
enciphered_blk = bytes.fromhex(inputs["problem2"])
outputs["problem2"] = (AES_decrypt_block(key, enciphered_blk)).decode("utf-8", "strict")

# Problem 3
full_str = bytes(inputs["problem3"],encoding='utf-8')
numOfBlks = int(len(full_str) / 16)
outputs["problem3"] = ""
pos = 0
#print(numOfBlks)
for x in range(numOfBlks):
    blk = full_str[pos:pos+16]
    #print(len(blk))
    #print(blk)
    outputs["problem3"] += AES_encrypt_block(key, blk).hex()
    #print(AES_encrypt_block(key, blk).hex())
    pos+=16

# Problem 4
full_str = bytes.fromhex(inputs["problem4"])
numOfBlks = int(len(full_str) / 16)
outputs["problem4"] = ""
pos = 0
#print(numOfBlks)
for x in range(numOfBlks):
    blk = full_str[pos:pos+16]
    #print(len(blk))
    #print(blk)
    outputs["problem4"] += AES_decrypt_block(key, blk).decode("utf-8", "strict")
    pos+=16

#Problem 5
outputs["problem5"] = []
for x in range(4):
    input_string = bytes.fromhex(inputs["problem5"][x])
    remainder = len(input_string) % 16
    if remainder == 0:
        remainder+=16
    elif remainder < 16:
        remainder = 16 - remainder
    bytestr = bytes(str(hex(remainder)[2:].zfill(2)),encoding='utf-8') * remainder #eg. b'01' * remainder, b'02' * remainder

    input_string = input_string.hex()
    bytestr = bytestr.decode("utf-8", "strict")
    outputs["problem5"].append(input_string + bytestr)
    #outputs["problem5"].append((input_string + bytestr).hex()) -> does not work because bytestr will be interpreted as ASCII (as opposed to BASE10) represented as hex
    #eg. '1' -> 31 (hex) and '8' -> 38 (hex)

#Problem 6
outputs["problem6"] = []
for x in range(3):
    current_string = (inputs["problem6"][x])
    #print(str(current_string))
    strLen = len(current_string)
    padLen = int(current_string[-2:], 16) * 2 #int("0a", 16) * 2 -> 10 * 2 = 20
    #print(current_string[0:strLen-padLen])
    outputs["problem6"].append(bytes.fromhex(current_string[0:strLen-padLen]).decode("utf-8", "strict"))

#Problem 7
outputs["problem7"] = {"ciphertext":"","repeats":[]}
input_string0 = inputs["problem7"]["lyrics"]
#print(len(input_string0))
key = bytes.fromhex(inputs["problem7"]["key"])

input_string = bytes(input_string0, encoding='utf-8')
pos = 0

remainder = len(input_string0) % 16
#print(remainder)

if remainder == 0:
    remainder+=16
elif remainder < 16:
    lenToPad = 16 - remainder

padding = bytes(chr(lenToPad), encoding='utf-8') * lenToPad #eg. b'01' * remainder, b'02' * remainder
#print(str(padding))
paddedInputString = (input_string + padding)

numOfBlks = int(len(paddedInputString) / 16)
#print(numOfBlks)


blkList = []

#for x in range(numOfBlks+1):
#    if x == numOfBlks+1:
#        blk = input_string[pos:pos+remainder]
#        pos+=remainder
#    else:
#        blk = input_string[pos:pos+16]
#        pos+=16

for x in range(numOfBlks):
    blk = paddedInputString[pos:pos+16]
    outputs["problem7"]["ciphertext"] += AES_encrypt_block(key, blk).hex()
    blkList.append(AES_encrypt_block(key, blk).hex())
    
    #decrypts the above for verification check
    #y = bytes.fromhex(AES_encrypt_block(key, blk).hex())
    #w = AES_decrypt_block(key, y)
    #print(w.decode("utf-8", "strict"))
    #print(str(w))
    
    #decrypts problem7 ciphertext for verification check
    #b = "fded6e9b1d7464395ee5c56daa65a0e1c4e518fd5ae36c82466df4104ecb32618b7954e627ad85d2777589574717308b7177841e1849cbda95057fed9254a664355cf92f963cda26dbc598ed656d61e00b3fca5a58456dfbdaeb41a8280bee49b9e063504cdb5dc945d472e51a834cf7fded6e9b1d7464395ee5c56daa65a0e1c4e518fd5ae36c82466df4104ecb326108e1b2c7619d98e66877fc5b9eb5984c8e11a156ff50725f0d2158a8866d82e8"
    #c = bytes.fromhex(b)
    #cSub = c[pos:pos+16]
    #decryptedBlk = AES_decrypt_block(key, cSub)
    #print(decryptedBlk.decode("utf-8", "strict"))
    #print(str(decryptedBlk))
    pos+=16
pos=0
for x in range(numOfBlks):
    blk = paddedInputString[pos:pos+16]
    encryptedBlk = AES_encrypt_block(key, blk).hex()
    #print("occurrences:")
    #print(len(re.findall(str(encryptedBlk), str(blkList))))
    if len(re.findall(str(encryptedBlk), str(blkList))) > 1 and str(encryptedBlk) not in outputs["problem7"]["repeats"]:
        outputs["problem7"]["repeats"].append(str(encryptedBlk))
    pos+=16




#Problem 8
key = bytes.fromhex(inputs["problem8"]["key"])
nonce = bytes.fromhex(inputs["problem8"]["nonce"])
plaintext = inputs["problem8"]["plaintext"]
numOfBlks = int(len(plaintext) / 16)
remainder = len(plaintext) % 16

pos = 0

counter = 0

blkList = []
fullCiphertext = ""

for x in range(numOfBlks+1):
    if x == numOfBlks+1:
        blk = plaintext[pos:pos+remainder]
        pos+=remainder
    else:
        blk = plaintext[pos:pos+16]
        pos+=16
    counter, ciphertext = AES_encrypt_block_CTR(nonce, key, blk, counter)
    fullCiphertext += ciphertext.hex()
outputs["problem8"] = fullCiphertext  

#Problem 9
key = bytes.fromhex(inputs["problem9"])
plaintext = (b"\x00" * 40).decode("utf-8", "strict")
nonce = b"\x00" * 12
counter = 0
pos = 0
numOfBlks = int(40 / 16) #2
remainder = int(40 % 16) #8

blkList = bytearray()
listOfInts = []

for x in range(numOfBlks+1):
    if x == numOfBlks+1:
        blk = plaintext[pos:pos+remainder]
        pos+=remainder
    else:
        blk = plaintext[pos:pos+16]
        pos+=16
    counter, ciphertext = AES_encrypt_block_CTR(nonce, key, blk, counter)
    blkList.extend(ciphertext)

pos=0
for x in range(5):
    blk = blkList[pos:pos+8]
    listOfInts.append(int.from_bytes(blk, "little"))
    pos+=8

outputs["problem9"] = listOfInts


print(json.dumps(outputs, indent="  "))