#! /usr/bin/env python3

import binascii
import json
from nacl.secret import SecretBox
import secrets
import os
import sys


def xor_bytes(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))

#f = open('example_input.json')
#inputs = json.loads(json.dumps(json.load(f)))
inputs = json.loads(json.dumps(json.load(sys.stdin)))
outputs = {}

# Problem 1
#print("Problem 1")
#print(inputs["problem1"])
#print(len(inputs["problem1"]))
#print(type(inputs["problem1"]))
#print(len(bytes(inputs["problem1"], encoding='utf-8')))

onetimepad = (secrets.token_bytes(len(inputs["problem1"])))
ciphertext = (xor_bytes(bytes(inputs["problem1"], encoding='utf-8'), onetimepad))

outputs["problem1"] = {
   "pad": onetimepad.hex(),
   "ciphertext": ciphertext.hex(),
 }
#print(outputs["problem1"]["pad"])
#print(outputs["problem1"]["ciphertext"])


# Problem 2
#print("Problem 2")
onetimepad2 = inputs["problem2"]["pad"]
ciphertext2 = inputs["problem2"]["ciphertext"]

outputs["problem2"] = (xor_bytes(bytes.fromhex(ciphertext2), bytes.fromhex(onetimepad2))).decode("utf-8", "strict")

#print(outputs["problem2"])

# Problem 3
#print("Problem 3")
cipher1 = inputs["problem3"][0]
cipher2 = inputs["problem3"][1]
plaintext1 = b"$" * len(bytes.fromhex(cipher1))
#print(len(cipher1))
#print(len(bytes.fromhex(cipher1)))
onetimepad = xor_bytes(bytes.fromhex(cipher1), plaintext1)
outputs["problem3"] = (xor_bytes(bytes.fromhex(cipher2), onetimepad)).decode("utf-8", "strict") #plaintext of cipher2

#print(outputs["problem3"])

# Problem 4
#print("Problem 4")
input_string = inputs["problem4"]
key = b"A" * 32
enciphered = []
#noncelist = [x.to_bytes(24, "little") for x in range(0,len[input_string])]

#print(len(input_string))
for x in range(0,len(input_string)):
    plaintext = input_string[x]
    enciphered.append(SecretBox(key).encrypt(plaintext.encode('ascii'), x.to_bytes(24, "little")).ciphertext)
    #print(len(plaintext.encode('ascii')))

outputs["problem4"] = [
    enciphered[0].hex(),
    enciphered[1].hex(),
    enciphered[2].hex(),
]

#print(outputs["problem4"])

# Problem 5
#print("Problem 5")
input_string0 = inputs["problem5"][0]
#print(len(input_string0))
input_string1 = inputs["problem5"][1]
#print(len(input_string1))
input_string2 = inputs["problem5"][2]
#print(len(input_string2))
deciphered = []
key = b"B" * 32

for x in range(0,3):
    ciphertext = inputs["problem5"][x]
    #print(ciphertext)
    deciphered.append(SecretBox(key).decrypt(bytes.fromhex(ciphertext), x.to_bytes(24, "little")))

outputs["problem5"] = [
    deciphered[0].decode("utf-8", "strict"),
    deciphered[1].decode("utf-8", "strict"),
    deciphered[2].decode("utf-8", "strict"),
]

#print(outputs["problem5"])


#Problem 6
#print("Problem 6")
input_string0 = inputs["problem6"][0]
input_string0 = input_string0[32:] #remove 16-byte Poly1305 authenticator tags
#print(len(input_string0))
input_string1 = inputs["problem6"][1]
input_string1 = input_string1[32:]
#print(len(input_string1))
plaintext0 = b"$" * len(bytes.fromhex(input_string0))
#print(len(plaintext0))

onetimepad = xor_bytes(bytes.fromhex(input_string0), plaintext0)
outputs["problem6"] = (xor_bytes(bytes.fromhex(input_string1), onetimepad)).decode("utf-8", "strict") #plaintext of cipher2
#print(type(outputs["problem6"]))


#Problem 7
#print("Problem 7")
enciphered = []
key = b"C" * 32
for x in range(0,3):
    plaintext = inputs["problem7"][x]
    nonce=(int.from_bytes(os.urandom(24), byteorder="little"))
    enciphered.append(SecretBox(key).encrypt(plaintext.encode('ascii'), nonce.to_bytes(24, "little")))
#print(type(enciphered[0].hex()))
outputs["problem7"] = [
    enciphered[0].hex(),
    enciphered[1].hex(),
    enciphered[2].hex(),
]

#print(outputs["problem7"])


#Problem 8
#print("Problem 8")
input_string0 = inputs["problem8"][0]
#print(len(input_string0))
input_string1 = inputs["problem8"][1]
#print(len(input_string1))
input_string2 = inputs["problem8"][2]
#print(len(input_string2))
deciphered = []
key = b"C" * 32

for x in range(0,3):
    ciphertext = inputs["problem8"][x]
    #print(ciphertext)
    deciphered.append(SecretBox(key).decrypt(bytes.fromhex(ciphertext)))

outputs["problem8"] = [
    str(deciphered[0].decode("utf-8", "strict")),
    str(deciphered[1].decode("utf-8", "strict")),
    str(deciphered[2].decode("utf-8", "strict")),
]

#print(outputs["problem8"])


print(json.dumps(outputs, indent="  "))
