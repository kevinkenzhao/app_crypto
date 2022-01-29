import json
import os
import hashlib
import sys
import hmac
#from sys import byteorder
from cryptography.hazmat.primitives.poly1305 import Poly1305
from nacl import encoding
import salsa20
import secrets
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError

f = open('example_input.json')
inputs = json.loads(json.dumps(json.load(f)))
#inputs = json.loads(json.dumps(json.load(sys.stdin)))
outputs = {}

def xor_bytes(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))

def secretbox(key, nonce, plaintext):
    length = len(plaintext) + 32
    salsa20_keystream = salsa20.XSalsa20_keystream(length, nonce, key)
    poly1305_key = salsa20_keystream[0:32]
    #print("salsa20_keystream")
    #print(salsa20_keystream.hex())
    #print("poly key")
    #print(poly1305_key.hex())
    #print(len(poly1305_key))
    partial_keystream = salsa20_keystream[32:61] #bytes 33 to 61, after the first 32 bytes used fors the poly1305 key
    #print("partial keystream")
    #print(partial_keystream.hex())
    #print(len(partial_keystream))
    #print(type(partial_keystream))
    #print(type(p4_message.encode("ascii")))
    #print(len(p4_message.encode("ascii")))
    xor_ciphertext = xor_bytes(partial_keystream, p4_message.encode("ascii"))
    poly1305_mac = Poly1305.generate_tag(poly1305_key, xor_ciphertext)
    #print(type(poly1305_mac))
    secretbox_ciphertext = poly1305_mac + xor_ciphertext
    return secretbox_ciphertext

#Problem 1
p1_Key = bytes.fromhex(inputs["problem1"]["key"])
p1_Message = inputs["problem1"]["message"].encode("ascii")
ipad = b"\x36" * 64
opad = b"\x5c" * 64

masked_inner_key = xor_bytes(p1_Key, ipad)
maskedInnerKeyandMessageHash = hashlib.sha256(masked_inner_key+p1_Message).digest()
masked_outer_key = xor_bytes(p1_Key, opad)
hmacKeyMessage = hashlib.sha256(masked_outer_key + maskedInnerKeyandMessageHash).hexdigest()

hmacdigest = hmac.new(p1_Key, msg=p1_Message, digestmod=hashlib.sha256).digest()

assert hmac.compare_digest(hmacKeyMessage, hmacdigest.hex())
outputs["problem1"] = hmacdigest.hex()
#print(hmacKeyMessage)
#print(hmacdigest.hex())

#Problem 2
length = (int(inputs["problem2"]))
nonce = b"E"*24
key = b"D"*32
outputs["problem2"] = salsa20.XSalsa20_keystream(length, nonce, key).hex()

#Problem 3
p3_message = bytes(inputs["problem3"], encoding='utf-8')
p3_key = b"F" * 32
outputs["problem3"] = Poly1305.generate_tag(p3_key, p3_message).hex()

#Problem 4
p4_message = inputs["problem4"]
p4_key = b"G" * 32
p4_nonce = b"H" * 24

outputs["problem4"] = secretbox(p4_key, p4_nonce, p4_message).hex()

#verification check
ciphertext = SecretBox(p4_key).encrypt(bytes(p4_message, encoding="utf-8"), p4_nonce).hex()
secretbox_ciphertext = ciphertext[len(p4_nonce)*2:len(ciphertext)] #slice resulting ciphertext to omit the prepended 24-byte "H" nonce
assert secretbox_ciphertext == outputs["problem4"]

print(json.dumps(outputs, indent="  "))