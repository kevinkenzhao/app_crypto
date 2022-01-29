#! /usr/bin/env python3

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.signing import SigningKey
from nacl.signing import VerifyKey
import json
import sys

f = open('example_input.json')
inputs = json.loads(json.dumps(json.load(f)))
#inputs = json.loads(json.dumps(json.load(sys.stdin)))
outputs = {}

#Problem 1
my_keypair = PrivateKey(b"A" * 32)
#print("my private key:", my_keypair.encode().hex())
my_publickey = my_keypair.public_key

alice_public_key = PublicKey(bytes.fromhex(inputs["problem1"]))
#print("alice public key:", alice_public_key.encode().hex())

bob_box = Box(my_keypair, alice_public_key)
message = b"hello world"
nonce_len = 24
nonce = b"B" * nonce_len
outputs["problem1"] = bob_box.encrypt(message,nonce).hex()[nonce_len*2:]

#Problem 2
nonce2 = b"C" * 24
plaintext = bob_box.decrypt(bytes.fromhex(inputs["problem2"]),nonce2)
outputs["problem2"] = plaintext.decode('utf-8')
#print(plaintext.decode('utf-8'))

#Problem 3
outputs["problem3"] = Box(my_keypair, alice_public_key).encode().hex()
boxobject = SecretBox(Box(my_keypair, alice_public_key).encode())
#print(boxobject.decrypt(bytes.fromhex(outputs["problem1"]), nonce = b"B" * 24).decode('utf-8')) #verified that symmetric decryption via SecretBox using nonce b"B"*24 yields "hello world"

#Problem 4
my_keypair = SigningKey(b"D" * 32)
signature = my_keypair.sign(bytes(inputs["problem4"],encoding='utf-8')).signature
outputs["problem4"] = signature.hex()

#Problem 5
verify_public_key = VerifyKey(bytes.fromhex(inputs["problem5"]["signing_public_key"]))

for x in inputs["problem5"]["candidates"]:
    try:
        outputs["problem5"] = verify_public_key.verify(x.encode('utf-8'), bytes.fromhex(inputs["problem5"]["signature"])).decode()
        break
    except CryptoError:
        continue

print(json.dumps(outputs, indent="  "))