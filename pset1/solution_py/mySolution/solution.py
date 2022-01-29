#! /usr/bin/env python3

from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
import sys
import json
from math import prod

#f = open('example_input.json')
inputs = json.loads(json.dumps(json.load(sys.stdin)))
#inputs = json.load(sys.stdin)
outputs = {}

# Problem 1
outputs["problem1"] = {
    "sum": sum(x for x in inputs["problem1"]),
    "product": prod(x for x in inputs["problem1"]), 
}

#print(outputs["problem1"]["sum"])
#print(outputs["problem1"]["product"])


# Problem 2
input_hex = inputs["problem2"]
outputs["problem2"] = bytes.fromhex(input_hex).decode('ascii')

#print(outputs["problem2"])

# Problem 3
input_string = inputs["problem3"]
outputs["problem3"] = input_string.encode('ascii').hex()

#print(outputs["problem3"])

# Problem 4
input_string = inputs["problem4"]
plaintext = SecretBox(b'A'*32).decrypt(bytes.fromhex(input_string), (b'B'*24))
outputs["problem4"] = plaintext.decode()
#print(outputs["problem4"])

# Problem 5
input_string = inputs["problem5"]
#print(input_string)
#print(type(input_string))

plaintext = ""
for x in input_string:
    try:
        plaintext = SecretBox(b'C'*32).decrypt(bytes.fromhex(x), (b'D'*24))
        outputs["problem5"] = plaintext.decode()
    except CryptoError:
        continue

#print(outputs["problem5"])

print(json.dumps(outputs, indent="  "))