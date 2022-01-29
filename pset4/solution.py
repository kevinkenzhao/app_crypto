import json
import os
import hashlib
import sys
#from sys import byteorder

#f = open('example_input.json')
#inputs = json.loads(json.dumps(json.load(f)))
inputs = json.loads(json.dumps(json.load(sys.stdin)))
outputs = {}

#Problem 1
inputstring = bytes(inputs["problem1"],encoding='utf-8')
outputs["problem1"] = {"md5":"","sha1":"","sha256":"","sha3_256":"",}
for x in ["md5","sha1","sha256","sha3_256"]:
    s = "hashlib." + x + "(" + str(inputstring) + ").hexdigest()"
    hex_encoded_hash = eval(s)
    outputs["problem1"][x] = hex_encoded_hash

#Problem 2
original = inputstring
modified = bytearray(original)
#modified[0] = ord("?") #ASCII to HEX to BASE10: "?" -> 3f -> 63
modified[0] = 63 
assert modified.startswith(b"?") == True

outputs["problem2"] = {"md5":"","sha1":"","sha256":"","sha3_256":"",}
for x in ["md5","sha1","sha256","sha3_256"]:
    s = "hashlib." + x + "(" + str(modified) + ").hexdigest()"
    hex_encoded_hash = eval(s)
    outputs["problem2"][x] = hex_encoded_hash

#Problem 3
hex_encoded_hashes = []
for x in inputs["problem3"]:
    hex_encoded_hashes.append(hashlib.md5(bytes.fromhex(x)).hexdigest())
assert hex_encoded_hashes[0] == hex_encoded_hashes[1]
outputs["problem3"] = hex_encoded_hashes[0]

#Problem 4
#pdfBytes = []
#print(os.listdir(os.getcwd()))
#os.chdir('/autograder')
#for f in os.listdir(os.getcwd()):
#    if f.startswith('shattered-') and f.endswith('.pdf'):
#        pdfBytes.append(hashlib.sha1(open(f, "rb").read()).hexdigest()) #read file contents as bytes and take the hash of that byte stream
#assert len(pdfBytes) > 0
#assert pdfBytes[0] == pdfBytes[1]

outputs["problem4"] = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

#Problem 5
currentCount = startCount = inputs["problem5"]
outputs["problem5"] = {"lucky_hash":"","tries":""}

while True:
    hexdigest = hashlib.sha256(currentCount.to_bytes(8, byteorder="little")).hexdigest()
    if hexdigest.startswith("000000"):
        outputs["problem5"]["lucky_hash"] = hexdigest
        outputs["problem5"]["tries"] = currentCount - startCount + 1
        break
    currentCount+=1

print(json.dumps(outputs, indent="  "))


