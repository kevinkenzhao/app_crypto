import json
import os
import hashlib
import sys
#from sys import byteorder

ROUND_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

f = open('example_input.json')
inputs = json.loads(json.dumps(json.load(f)))
#inputs = json.loads(json.dumps(json.load(sys.stdin)))
outputs = {}

def add32(x, y):
    assert isinstance(x, (int, float)), 'Variable x type error!'
    assert isinstance(y, (int, float)), 'Variable y type error!'
    return ((x+y) % 2**32)

def rightrotate32(x, n):
    right_part = x >> n
    left_part = (x << (32 - n)) % (2 ** 32)
    return left_part | right_part

def little_sigma0(x):
    return (rightrotate32(x, 7) ^ rightrotate32(x, 18) ^ (x >> 3))

def little_sigma1(x):
    return (rightrotate32(x, 17) ^ rightrotate32(x, 19) ^ (x >> 10))

def message_schedule(x):
    inputstring = x
    numOfBlks = int(len(inputstring) / 4)
    #print(numOfBlks)
    pos = 0
    lst = []
    for x in range(numOfBlks):
        #print(x)
        blk = inputstring[pos:pos+4]
        #print("printing blk...")
        #print(type(blk))
        #print(blk)
        lst.append(int.from_bytes(blk, "big"))
        pos+=4
        #print(pos)
    
    for wordCount in range(16,64,1):
        # W[i] := W[i-16] + little_sigma0(W[i-15]) + W[i-7] + little_sigma1(W[i-2])
        p1 = add32(lst[wordCount-16], little_sigma0(lst[wordCount-15])) #W[i-16] + little_sigma0(W[i-15])
        p2 = add32(lst[wordCount-7], little_sigma1(lst[wordCount-2])) #W[i-7] + little_sigma1(W[i-2])
        lst.append(add32(p1, p2))
    return lst

def big_sigma0(x):
    return (rightrotate32(x, 2) ^ rightrotate32(x, 13) ^ rightrotate32(x, 22))

def big_sigma1(x):
    return (rightrotate32(x, 6) ^ rightrotate32(x, 11) ^ rightrotate32(x, 25))

def choice(x,y,z):
    return ((x & y) ^ (~x & z))

def majority(x,y,z):
    return ((x & y) ^ (x & z) ^ (y & z))

def round_Funct(state, round_constant, schedule_word):
    ch = choice(state[4], state[5], state[6])
    p1 = add32(state[7], big_sigma1(state[4]))
    p2 = add32(ch, round_constant)
    p3 = add32(p2, schedule_word)
    temp1 = add32(p1,p3)
    maj = majority(state[0], state[1], state[2])
    temp2 = add32(big_sigma0(state[0]), maj)
    new_state = [add32(temp1, temp2), state[0], state[1], state[2], add32(state[3], temp1), state[4], state[5], state[6]] 
    return new_state

def compress(input_state, block):
    W = message_schedule(block)
    state = input_state
    for i in range(0,64,1):
        state = round_Funct(state, ROUND_CONSTANTS[i], W[i])
    state = [add32(input_state[0], state[0]),add32(input_state[1], state[1]),add32(input_state[2], state[2]), add32(input_state[3], state[3]), add32(input_state[4], state[4]), add32(input_state[5], state[5]), add32(input_state[6], state[6]), add32(input_state[7], state[7])]
    return state

def padding(input_length):
    eightByteNum = (input_length * 8).to_bytes(8, byteorder='big')
    remainder = (input_length + 8) % 64 #original length + length of eightByteNum appended to end
    numOfPaddedBytes = 64 - remainder - 1 # subtract by the remainder and length of single 0x80 byte at the beginning
    zero_bytes = b'\x00' * numOfPaddedBytes
    return (b'\x80' + zero_bytes + eightByteNum)

def sha256(message):
    paddedMsg = bytes(message,encoding='utf-8') + padding(len(message)) #bytes(message,encoding='utf-8')
    state = IV
    numOfBlks = int(len(paddedMsg) / 64)
    pos = 0
    for x in range(numOfBlks):
        blk = paddedMsg[pos:pos+64]
        state = compress(state, blk)
        pos+=64

    hashsum = ""
    for word in state:
        hashsum += (word).to_bytes(4, byteorder='big').hex()

    return hashsum

#Problem 1
outputs["problem1"]=[]

for x in inputs["problem1"]:
    outputs["problem1"].append(add32(x[0],x[1]))

#Problem 2
outputs["problem2"]=[]

for x in inputs["problem2"]:
    outputs["problem2"].append(rightrotate32(x[0],x[1]))

#Problem 3
outputs["problem3"] = little_sigma0(inputs["problem3"])

#Problem 4
outputs["problem4"] = little_sigma1(inputs["problem4"])

#Problem 5
outputs["problem5"] = message_schedule(inputs["problem5"].encode('ascii'))

#Problem 6
outputs["problem6"] = big_sigma0(inputs["problem6"])

#Problem 7
outputs["problem7"] = big_sigma1(inputs["problem7"])

#Problem 8
outputs["problem8"] = choice(inputs["problem8"][0],inputs["problem8"][1],inputs["problem8"][2])

#Problem 9
outputs["problem9"] = majority(inputs["problem9"][0],inputs["problem9"][1],inputs["problem9"][2])


#Problem 10
#print("problem10")
state = inputs["problem10"]["state"]
round_const = inputs["problem10"]["round_constant"]
schedule_word = inputs["problem10"]["schedule_word"]
outputs["problem10"] = round_Funct(state, round_const, schedule_word)

#Problem 11
#print("problem11")
state = inputs["problem11"]["state"]
block = inputs["problem11"]["block"].encode('ascii')
outputs["problem11"] = compress(state, block)

#Problem 12
listOfInputLen = inputs["problem12"]
#print("problem12")
sha256PaddingByteStr = []

for value in listOfInputLen:
    sha256PaddingByteStr.append(padding(value).hex())

outputs["problem12"] = sha256PaddingByteStr

#Problem 13
listOfStrings = inputs["problem13"]
outputs["problem13"] = []
#print("problem13")
for message in listOfStrings:
    outputs["problem13"].append(sha256(message))

#Problem 14
originalInput = inputs["problem14"]["original_input"]
chosenSuffix = inputs["problem14"]["chosen_suffix"]
originalInput = originalInput.encode("ascii")
chosenSuffix = chosenSuffix.encode("ascii")
outputs["problem14"] =  originalInput.hex() + padding(len(originalInput)).hex() + chosenSuffix.hex()

#Problem 15
outputs["problem15"] = []
hashAsBytes = bytes.fromhex(inputs["problem15"])
numOfBlks = int(len(hashAsBytes) / 4)
#print(numOfBlks)
pos = 0
lst = []
for x in range(numOfBlks):
    #print(x)
    blk = hashAsBytes[pos:pos+4]
    lst.append(int.from_bytes(blk, "big"))
    pos+=4

outputs["problem15"] = lst

#Problem 16
originalInput = bytes.fromhex(inputs["problem16"]["original_hash"])
originalLen = inputs["problem16"]["original_len"]
chosenSuffix = inputs["problem16"]["chosen_suffix"].encode('ascii')
paddingOutput = padding(len(padding(originalLen)) + originalLen + len(chosenSuffix)) #padding(94) -> equivalent to padding(chosen suffix length)
paddedMsg = chosenSuffix + paddingOutput
#print("chosen suffix length:" + str(len(chosenSuffix)))
#print("Padding Output:" + str(paddingOutput))
#print("chosen suffix pad length:" + str(len(paddingOutput)))
#print("padding input length:" + str(len(padding(originalLen)) + originalLen + len(chosenSuffix)))

#------Recovering state of original hash------
numOfBlks = int(len(originalInput) / 4)
pos = 0
originalState = []
for x in range(numOfBlks):
    blk = originalInput[pos:pos+4]
    originalState.append(int.from_bytes(blk, "big"))
    pos+=4

#---------------------------------------------

state = originalState
numOfBlks = int(len(paddedMsg) / 64)
pos = 0
for x in range(numOfBlks):
    blk = paddedMsg[pos:pos+64]
    state = compress(state, blk)
    pos+=64

hashsum = ""

for word in state:
    hashsum += (word).to_bytes(4, byteorder='big').hex()
    #print(word)
outputs["problem16"] = hashsum

print(json.dumps(outputs, indent="  "))


