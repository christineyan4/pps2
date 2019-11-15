import urllib.request
from Crypto.Cipher import AES
import binascii
import base64
import random
import os
import zlib


################################################################################
# Helper functions
################################################################################

# problem 1
def find_bias():
    hashes = []
    query = ''

    for i in range(50):
        hashes.append({})
        query += '\x00'
    for i in range(200):
        response = make_query('one', 'cyan4', query)
        for j in range(50):
            byte = response[j]
            if byte in hashes[j]:
                hashes[j][byte] += 1
            else:
                hashes[j][byte] = 1
    
    maxbyte = bytes()
    maxcount = 0
    maxindex = -1 
    i = 0
    for hash in hashes:
        for key in hash: 
            if hash[key] > maxcount:
                maxcount = hash[key]
                maxbyte = key
                maxindex = i
        i += 1

    print("Bias is " + str(maxbyte) + " at byte " + str(maxindex))
    print(str(maxcount) + " times")
    return maxindex

# problem 3
def get_flaglength():
    replylengths = []
    query = '\x00'
    oldresponse = make_query('three', 'cyan4', query)
    done = False

    while not done:
        query += '\x00'
        newresponse = make_query('three', 'cyan4', query)
        if len(newresponse) != len(oldresponse):
            done = True
    flaglength = len(newresponse) - 16 - len(query)
    return flaglength

def xor(blockone, blocktwo):
    key = bytearray()
    for i in range(16):
        key.append(blockone[i] ^ blocktwo[i])
    return bytes(key)

# problem 4
def cbc_encrypt(plaintext, key):
    paddedtext = cmsc284pad(plaintext)
    blockone = bytes(paddedtext[:16])
    blocktwo = bytes(paddedtext[16:])
    
    cipher = AES.new(key, AES.MODE_ECB)
    cipherone = cipher.encrypt(xor(key, blockone))
    ciphertwo = cipher.encrypt(xor(cipherone, blocktwo))

    return cipherone + ciphertwo

###############################################################################
# CS 284 Padding Utility Functions
################################################################################

# s is a bytearray to pad, k is blocklength
# you won't need to change the block length
def cmsc284pad(s,k=16):
    if k > 255:
        print("pkcs7pad: padding block length must be less than 256")
        return bytearray()
    n = k - (len(s) % k)
    if n == 0:
        n = k
    for i in range(1,n+1):
        s.extend([i])
    return s

# s is bytes to pad, k is blocklength
# you won't need to change the block length
def cmsc284padbytes(s,k=16):
    if k > 255:
        raise Exception("pkcs7pad: padding block length must be less than 256")
    n = k - (len(s) % k)
    if n == 0:
        n = k
    for i in range(1,n+1):
        s += chr(i).encode("utf-8")
    return s

# s is bytes to unpad, k is blocklength
# you won't need to change the block length
def cmsc284unpad(s,k=16):
    if not cmsc284checkpadding(s,k):
        print("cmsc284unpad: invalid padding")
        return b''
    n = s[len(s)-1]
    return s[:len(s)-n]

# checks padding on s and returns a boolean
# you won't need to change the block length
def cmsc284checkpadding(s,k=16):
    if(len(s) == 0):
       #print("Invalid padding: String zero length"%k) 
       return False
    if(len(s)%k != 0): 
       #print("Invalid padding: String is not multiple of %d bytes"%k) 
       return False
    n = s[len(s)-1]
    if n > k or n == 0:
       return False
    else: 
        for i in range(n):
            if s[len(s)-1-i] != (n-i):
                return False
    return True

################################################################################
# Function for querying the server
################################################################################

PPS2SERVER = "http://cryptoclass.cs.uchicago.edu/"
def make_query(task, cnetid, query):
    #DEBUG = True
    DEBUG = False
    if DEBUG:
        print("making a query")
        print("Task:", task)
        print("CNET ID:", cnetid)
        print("Query:", query)
    if (type(query) is bytearray) or (type(query) is bytes):
        url = PPS2SERVER + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnetid) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query)) + "/"
    else:
        url = PPS2SERVER + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnetid) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query.encode('utf-8'))) + "/"
    if DEBUG:
        print("Querying:", url)

    with urllib.request.urlopen(url) as response:
        raw_answer = response.read()
        answer = base64.urlsafe_b64decode(raw_answer)
        if DEBUG:
            print("Answer:", answer)
        return answer
    return None


################################################################################
# Problem 1 SOLUTION
################################################################################

def problem1(cnetid):
    query = ''
    for i in range(30):
        query += '\x00'
    
    hashes = [{} for i in range(17)]
    for i in range(17):
        for j in range(150):
            response = make_query('one', 'cyan4', query)
            byte = response[30]
            if byte in hashes[i]:
                hashes[i][byte] += 1
            else:
                hashes[i][byte] = 1
        query = query[1:]
        print(len(query))
    
    flag = bytearray()
    for hash in hashes:
        maxcount = 0
        maxbyte = bytes()
        for key in hash:
            if hash[key] > maxcount:
                maxcount = hash[key]
                maxbyte = key
        flag.append(maxbyte)
    return bytes(flag)


################################################################################
# Problem 2 SOLUTION
################################################################################

def problem2(cnetid):
    onebyte = 'c'
    response = make_query('twob', cnetid, onebyte)
    usertext = response[:16]

    emptyquery = ''
    response = make_query('twoa', cnetid, emptyquery)
    admintext = response[-16:]

    ciphertext = usertext + admintext
    response = make_query('twoc', cnetid, ciphertext)

    return response


################################################################################
# Problem 3 SOLUTION
################################################################################

def problem3(cnetid):
    flaglength = get_flaglength()
    querylength = flaglength + (16 - flaglength % 16) - 1

    query = bytearray(querylength)
    flag = bytearray()
    newquery = bytearray(querylength + 1)

    for i in range(flaglength):
        response = make_query('three', cnetid, query)

        for x in range(0, 256):
            newquery[querylength] = x
            newresponse = make_query('three', cnetid, newquery)
            if newresponse[:querylength + 1] == response[:querylength + 1]:
                flag.append(x)
                newquery.append(x)
                newquery = newquery[1:]
                break
        query = query[1:]

    return flag


################################################################################
# Problem 4 SOLUTION
################################################################################

def problem4(cnetid):
    keyquery = bytearray(32)
    keytext = make_query('fourb', cnetid, keyquery)
    key = xor(keytext[:16], keytext[16:])
    print(key)

    plaintext = bytearray(b'let me in please')
    ciphertext = cbc_encrypt(plaintext, bytes(key))
    print(ciphertext)

    response = make_query('fourc', cnetid, ciphertext)
    return response


################################################################################
# Problem 5 SOLUTION
################################################################################

def problem5(cnetid):
    return b''

################################################################################
# Problem 6 SOLUTION
################################################################################

def problem6(cnetid):
    return b''


if __name__ == "__main__":
    """
    # testing problem 1
    biasbyte = find_bias()
    print(problem1('cyan4'))

    # testing problem 2
    print(problem2('cyan4'))

    # testing problem 3
    flaglength = get_flaglength()
    print(problem3('cyan4'))
"""
    # testing problem 4
    print(problem4('cyan4'))

    # example running AES; delete the code below here
    """
    key = b'ABCDEFGHABCDEFGH'
    block1 = b'abcdefghabcdefgh'
    block2 = bytearray(b'abcdefghabcdefgh')

    # we declare the mode to be ECB but can just it or single-block calls to
    # AES
    cipher = AES.new(key, AES.MODE_ECB)
    print(cipher.encrypt(block1))

    # the following call with fail without the converting block2 to bytes the
    # call to AES. The AES implementation requires an immutable object and
    # bytearray is mutable. Same goes for key.
    print(cipher.encrypt(bytes(block2)))

    # test query, will hang if off campus
    # print(make_query('one','davidcash', ''))

    # bytearrays are mutable, which is handy
    print(block2)
    block2.extend([0])
    print(block2)
    block2.extend(block1)
    block2 = bytearray(b'abcdefghabcdefgh')
    print(block2)
    """