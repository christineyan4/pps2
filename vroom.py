import pps2 as pps

def findbias(query):
    hashes = []
    maxbyte = bytes()
    maxnum = 0
    maxindex = -1 

    for i in range(51):
        hashes.append({})
    for i in range(100):
        response = pps.make_query('one', 'cyan4', query)
        for j in range(51):
            byte = response[j]
            if byte in hashes[j]:
                hashes[j][byte] += 1
            else:
                hashes[j][byte] = 1
    
    i = 0
    for hash in hashes:
        for key in hash: 
            if hash[key] > maxnum:
                maxnum = hash[key]
                maxbyte = key
                maxindex = i
        i += 1

    print(hashes)
    print("Bias is " + str(maxbyte) + " at byte " + str(maxindex))
    print(str(maxnum) + " times")

def breakbias(query):
    hashes = []

    for i in range(17):
        hashes.append({})
    for i in range(17):
        for j in range(200):
            response = pps.make_query('one', 'cyan4', query)
            byte = response[30]
            if byte in hashes[i]:
                hashes[i][byte] += 1
            else:
                hashes[i][byte] = 1
        query = query[1:] 
        print(len(query))

    flag = bytearray()
    for hash in hashes:
        maxnum = 0
        maxbyte = bytes()
        for key in hash:
            if hash[key] > maxnum:
                maxnum = hash[key]
                maxbyte = key
        flag.append(maxbyte)
    return flag
    
if __name__ == '__main__':
    response = pps.make_query('one', 'cyan4', '')
    print(len(response))

    query = ''
    for i in range(50):
        query += '\x00'
    print(query)
    #findbias(query)
    
    flag = breakbias(query[-30:])
    print(flag)