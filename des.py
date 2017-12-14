"""
key: key we will use to chyper and decypher
text_plain: text to cypher/decypher
"""
import matrices as m

# CONSTANTS
BLOCK_SIZE = 8  # Block size of DES = 8Bytes=64bits, sames as Key size.
PADDING = "0"   # we will fill the plaintext with 0s  if needed


# check key length
def check_key_length(key):
    if len(key) != BLOCK_SIZE:
        raise ValueError("DES Key size not valid, it should be 8 Bytes long.\n")
    else:
        print("Input Key is valid.")


# check input is not empty:
def check_input(data):
    if not data:
        raise ValueError("Input cannot be empty.")
    else:
        print("Input data is valid.\n")
        
# String (ASCII) to bits        
def string_to_bits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:] 
        # ord(c) returns the value of the byte when the argument is an 8-bit string
        # bin(ord(c)) as c is a string, returns 0b1100001(example) where 0b is like 0x for hexs, 0b indicates it is bin.
        # bin(ord(c))[2:] we dont want the two first elements (0b)
        bits = '00000000'[len(bits):] + bits  # fill with 0s in the left until it reachs 8.
        # len(bits) normally is < 8 because bin() dos not show the left 0s
        result.extend([int(b) for b in bits])  # put bits (a string) in an array.
    return result


# bits to string (ASCII)
def bits_to_string(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]  # byte = 8 bits, 0-7, 8-15...
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))  # int((''.join...),2)=>base 2 (binary, 0 or 1)
    return ''.join(chars)  # from array (chars) to string


# add padding to text
def add_padding(text):
    if len(text) % BLOCK_SIZE != 0:
        while len(text) % BLOCK_SIZE != 0:
            text += PADDING
    return text


# remove padding to text_padded 
def remove_padding(text):
    text = text[:-BLOCK_SIZE] + text[-BLOCK_SIZE:].rstrip(PADDING)
    return text
    
    
# *********************************************************************************
# Key Related Operations
# *********************************************************************************

# apply Matrix Permuted Choice 1 (pc1)
def key_expansion (key_binary):
    """
    binary_key: key in binary
    key_pc1:    key after permutating with pc1
    c:          [0] first 28 bits of pc1, [1] after first left shift, [2] after second left shift,...
    d:          [0] last 28 bits of pc1, [1] after first left shift, [2] after second left shift,...
    key_middle: array (size of pc2), is the result of applying pc2 to c+d, is filled element by element in a for loop.
    kn:         list of lists [k1,k2,...,k16], size of each k: 48bits. kn[0] = k1, ...
    """
    key_pc1 = [0]*56
    kn = [[0] * 48] * 16  # initializing a list of arrays(k1-k16)
    key_middle = [0]*len(m.pc2)
    #apply permuted choice1
    for i in range(0, len(m.pc1)):
        key_pc1[i] = key_binary[m.pc1[i]]

    c = key_pc1[:28]
    d = key_pc1[28:]
    # test
    # c = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27]
    # d = [28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55]
    
    for i in range (0, len(m.left_shifts)):
        for j in range (m.left_shifts[i]):
            # shift c and d:
            c.append(c[0])
            d.append(d[0])
            del c[0]
            del d[0]
            
        # apply pc2 for all k1-k16
        cd= c + d
        for k in range(0, len(m.pc2)):
            key_middle[k] = cd[m.pc2[k]]
        kn[i] = key_middle
    return kn




key = "01234567"  # NOT hex, normal string(ascii for python2.x).
text_plain = "hola"

check_key_length(key)
check_input(text_plain)
text_padded = add_padding(text_plain)
bits = string_to_bits(text_padded)
string = bits_to_string(bits)
text_unpadded = remove_padding(text_padded)
print text_plain
print text_padded
print bits
print string
print text_unpadded

#DES steps
check_key_length(key)
check_input(text_plain)
binary_key = string_to_bits(key)
kn = key_expansion(binary_key)




# TODO-me Optimize code for matrix permutation, this means: ip,ip_inv,pc1,pc2 and so on. (Create a function with two arguments:variable_to_permutate,permutating_matrix) 
# TODO-me implement PKCS-5 in order to avoid problem with remove_padding (if text=12340, padded=>12340000, unpadded=>1234 with my actual function remove_padding). if PKCS-5 complicated to implement, just make a quick check in remove_padding: if textplain last char is the same as the set of padding be careful.
# TODO-me optimize add_padding and remove_padding
# TODO-me offer the option of getting key, data an so by terminal (maybe comment one of the options, by prompt or by code))
# TODO-me if use prompt key input it is necessary to change function check_key_length(key) so if key is wrong, have the chance to change it.
# TODO-me key should be input as hex? check it out.
# TODO-me add compatibility with Python 3.x (most worry about string encoding in python3.x)
