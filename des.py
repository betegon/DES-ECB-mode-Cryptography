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
        # bin(ord(c)) as c is a string, returns  0b1100001(example) where 0b is like 0x for hexs, 0b indicates it is bin.
        # bin(ord(c))[2:] we dont want the two first elements (0b)
        bits = '00000000'[len(bits):] + bits #fill with 0s in the left until it reachs 8. 
        # len(bits) normally is < 8 because bin() dos not show the left 0s
        result.extend([int(b) for b in bits]) # put bits (a string) in an array.
    return result

# bits to string (ASCII)
def bits_to_string(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8] # byte = 8 bits, 0-7, 8-15...
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2))) # int((''.join...),2)=>base 2 (binary, 0 or 1)
    return ''.join(chars) #from array (chars) to string


# add padding to text
def add_padding(text):
    if len(text) % BLOCK_SIZE != 0:
        while len(text) % BLOCK_SIZE != 0:
            text += PADDING
    return text


# remove padding to paddedtext 
def remove_padding(text):
    text = text[:-BLOCK_SIZE] + text[-BLOCK_SIZE:].rstrip(PADDING)
    return text
    
    
# **********************
# Key related operations
# **********************

#apply Matrix Permuted Choice 1 (pc1)
def permuted_choice1 (key):
    c0 = [] #initializing c0 array
    d0 = [] #initializing d0 array
    
    return c0,d0




#LAST FUNCTION RELATED TO KEY OPERATIONS
#def key_expansion(key):
#    kn = [[0] * 48] * 16
#    return kn




key = "01234567"  # NOT hex, normal string.
text_plain = "h"

check_key_length(key)
check_input(text_plain)
text_padded = add_padding(text_plain)
bits = string_to_bits(text_padded)
string  = bits_to_string(bits)
text_unppaded = remove_padding(text_padded)
print text_plain
print text_padded
print bits
print string
print text_unppaded

# TODO-me implement PKCS-5 in order to avoid problem with remove_padding (if text=12340, padded=>12340000, unpadded=>1234 with my actual function remove_padding). if PKCS-5 complicated to implement, just make a quick check in remove_padding: if mes
# TODO-me optimize add_padding and remove_padding
# TODO-me offer the option of getting key, data an so by terminal (maybe comment one of the options, by prompt or by code))
# TODO-me if use prompt key input it is necessary to change function check_key_length(key) so if key is wrong, have the chance to change it.
# TODO-me key should be input as hex? check it out.
# TODO-me add compatibility with Python 3.x (most worry about string encoding in python3.x)
