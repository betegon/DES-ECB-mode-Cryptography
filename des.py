"""
key: key we will use to chyper and decipher
text_plain: text to cipher/decipher
"""
import matrices as m
import time
# CONSTANTS
BLOCK_SIZE = 16  # Block size of DES 16hex = 8Bytes=64bits, sames as Key size.
PADDING = "0"  # we will fill the plaintext with 0s  if needed

def hex2bin(chain):
    result = []
    result_string = ''.join((bin(int(chain[i:i+2], 16))[2:].zfill(8) for i in range(0, len(chain), 2)))
    result.extend([int(b) for b in result_string])
    return result
    
def bin2hex(bit_array):
    results = map(str, bit_array)
    bit_string = ''.join(results)
    x =len(bit_string)/4
    y = "%0" +str(x)+"x"
    hex_string = y % int(bit_string, 2)
    return hex_string

# check key length
def check_key_length(key):
    if len(key) != BLOCK_SIZE:
        raise ValueError("DES Key size not valid, it should be 8 Bytes long.\n")
    else:
        print("Input Key is valid.\n")

# check input is not empty:
def check_input(data):
    if not data:
        raise ValueError("Input cannot be empty.")
    else:
        print("Input data is valid.")


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
        byte = bits[b * 8:(b + 1) * 8]  # byte = 8 bits, 0-7, 8-15...
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


# apply DES matrix to an input.
def matrix_apply(input, matrix):
    output = [0] * len(matrix)
    for cont in range(len(matrix)):
        output[cont] = input[matrix[cont]]
    return output

#XOR operation of two arrays
def xor(input1,input2):
    '''
    input1 and input2 should have the same length, otherwise this function raise an error.
    #other way to make XOR:
    # for i in range (len(a)):
    #     y[i] = a[i]+b[i]
    #     if y[i] == 2:
    #         y[i] = 0
    # print y
    '''
    if len(input1) != len(input2):
        raise ValueError("Inputs should have the same lenght.")
        return 0
    output = [0]*len(input1)

    for j in range(len(input1)):
        output[j] = input1[j] ^ input2[j]
    return output


# *********************************************************************************
# Key Related Operations
# *********************************************************************************

# apply Matrix Permuted Choice 1 (pc1)
def key_expansion(key_binary):
    """
    binary_key: key in binary
    key_pc1:    key after permutating with pc1
    c:          [0] first 28 bits of pc1, [1] after first left shift, [2] after second left shift,...
    d:          [0] last 28 bits of pc1, [1] after first left shift, [2] after second left shift,...
    key_middle: array (size of pc2), is the result of applying pc2 to c+d, is filled element by element in a for loop.
    kn:         list of lists [k1,k2,...,k16], size of each k: 48bits. kn[0] = k1, ...

    ****
    TEST
    ****
    test key_expansion with this example. (have the step by step guide of this example in my class notebook).
    input = [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0,
            1, 0,0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1])
    """
    kn = [[0] * 48] * 16  # initializing a list of arrays(k1-k16)
    # apply permuted choice1
    key_pc1 = matrix_apply(key_binary, m.pc1)
    c = key_pc1[:28]
    # print "c is ", c
    d = key_pc1[28:]
    # print "d is: ", d
    for i_cont in range(len(m.left_shifts)):
        # other way to shift. define shift function separate and make the call here.
        # def left_shifting(array_to_shift, number_of_shifts):
        # return array_to_shift[number_of_shifts:] + array_to_shift[:number_of_shifts]
        # make the call
        # left_shifting(c,m.left_shifts[i_cont])
        # left_shifting(d,m.left_shifts[i_cont])

        # shift c and d:
        for j in range(m.left_shifts[i_cont]):
            c.append(c[0])
            d.append(d[0])
            del c[0]
            del d[0]

        # apply pc2 for all k1-k16
        cd = c + d
        key_middle = matrix_apply(cd, m.pc2)
        kn[i_cont] = key_middle
        # test
        # print 'This is kn of ', i_cont, kn[i_cont]
        # print 'key_middle:     ', key_middle
        # print 'this is kn', kn
        # print "\n"
    return kn


# *********************************************************************************
# Cipher/Decipher Related Operations
# *********************************************************************************

# Split data in blocks and call cipher_decipher_block
def ciphering_deciphering_data(data,key,mode):
    # cipher_decipher_block(block,kn,mode):
    check_input(data)
    check_key_length(key)
    binary_key = hex2bin(key)
    kn = key_expansion(binary_key)
    
    if mode == "cipher":
        data = add_padding(data)
        bits = hex2bin(data)
    else:
        bits = hex2bin(data)
    
    print "Mode selected is",mode,"\n"
    data_output = [] # this will be all data cipher/decipher in string.
    i = 0
    progress_block = 1
    
    while i < (len(bits)): #/2 because it is in hex, 2hex=1B
        block = bits[i:i+64]  # +64 because it is in bits 64bits = 8Bytes = 8 characters = 1block
        print "In progress Block #", progress_block
        time.sleep(1)
        block_output = cipher_decipher_block(block,kn,mode)
        #print "mi blok",block_output
        block_output_string = bin2hex(block_output)
        
        #data_output = data_output + block_output_string
        data_output.append(block_output_string)
        i = i + 64  # 64bits, 1 block in bits
        progress_block = progress_block + 1
    # print data_output
    if mode == "decipher":
        data_output = ''.join(data_output)
        data_output = remove_padding(data_output)
        return data_output
    else:
        
        return ''.join(data_output)


def cipher_decipher_block(block,kn,mode):
    """
    Chyper or Decypher JUST 1 BLOCK of data.
    mode:               Cipher/Decipher
    block:              block to Cipher/Decipher
    block_ip:           block after Initial Permutation (ip)
    left:               first 32bits after applying ip matrix to the block
    right:              last 32bits after applying ip matrix to the block
    right_change:       coppy of "right" to make L1=R0 (R0=right_change).
    right_expansion:    output of applying Expansion table to right(R)
    xor:                function for calculating xor. xor(input1,input2)
    xor_output:         output of function xor.
    f:                  function "F".
    des_iteration:      stores the value of first iteration (0 if cipher, 15 if decipher)
    des_adder:          used to add or subtract from des_iteration.(add if cipher, subtract if decipher)
    """
    if mode == "cipher":
        des_iteration = 0
        des_adder = 1
    elif mode =="decipher":
        des_iteration = 15
        des_adder = -1
    else:
        raise ValueError("given DES mode is wrong. modes: cipher or decipher")


    # apply initial permutation to input text
    block_ip = matrix_apply(block,m.ip)
    left = block_ip[:32]
    right = block_ip[32:]
    # right_change = right  # later, L1=R0, so we have this to make that change
    i = 0
    while i < 16: #16 iterations, for cipher and decipher
        right_change = right  # later, L1=R0, so we have this to make that change
  
        ## CALCULATE cipher function "f".
        # 1. right expansion
         # 2. XOR of #1. and k[i]
        # 3. Selection (S-Boxes) to compress #2.
        # 4. Permutation (P) matrix

        # 1. apply Expansion table to R
        right_expansion = matrix_apply(right,m.expansion_table)
        #print "EXPANSIOOON", right_expansion
    # 2. XOR of right_expansion and kn[i]
        xor_output = [0]*len(right_expansion)
        xor_output = xor(right_expansion,kn[des_iteration])
        #print "xor_output", xor_output
        # 3. apply S-Boxes for compression of #2.
        sbox_input = [xor_output[:6], xor_output[6:12], xor_output[12:18],xor_output[18:24], xor_output[24:30], xor_output[30:36], xor_output[36:42], xor_output[42:]]
        #print "sbox_input",sbox_input
        
        sbox_output = [0] * 32
        position = 0
        for k in range(len(sbox_input)):
            # get the index of the row
            sbox_row = (sbox_input[k][0] << 1) + sbox_input[k][5]  # this is to change from binary to decimal: e.g.
            # a<<1 =2^a (bin:...84210) now we have a number between 0 and 3 which is the index of the "S-box row".

            # same as above, a<<3 = a*2^3, a<<2 = a*2^2 + a<<1 = a*2^1 and a = a || this stands for the hex value
            # bits(1-4) of xor_output.
            sbox_column = (sbox_input[k][1] << 3) + (sbox_input[k][2] << 2) + (sbox_input[k][3] << 1) + sbox_input[k][4]
           
            # use the sbox matrix to compress. access to the element with <<4, so if sbox_row = 0, this is 0,
            # if it is 1, then it is 16 (second row), if it is 2, then it is 32 (third row)
            v =m.sbox[k][(sbox_row << 4) + sbox_column]
            # print "SBOX #",k
            # print "row:   ",sbox_row
            # print "column:",sbox_column
            # print "Sbox:  ",v
            # print "\n"

            # from decimal to bits the same way as above. a>>3 is divide a by 2**3
            sbox_output[position] = (v & 8) >> 3
            # print sbox_output[position]
            sbox_output[position + 1] = (v & 4) >> 2
            # print sbox_output[position+1]
            sbox_output[position + 2] = (v & 2) >> 1
            # print sbox_output[position+2]
            sbox_output[position + 3] = v & 1
            # print sbox_output[position+3]
            position += 4
            #print "SBOX_OUTPUT",sbox_output
        # 4. Apply permutation matrix P
        f = matrix_apply(sbox_output,m.p)
        right = xor(f, left)
        # print "XOOOOOR F:",i,bin2hex(right)
        left = right_change
        i = i + 1
        des_iteration = des_iteration + des_adder
    
    # final operation:  Inverse initial Permutation (IP^-1)
    # right + left: this is to get ready for decipher after or cipher (DES Standard FIGURE 1: Enciphering computation)
      
    des_output = matrix_apply(right+left,m.inv_ip)
    return des_output






data = "0123456789abcdef0123456789abcdef"
key = "0123456789abcdef"

# cipher all data
ciphered = ciphering_deciphering_data(data,key,"cipher")
print  "\n","Ciphered Data:",ciphered,"\n"

#decipher all data
deciphered = ciphering_deciphering_data(ciphered,key,"decipher")
print "deciphered Data:",deciphered


#cipher first block
data_bin = hex2bin(data)
key_bin = hex2bin(key)
kn = key_expansion(key_bin)
ciphered_block = bin2hex(cipher_decipher_block(data_bin,kn,"cipher"))
print "\n","ciphered block:",ciphered_block

#decipher first block
bin_ciphered_block = hex2bin(ciphered_block)
deciphered_block = cipher_decipher_block(bin_ciphered_block,kn,"decipher")
print "deciphered block:",bin2hex(deciphered_block)







#######################################################################################################################
# TEST ALL DES.
# key_expansion IS WORKING
#key_binary = hex2bin(key)
# print "key binary:", key_binary
#kn = key_expansion(key_binary)
# print "kn[0]",kn[0]
#hexkn0 = bin2hex(kn[0])
# print "hex kn[0]",hexkn0

# IP is WORKING (checked with class exercise (l0, R0 in class exercise)
#data_bin = hex2bin(data)
#ip= matrix_apply(data_bin,m.ip)
# print ip
# print bin2hex(ip)

#******************
#THINGS THAT ARE OK
#******************
#bin2hex
#hex2bin
#key_expansion (at least kn[0], we have its value from class exercise)
#EXPANSION, XOR( I mean xor_ouput), SBOX(sbox_output I mean), l1,R1 ARE WORKING

#check_key_length(key)
#check_input(text_plain)
#binary_key = string_to_bits(key)
# test key_expansion with an example. (have the step by step guide of this example in my class notebook).
# knn = key_expansion([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0,
# 1, 1, 1, 1, 0, 0, 0, 1, 0,0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1])

#block = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63 ]

#block = [0,0,0,0,1,1,1,1]
#kn =    [0,1,0,1,0,1,0,1]
#y = cipher_decipher_block(bits,kn,"cipher")

#######################################################################################################################


# TODO-me implement PKCS-5 in order to avoid problem with remove_padding (if text=12340, padded=>12340000, unpadded=>1234 with my actual function remove_padding). if PKCS-5 complicated to implement, just make a quick check in remove_padding: if textplain last char is the same as the set of padding be careful.
# TODO-me optimize add_padding and remove_padding
# TODO-me offer the option of getting key, data an so by terminal (maybe comment one of the options, by prompt or by code))
# TODO-me if use prompt key input it is necessary to change function check_key_length(key) so if key is wrong, have the chance to change it.

# TODO-me add compatibility with Python 3.x (most worry about string encoding in python3.x)
