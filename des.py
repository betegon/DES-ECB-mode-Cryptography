"""
key => key we will use to chyper and decypher

plaintext => text to cypher/decypher
"""

import matrices as m

# CONSTANTS
BLOCK_SIZE = 8  # Block size of DES = 8Bytes=64bits
PADDING = "0"   # we will fill the plaintext with 0s  if needed


# check key length
def check_key_length(key):
    if len(key) != 8:
        raise ValueError("DES Key size not valid, it should be 8 Bytes long.\n")
    else:
        print("Input Key is valid.")


# check input is not empty:
def check_input(data):
    if not data:
        raise ValueError("Input cannot be empty.")
    else:
        print("Input data is valid.\n")


# add padding to text
def add_padding(text):
    if len(text) % BLOCK_SIZE != 0:
        while len(text) % BLOCK_SIZE != 0:
            text += PADDING

    return text


# remove paading to paddedtext 
def remove_padding(text):
    text = text[:-BLOCK_SIZE] + text[-BLOCK_SIZE:].rstrip(PADDING)
    return text


key = "01234567"  # NOT hex, normal string.
plaintext = "holaholaa"
check_key_length(key)
check_input(plaintext)
textpadded = add_padding(plaintext)
print("original text: " + plaintext)
print("text padded:   " + textpadded)
textunppaded = remove_padding(textpadded)
print("text unppaded: " + textunppaded)

# IDEA TO CHANGE FROM ASCII(strings in python2) TO binary
#  key_bin = ''.join(format(ord(x),'b') for x in key)  # change from string to bits
#  print(key_bin)
# print(key.encode("hex"))
#  print("holi".encode("hex"))



# TODO-me inverse naming: text_plain,text_padded, text_unpadder
# TODO-me implement PKCS-5 in order to avoid problem with remove_padding (if text=12340, padded=>12340000, unpadded=>1234 with my actual function remove_padding). if PKCS-5 complicated to implement, just make a quick check in remove_padding: if mes
# TODO-me optimize add_padding and remove_padding
# TODO-me offer the option of getting key, data an so by terminal (maybe comment one of the options, by prompt or by code))
# TODO-me if use prompt key input it is necessary to change function check_key_length(key) so if key is wrong, have the chance to change it.
# TODO-me key should be input as hex? check it out.
# TODO-me add compatibility with Python 3.x (most worry about string encoding in python3.x)
