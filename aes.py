#!/usr/bin/python #

#CSCD27 Assignment 1
#Eric Ren: 999661575 reneric
#Man Xu: 999586755 xuman2

''' Compiler/OS Used: cygwin Win7
    Sources Used: BitVector documentation, NIST AES-spec appendix for tests
'''

import sys
import BitVector
import binascii
import copy

rounds = 10  # 128-bit AES uses 10 rounds

''' S-box for use in encryption '''
sbox = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
       [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
       [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
       [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
       [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
       [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
       [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
       [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
       [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
       [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
       [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
       [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
       [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
       [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
       [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
       [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]

''' inverse S-box for use in decryption '''
sboxinv = [[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
          [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
          [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
          [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
          [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
          [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
          [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
          [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
          [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
          [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
          [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
          [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
          [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
          [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
          [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
          [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]]

''' rcon is a table of round constants used to compute the key schedule '''
rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d]

''' HELPER functions (you are free to use or ignore these)'''

def bv_hex_str(bv):
    ''' DEBUG HELPER to convert BitVector value bv to a hex string '''
    cstr = ""
    for n in range((len(bv)/8)):
        c = chr(bv[n*8:n*8+8].intValue())
        cstr += c
    return binascii.hexlify(cstr)

def print_state(state_array, label = " "):
    ''' DEBUG HELPER to print a state_array, optionally with a label '''
    for col in state_array:
        psa = ""
        for row in col:
            psa += bv_hex_str(row)
            print (psa)
    print (label)

def state_str(state_array):
    ''' DEBUG HELPER to convert a state_array value to a hex string '''
    psa = ""
    for col in state_array:
        for row in col:
            psa += bv_hex_str(row)
    return psa
def state_str_p(state_array):
    ''' DEBUG HELPER to convert a state_array value to a hex string '''
    psa = ""
    for col in state_array:
        for row in col:
            psa += bv_hex_str(row)
        psa += " "
    return psa
def key_str(round_key):
    ''' DEBUG HELPER to convert a list of round key words to a hex string '''
    kstr = ""
    for word in round_key:
        kstr += bv_hex_str(word)
    return kstr

def key_bv(hex_key):
    ''' HELPER to convert a hex-string representation of a key to the
        equivalent BitVector value '''
    keybytes = binascii.a2b_hex(hex_key)  # hex string to byte string
    key_bv = BitVector.BitVector(size = 0) # initialize BitVector
    for byte in keybytes: 
        byte_bv = BitVector.BitVector(intVal=ord(byte), size=8) # one byte to add to BitVector
        key_bv += byte_bv # catenate new BitVector byte onto return value
    return key_bv

''' END of HELPER functions '''


def init_state_array(bv):
    ''' Return a state array corresponding to 128-bit BitVector param bv,
        where the state array is a column-ordered array (list) of 16 8-bit
    BitVector values, organized as 4 columns (sublists) each containing
    4 8-bit BitVector bytes, as shown on slide #17 '''
    output = []
    for i in range(4):
        col = []
        for j in range(4):
            col.append(bv[(i*32)+(j*8):(i*32)+(j*8)+8])
        output.append(col)
    return output


def sub_key_bytes(key_word):
    ''' Iterate through round-key key_word (4-byte word) performing sbox
        substitutions, returning the transformed round-key key_word '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 44-47
    w1 = sbox_lookup(key_word[0:8])
    w2 = sbox_lookup(key_word[8:16])
    w3 = sbox_lookup(key_word[16:24])

    w4 = sbox_lookup(key_word[24:])
    return w1+w2+w3+w4


def init_key_schedule(kb):
    '''key_bv is the 128-bit input key value represented as a BitVector; return
       key_schedule as an array of (4*(1+#rounds)) 32-bit BitVector words '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 44-47  
    key_schedule = []
    for i in range(4):
        key_schedule.append(kb[i*32:i*32+32])
    for i in range(4,(rounds+1)*4):
        temp = key_schedule[i-1]
        if (i % 4 == 0):
            temp = (sub_key_bytes((temp.deep_copy() << 8)) ^ (BitVector.BitVector(intVal=rcon[i/4],size=32) << 24))
        key_schedule.append(key_schedule[i-4] ^ temp)

    return key_schedule

def add_round_key(sa, rk):
    ''' XOR state array sa with roundkey rk to return new state array.
        param sa is a 4x4 state array, param rk is a 4-word round key '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 40-42  
    new_sa = []
    for col in range(len(sa)):
        new_col = []
        for row in range(len(sa[col])):
            new_col.append(sa[col][row] ^ rk[col][row*8:row*8+8])
        new_sa.append(new_col)
    return new_sa


def sbox_lookup(input):
    ''' Given an 8-bit BitVector input, look up the sbox value corresponding
        to that byte value, returning the sbox value as an 8-bit BitVector.  '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 18-20  
    row = int(input[0:4])
    col = int(input[4:])
    output = BitVector.BitVector(intVal=sbox[row][col],size=8)
    return output

def inv_sbox_lookup(input):
    ''' Given an 8-bit BitVector input, look up the sboxinv value corresponding
        to that byte, returning the sboxinv value as an 8-bit BitVector. '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 18-20   
    row = int(input[0:4])
    col = int(input[4:])
    output = BitVector.BitVector(intVal=sboxinv[row][col],size=8)
    return output

def sub_bytes(sa):
    ''' Iterate throught state array sa to perform sbox substitution 
    returning new state array. '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 18-20   
    new_sa = copy.deepcopy(sa)
    for c_i in range(len(sa)):
        for b_i in range(len(sa[c_i])):
            new_sa[c_i][b_i] = sbox_lookup(sa[c_i][b_i])
    return new_sa

def inv_sub_bytes(sa):
    ''' Iterate throught state array sa to perform inv-sbox substitution 
    returning new state array. '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 18-20   
    new_sa = copy.deepcopy(sa)
    for c_i in range(len(sa)):
        for b_i in range(len(sa[c_i])):
            new_sa[c_i][b_i] = inv_sbox_lookup(sa[c_i][b_i])
    return new_sa

def shift_bytes_left(bv, num):
    ''' Return the value of BitVector bv after rotating it to the left
        by num bytes'''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 30-32   
    res = copy.deepcopy(bv)
    return res << num*8

def shift_bytes_right(bv, num):
    ''' Return the value of BitVector bv after rotating it to the right
        by num bytes'''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 30-32
    res = copy.deepcopy(bv)
    return res >> num*8

def shift_rows(sa):
    ''' shift rows in state array sa to return new state array '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 30-32
    new_sa = copy.deepcopy(sa)
    for i in range(1,4):
        new_row = new_sa[0][i]+new_sa[1][i]+new_sa[2][i]+new_sa[3][i]
        new_row = shift_bytes_left(new_row,i)
        new_sa[0][i]=new_row[0:8]
        new_sa[1][i]=new_row[8:16]
        new_sa[2][i]=new_row[16:24]
        new_sa[3][i]=new_row[24:]
    return new_sa


def inv_shift_rows(sa):
    ''' shift rows on state array sa to return new state array '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 30-32
    new_sa = copy.deepcopy(sa)
    for i in range(1,4):
        new_row = new_sa[0][i]+new_sa[1][i]+new_sa[2][i]+new_sa[3][i]
        new_row = shift_bytes_right(new_row,i)
        new_sa[0][i]=new_row[0:8]
        new_sa[1][i]=new_row[8:16]
        new_sa[2][i]=new_row[16:24]
        new_sa[3][i]=new_row[24:]
    return new_sa


def gf_mult(bv, factor):
    ''' Used by mix_columns and inv_mix_columns to perform multiplication in
    GF(2^8).  param bv is an 8-bit BitVector, param factor is an integer.
        returns an 8-bit BitVector, whose value is bv*factor in GF(2^8) '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 33-36
    add_coefs = []
    bv_factor = BitVector.BitVector(size=8, intVal=factor)
    bv_irreducible = BitVector.BitVector(size=9, intVal=0x11b)
    # generate list of power-of-2 shifted bv values
    for i in range(bv_factor.size):
        if bv_factor[i] == 1:  # check if factor bit is a 1
            bv_bitmul = BitVector.BitVector(size=8, intVal=bv.intValue())
            bv_bitmul.pad_from_right(bv_factor.size-i-1)
            add_coefs.append(bv_bitmul)
    bv_mul = BitVector.BitVector(bitstring="")
    # add up the list of partial-results
    for i in range(len(add_coefs)):              
        bv_mul ^= add_coefs[i]
    bv_gfmul = copy.deepcopy(bv_mul)
    i = bv_gfmul.next_set_bit(0)
    while ((i != -1)&(i+8 < bv_gfmul.size)):
        bv_gfmul[i:i+9] = (bv_gfmul[i:i+9] ^ bv_irreducible)
        i = bv_gfmul.next_set_bit(0) 
    bv_result = BitVector.BitVector(size=8)
    bv_result = bv_gfmul[(bv_gfmul.size-8):bv_gfmul.size]
    return bv_result


    

def mix_columns(sa):
    ''' Mix columns on state array sa to return new state array '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 33-35   
    mixsa = []
    for colm in sa:
        mc0 = gf_mult(colm[0], 2) ^ gf_mult(colm[1], 3) ^ colm[2] ^ colm[3]
        mc1 = colm[0] ^ gf_mult(colm[1], 2) ^ gf_mult(colm[2], 3) ^ colm[3]
        mc2 = colm[0] ^ colm[1] ^ gf_mult(colm[2], 2) ^ gf_mult(colm[3], 3)
        mc3 = gf_mult(colm[0], 3) ^ colm[1] ^ colm[2] ^ gf_mult(colm[3], 2)
        mixsa.append([mc0, mc1, mc2, mc3])
    return mixsa
    

def inv_mix_columns(sa):
    ''' Inverse mix columns on state array sa to return new state array '''
    # ADD YOUR CODE HERE - SEE LEC SLIDE 36  
    
    invmix = []
    for colm in sa:
        mc0 = gf_mult(colm[0], 14) ^ gf_mult(colm[1], 11) \
            ^ gf_mult(colm[2], 13) ^ gf_mult(colm[3], 9)
        mc1 = gf_mult(colm[0], 9) ^ gf_mult(colm[1], 14) \
            ^ gf_mult(colm[2], 11) ^ gf_mult(colm[3], 13)
        mc2 = gf_mult(colm[0], 13) ^ gf_mult(colm[1], 9) \
            ^ gf_mult(colm[2], 14) ^ gf_mult(colm[3], 11)
        mc3 = gf_mult(colm[0], 11) ^ gf_mult(colm[1], 13) \
            ^ gf_mult(colm[2], 9) ^ gf_mult(colm[3], 14)
        invmix.append([mc0, mc1, mc2, mc3])
    return invmix

  
def encrypt(hex_key, hex_plaintext):
    ''' perform AES encryption using 128-bit hex_key on 128-bit plaintext 
        hex_plaintext, where both key and plaintext values are expressed
    in hexadecimal string notation. '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 14-15
    ks = init_key_schedule(key_bv(hex_key))
    sa = init_state_array(key_bv(hex_plaintext))
    sa = add_round_key(sa,ks[0:4])
    for i in range(1,rounds):
        sa = sub_bytes(sa)
        sa = shift_rows(sa)
        sa = mix_columns(sa)
        sa = add_round_key(sa,ks[4*i:4*i+4])
    sa = sub_bytes(sa)
    sa = shift_rows(sa)
    sa = add_round_key(sa,ks[4*rounds:4*rounds+4])
    return state_str(sa)




def decrypt(hex_key, hex_ciphertext):
    ''' perform AES decryption using 128-bit hex_key on 128-bit ciphertext
        hex_ciphertext, where both key and ciphertext values are expressed
    in hexadecimal string notation. '''
    # ADD YOUR CODE HERE - SEE LEC SLIDES 14-15
    ks = init_key_schedule(key_bv(hex_key))
    sa = init_state_array(key_bv(hex_ciphertext))
    sa = add_round_key(sa,ks[4*rounds:4*rounds+4])
    sa = inv_shift_rows(sa)
    sa = inv_sub_bytes(sa)
    for i in range(rounds-1,0,-1):
        sa = add_round_key(sa,ks[4*i:4*i+4])
        sa = inv_mix_columns(sa)
        sa = inv_shift_rows(sa)
        sa = inv_sub_bytes(sa)
    sa = add_round_key(sa,ks[0:4])
    return state_str(sa)


