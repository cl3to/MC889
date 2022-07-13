from Cyphers.AES import AES_3GPP as AES
from Cyphers.SNOW3G import SNOW3G
from Cyphers.ZUC import ZUC
from Cyphers.SNOWV import SNOWV

with open('benchmark/plaintxt.txt', 'rb') as file:
    data = file.read()

dsize = len(data)

size_64 = 1 << 6
size_256 = 1 << 8
size_1024 = 1 << 10
size_2048 = 1 << 11
size_4096 = 1 << 12
size_8192 = 1 << 13
size_16384 = 1 << 14

def aes_enc(size):
    aes = AES()
    key     = b'\xd3\xc5\xd5\x922\x7f\xb1\x1c@5\xc6h\n\xf8\xc6\xd1'
    count   = 0x398a59b4 
    bearer  = 0x15
    direct  = 1
    plaintxt = data[:size]
    bitlen = size*8
    return aes.EEA2(key, count, bearer, direct, plaintxt, bitlen)


def zuc_enc(size):
    zuc = ZUC()
    key     = b'\xd3\xc5\xd5\x922\x7f\xb1\x1c@5\xc6h\n\xf8\xc6\xd1'
    count   = 0x398a59b4 
    bearer  = 0x15
    direct  = 1
    plaintxt = data[:size]
    bitlen = size*8
    return zuc.EEA3(key, count, bearer, direct, plaintxt, bitlen)

def snow3g_enc(size):
    snow3g = SNOW3G()
    key     = b'\xd3\xc5\xd5\x922\x7f\xb1\x1c@5\xc6h\n\xf8\xc6\xd1'
    count   = 0x398a59b4 
    bearer  = 0x15
    direct  = 1
    plaintxt = data[:size]
    bitlen = size*8
    return snow3g.EEA1(key, count, bearer, direct, plaintxt, bitlen)

def snowv_enc(size):
    snowv = SNOWV()
    key = bytes.fromhex('505152535455565758595a5b5c5d5e5f0a1a2a3a4a5a6a7a8a9aaabacadaeafa')
    iv = bytes.fromhex('0123456789abcdeffedcba9876543210')
    aad = bytes.fromhex('30313233343536373839616263646566')
    plaintxt = data[:size]
    ciphertxt, mac =  snowv.gcm_encript(key, iv, plaintxt, aad)
    #p2 = snowv.gcm_decript(key, iv, ciphertxt, aad, mac)
    return ciphertxt, mac

