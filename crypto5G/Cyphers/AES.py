from .utils import *
from Crypto.Cipher import AES
from struct import pack, unpack


class CMAC(object):
    """CMAC mode of operation as defined by NIST
    to be used with a block cipher
    
    Initialize with the key, block-cipher function and optionally MAC length.
    Run it with cmac() on the data to process.
    It returns the MAC of the expected length.
    
    e.g.
    >>> cmac = CMAC(16*b'A', AES, Tlen=64)
    >>> cmac.cmac(200*b'testing ')
    b'\xe0*\xf5x\x14\xbc\x13\x96'
    """
    
    def __init__(self, key, ciphermod, Tlen=None):
        """
        key [X bytes]: key used by the cipher algorithm set in `ciphermod'
            length X must correspond to the given ciphermod key length
        ciphermod [encryption module]: block-cipher algorithm
            must have `block_size' attribute and `__init__(key)' method,
            which returns an instance with an `encrypt(data_in)' method
        Tlen [int, optional]: requested MAC length (in bits)
        """
        # set the key
        self.key = key
        # init block cipher
        try:
            self.__init_cipher(ciphermod)
        except Exception as err:
            raise(CMException('invalid ciphermod arg, ', err))
        # schedule it (defines self.K1 and self.K2 [16 bytes])
        self.__keyschedule()
        # set MAC length
        if Tlen is None:
            self.Tlen = 8*self._blocksize
        elif not 0 < Tlen <= 8*self._blocksize:
            raise(CMException('invalid args'))
        else:
            self.Tlen = Tlen
    
    def __init_cipher(self, ciphermod):
        # set block-cipher and block size (in bits)
        self._ciphermod = ciphermod
        self._blocksize = ciphermod.block_size
        # init ECB-mode block cipher
        self._cipher = ciphermod(self.key)
        # link to its encrypt() method
        self._encrypt = self._cipher.encrypt
        
    def __keyschedule(self):
        # schedule the key for potential padding
        # encrypt a zero input block
        L = self._encrypt(b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0')
        # schedule depending of the MSB of L
        # python-fu: unpack the 128 bits register as 2 BE uint64
        Lh, Ll = unpack('>QQ', L)
        # sum both uint64 as an uint128, left-shift and filter
        K1 = (((Lh<<64)+Ll) << 1) & 0xffffffffffffffffffffffffffffffff
        # XOR K1 depending of the MSB of L
        if Lh & 0x8000000000000000:
             K1 ^= 0x87
        # re-shift K1 to make K2
        K2 = (K1 << 1) & 0xffffffffffffffffffffffffffffffff
        # XOR K2 depending of the MSB of K1
        if K1 & 0x80000000000000000000000000000000:
            K2 ^= 0x87
        # set 2 corresponding 16-bytes strings K1, K2
        self.K1 = pack('>QQ', K1>>64, K1%MAX_UINT64)
        self.K2 = pack('>QQ', K2>>64, K2%MAX_UINT64)
    
    def cmac(self, data_in, data_len=None):
        """Computes the CBC-MAC over data_in, according to initialization 
        information
        
        data_in [bytes]
        data_len [int, optional]: length in bits of data_in, over wich the mac
            is computed
        """
        # prepare the input data according to the requested length (in bits)
        # of input data to be processed
        len_data_in = 8 * len(data_in)
        if data_len is None:
            data_len = len_data_in
            lastbits = 0
        elif not 0 < data_len <= len_data_in:
            raise(CMException('invalid args'))
        elif data_len < len_data_in:
            # truncate data_in according to data_len
            olen = data_len>>3
            lastbits = (8-(data_len%8))%8
            if lastbits:
                # zero last bits after data_len
                data_in = data_in[:olen] + bytes( [data_in[olen] & (0x100-(1<<lastbits))] )
            else:
                data_in = data_in[:olen]
        else:
            lastbits = 0
        # data_in is splitted into Mn parts according to the block size of the ciphermod
        M = [data_in[i:i+self._blocksize] for i in range(0, len(data_in), self._blocksize)]
        if M:
            Mn = M.pop()
            Mnlen = data_len % (8*self._blocksize)
            if Mnlen:
                # M not blocksize-aligned
                # NIST'way to pad: (Mn*||10^j)^K2, j = n*b-Mlen-1 ...
                if lastbits:
                    # switch the 1st padding bit to 1 into the last byte of Mn
                    Mn = Mn[:-1] + bytes( [Mn[-1] + (1<<(lastbits-1))] )
                else:
                    # pad with an initial byte 0x80
                    Mn += b'\x80'
                # then pad with 0
                Mn += (16-1-(Mnlen>>3)) * b'\0'
                # xor Mn with K2
                Mn = xor_buf(Mn, self.K2)
            else:
                # M is blocksize-aligned
                # xor Mn with K1
                Mn = xor_buf(Mn, self.K1)
        else:
            # empty data_in...
            Mn = xor_buf(b'\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', self.K2)
        M.append(Mn)
        # loop over the blocks to MAC all of them
        C = self._blocksize * b'\0'
        for Mi in M:
            C = self._encrypt(xor_buf(C, Mi))
        if self.Tlen == self._blocksize:
            return C
        else:
            # truncate C
            olen = self.Tlen>>3
            T = C[:olen]
            if self.Tlen % 8:
                # zero last bits of T
                lastbits = (8-(self.Tlen%8))%8
                return T + bytes([C[olen] & (0x100 - (1<<lastbits))])
            else:
                return T



class AES_CTR(object):
    block_size = 16

    def __init__(self, key, nonce, cnt=0) -> None:
        """initialize AES in ECB mode with the given key and nonce buffer
        
        key  : 16 bytes buffer
        nonce: 8 most significant bytes buffer of the counter initial value
               counter will be incremented starting at 0
        cnt  : uint64, 8 least significant bytes value of the counter
               default is 0
        """
        self.__aes = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=cnt, use_aesni=False)

    def encrypt(self, data):
        """encrypt / decrypt data with the key and IV set at initialization"""
        return self.__aes.encrypt(data)

    decrypt = encrypt


class AES_ECB(object):
    """AES in ECB mode"""
    
    block_size = 16
    
    def __init__(self, key):
        """initialize AES in ECB mode with the given key"""
        self.aes = AES.new(key, AES.MODE_ECB)
    
    def encrypt(self, data):
        """encrypt data with the key set at initialization"""
        return self.aes.encrypt(data)


class AES_3GPP(object):
    """LTE 2nd encryption / integrity protection algorithm
    It is using AES with 128 bit key in CTR encryption mode and CBC-MAC integrity
    protection mode.
    
    For securing packets at the LTE PDCP and NAS layers, LTE modes of operation
    are defined in EEA2 and EIA2 methods:
    
    EEA2(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> data_out [bytes]
        
        an LTE bearer is usually coded on 5 bits
        optional bitlen argument represents the length of data_in in bits
    
    EIA2(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> mac [4 bytes]
        
        optional bitlen argument represents the length of data_in in bits
    """
    
    def EEA2(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer <= 32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
            lastbits = None
        else:
            lastbits = (8-(bitlen%8))%8
            blen = bitlen >> 3
            if lastbits:
                blen += 1
            if blen < len(data_in):
                data_in = data_in[:blen]
        #
        nonce = pack('>II', count, (bearer<<27)+(dir<<26))
        enc = AES_CTR(key, nonce).encrypt(data_in)
        #
        if lastbits:
            return enc[:-1] + bytes([enc[-1] & (0x100 - (1<<lastbits))])
        else:
            return enc
    
    def EIA2(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer <= 32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
        else:
            lastbits = (8-(bitlen%8))%8
            blen = bitlen >> 3
            if lastbits:
                blen += 1
            if blen < len(data_in):
                data_in = data_in[:blen]
        #
        M = pack('>II', count, (bearer<<27)+(dir<<26)) + data_in
        cmac = CMAC(key, AES_ECB, Tlen=32)
        return cmac.cmac(M, 64+bitlen)