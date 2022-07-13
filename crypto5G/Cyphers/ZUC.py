from pyzuc import *
from .utils import *

class ZUC(object):
    """LTE 3rd encryption / integrity protection algorithm
    It is a pseudo-random generator, working with:
        - 128 bits key and 128 bits initialization vector
        - delivering a stream of 32 bits words
    
    
    Generator initialization and keystream generation primitives are defined 
    with methods:
    
    _initialize(key [16 bytes], iv [16 bytes]) -> None
    
    _generate_keystream(length [uint32]) -> keystream [bytes]
    
    
    For securing packets at the LTE PDCP and NAS layers, LTE modes of operation
    are defined in EEA3 and EIA3 methods:
    
    EEA3(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> data_out [bytes]
        
        an LTE bearer is usually coded on 5 bits
        optional bitlen argument represents the length of data_in in bits
    
    EIA3(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> mac [4 bytes]
        
        optional bitlen argument represents the length of data_in in bits
    """
    iv_size  = 16
    key_size = 16
    
    def _initialize(self, key, iv):
        try:
            zuc_initialization(key, iv)
        except ValueError as err:
            raise(CMException(err))
    
    def _generate_keystream(self, length):
        if not 0 <= length < MAX_UINT32:
            raise(CMException('invalid args'))
        #
        lw = length >> 2
        if length % 4:
            lastbytes = True
            lw += 1
        else:
            lastbytes = False
        #
        try:
            if lastbytes:
                return zuc_generatekeystream(lw)[:length]
            else:
                return zuc_generatekeystream(lw)
        except ValueError as err:
            raise(CMException(err))
    
    def EEA3(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer < 32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
        #
        try:
            return zuc_eea3(key, count, bearer, dir, bitlen, data_in)
        except ValueError as err:
            raise(CMException(err))
    
    def EIA3(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer < 32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
        #
        try:
            return zuc_eia3(key, count, bearer, dir, bitlen, data_in)
        except ValueError as err:
            raise(CMException(err))
