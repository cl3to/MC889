from pysnow import *
from .utils import *

class SNOW3G(object):
    """UMTS secondary encryption / integrity protection algorithm
    It is a pseudo-random generator, working with:
        - 128 bits key and 128 bits initialization vector
        - delivering a stream of 32 bits words
    
    
    Generator initialization and keystream generation primitives are defined 
    with methods:
    
    _initialize(key [16 bytes], iv [16 bytes]) -> None
    
    _generate_keystream(length [uint32]) -> keystream

    LTE modes of operation (EEA1, EIA1) is supported as well: the only difference 
    is for EIA1, `bearer' is replacing `fresh' and has a max value of 31.
    EEA1 and EIA1 methods are defined:
    
    EEA1(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> data_out [bytes]
        
        an UMTS bearer is usually coded on 5 bits
        optional bitlen argument represents the length of data_in in bits
    
    EIA1(key [16 bytes], count [uint32], bearer [uint5], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> mac [4 bytes]
    """
    iv_size  = 16
    key_size = 16

    def _initialize(self, key, iv) -> None:
        try:
            snow_initialize(key, iv)
        except ValueError as err:
            raise(CMException(err))

    def _generate_keystream(self, length):
        if not 0 <= length < MAX_UINT32:
            raise(CMException('invalid args'))

        lw = length >> 2
        if length % 4:
            lastbytes = True
            lw += 1
        else:
            lastbytes = False

        try:
            if lastbytes:
                return snow_generatekeystream(lw)[:length]
            else:
                return snow_generatekeystream(lw)
        except ValueError as err:
            raise(CMException(err))

    def EEA1(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer < MAX_UINT32:
            raise(CMException('invalid args'))

        if bitlen is None:
            bitlen = 8*len(data_in)

        try:
            return snow_f8(key, count, bearer, dir, data_in, bitlen)
        except ValueError as err:
            raise(CMException(err))

    def EIA1(self, key, count, bearer, dir, data_in, bitlen=None):
        if not 0 <= bearer < 32:
            raise(CMException('invalid args'))

        try:
            return self.F9(key, count, bearer<<27, dir, data_in, bitlen)
        except (ValueError, CMException) as err:
            raise(CMException(err))    