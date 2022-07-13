MAX_UINT32 = 1<<32
MAX_UINT64 = 1<<64
    
def xor_buf(b1, b2):
    return bytes([b1[i]^b2[i] for i in range(0, min(len(b1), len(b2)))])

def int_from_bytes(b):
    return int.from_bytes(b, 'big')
    

# CryptoMobile-wide Exception handler
class CMException(Exception):
    """CryptoMobile specific exception
    """
    pass
