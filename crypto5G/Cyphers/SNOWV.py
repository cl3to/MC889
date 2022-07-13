from snowv import *
from .utils import *

class SNOWV(object):

    key_size = 32
    iv_size = 16
    def _initializer(self, key, iv):
        try:
            snowv_initializer(key, iv)
        except ValueError as e:
            raise(CMException(e))

    def _keystream(self):
        try:
            return snowv_keystream()
        except ValueError as err:
            raise(CMException(err))

    def gcm_encript(self, key, iv, plaintxt, aad):
        if type(plaintxt) != bytes:
            plaintxt = bytes(plaintxt.encode('ascii'))
        
        if type(aad) != bytes:
            aad = bytes(aad.encode('ascii'))

        try:
            return snowv_gcm_encrypt(key, iv, plaintxt, aad)
        except ValueError as e:
            raise CMException(e)

    def gcm_decript(self, key, iv, ciphertxt, aad, mac):
        
        if type(ciphertxt) != bytes:
            ciphertxt = bytes(ciphertxt.encode('ascii'))
        
        if type(aad) != bytes:
            aad = bytes(aad.encode('ascii'))
        
        try:
            return snowv_gcm_decrypt(key, iv, ciphertxt, aad, mac)
        except ValueError as e:
            raise CMException(e)