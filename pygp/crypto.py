# here is the interface for crypto.
# we will define all crypto functions we need
# and redirect to the open source project we select
# candidates are pycrypto 2.6.1, cryptography 1.7.1
from pygp.utils import *
from pygp.constants import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import cmac



# 8 bytes long NULL ICV
ICV_NULL_8 = '0000000000000000'
ICV_NULL_16 = '00000000000000000000000000000000'

def RANDOM(bloc_size = 8):
    ''' 
    Returns a block_size long random str
    '''
    import os
    rand = os.urandom(bloc_size)
    return rand.hex().upper() 

def ISO_9797_M1_Padding_left(data, bloc_size = 8):
    ''' 
    Performs a ISO_9797_M1 Padding by left.
    This padding is done in the following way: before the original data null bytes is added 
    in order for the whole block to have a length in bytes that is a multiple of 8
    If original data length is already a multiple of 8, no padding is needed
    '''
    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    # Perform padding
    _data_padd  = data
    while ( ( (len (_data_padd)/2) % bloc_size) != 0):
        _data_padd = '00' + _data_padd
    return(_data_padd)

def ISO_9797_M1_Padding(data, bloc_size = 8):
    ''' 
    Performs a ISO_9797_M1 Padding.
    This padding is done in the following way: after the original data null bytes is added 
    in order for the whole block to have a length in bytes that is a multiple of 8
    If original data length is already a multiple of 8, no padding is needed
    '''
    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    # Perform padding
    _data_padd  = data
    while ( ( (len (_data_padd)/2) % bloc_size) != 0):
        _data_padd = _data_padd + '00'
    return(_data_padd)

def ISO_9797_M1_Padding(data, bloc_size = 8):
    ''' 
    Performs a ISO_9797_M1 Padding.
    This padding is done in the following way: after the original data null bytes is added 
    in order for the whole block to have a length in bytes that is a multiple of 8
    If original data length is already a multiple of 8, no padding is needed
    '''
    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    # Perform padding
    _data_padd  = data
    while ( ( (len (_data_padd)/2) % bloc_size) != 0):
        _data_padd = _data_padd + '00'
    return(_data_padd)

def ISO_9797_M2_Padding(data, bloc_size = 8):
    ''' 
    Performs a ISO_9797_M2 Padding.
    This padding is done in the following way: after the original data a byte '80' is added.
    Then, in order for the whole block to have a length in bytes that is a multiple of 8, null bytes can be added
    (null bytes are optional and not present in case the length is already a multiple of 8)
    '''

    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    # Perform padding
    _data_padd  = data + '80'
    while ( ( (len (_data_padd)/2) % bloc_size) != 0):
        _data_padd = _data_padd + '00'
    return(_data_padd)


def DES_CBC(data, key, iv="0000000000000000"):
    ''' redirect to the selected crypto lib'''
    # pad data if needed
    #TODO: maybe check the key size or take only the first 8 bytes ?
    return DES3_CBC(data, key, iv)

def DES_INV_CBC(data, key, iv="0000000000000000"):
    ''' redirect to the selected crypto lib'''
    #TODO: maybe check the key size or take only the first 8 bytes ?
    return DES3_INV_CBC(data, key, iv)

def DES_ECB(data, key):
    ''' redirect to the selected crypto lib'''
    #TODO: maybe check the key size or take only the first 8 bytes ?
    return DES3_ECB(data, key)

def DES_INV_ECB(data, key):
    ''' redirect to the selected crypto lib'''
    #TODO: maybe check the key size or take only the first 8 bytes ?
    return DES3_INV_ECB(data, key)

def DES3_CBC(data, key, iv="0000000000000000"):
    ''' redirect to the selected crypto lib'''
    # pad data if needed
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    iv_bytes  = bytes.fromhex(iv)
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()
    return ct.hex().upper() 

def DES3_INV_CBC(data, key, iv="0000000000000000"):
    ''' redirect to the selected crypto lib'''
    # pad data if needed
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    iv_bytes  = bytes.fromhex(iv)
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = decryptor.update(data_bytes) + decryptor.finalize()
    return ct.hex().upper() 

def DES3_ECB(data, key):
    ''' redirect to the selected crypto lib'''
    # pad data if needed
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()
    return ct.hex().upper() 

def DES3_INV_ECB(data, key):
    ''' redirect to the selected crypto lib'''
    # pad data if needed
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = decryptor.update(data_bytes) + decryptor.finalize()
    return ct.hex().upper() 

def AES_CMAC(data, key):
    
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    c = cmac.CMAC(algorithms.AES(key_bytes), backend=default_backend())
    c.update(data_bytes)
    ct = c.finalize()
    return ct.hex().upper()

def AES_ECB(data, key):
    ''' redirect to the selected crypto lib'''
    # pad data if needed
    data = ISO_9797_M1_Padding(data, 16)
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()
    return ct.hex().upper()


def AES_CBC(data, key, iv="00000000000000000000000000000000"):
    ''' redirect to the selected crypto lib'''
    # pad data if needed
    data = ISO_9797_M1_Padding(data, 16)
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    iv_bytes  = bytes.fromhex(iv)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()
    return ct.hex().upper()

def AES_INV_ECB(data, key):
    ''' redirect to the selected crypto lib'''
    # pad data if needed
    data = ISO_9797_M1_Padding(data, 16)
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = decryptor.update(data_bytes) + decryptor.finalize()
    return ct.hex().upper()


def AES_INV_CBC(data, key, iv="00000000000000000000000000000000"):
    ''' redirect to the selected crypto lib'''
    # pad data if needed
    data = ISO_9797_M1_Padding(data, 16)
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    iv_bytes  = bytes.fromhex(iv)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = decryptor.update(data_bytes) + decryptor.finalize()
    return ct.hex().upper()


def MAC33(data, key, iv="0000000000000000"):
    ''' redirect to the selected crypto lib'''
    value = DES3_CBC(data, key, iv)
    return value[-16:]

def MAC3(data, key, iv="0000000000000000"):
    ''' redirect to the selected crypto lib'''
    # must check the key size
    # remove space if any
    import re
    key = ''.join( re.split( '\W+', key.upper() ) )
    if len(key) < 16*2:
        raise BaseException("Invalid key length for the MAC3 operation")

    value = DES_CBC(data, key[0:16], iv)
    value = DES_INV_ECB(value[-16:], key[16:32])
    value = DES_ECB(value, key[0:16])
    return value[-16:]

def MAC(data, key, iv="0000000000000000"):
    ''' redirect to the selected crypto lib'''
    value = DES_CBC(data, key, iv)
    return value[-16:]