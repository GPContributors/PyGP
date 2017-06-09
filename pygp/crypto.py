# here is the interface for crypto.
# we will define all crypto functions we need
# and redirect to the open source project cryptography
from pygp.utils import *
from pygp.constants import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asymmetric_utils
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography import utils



@utils.register_interface(ec.EllipticCurve)
class NISTP384R1(object):
    name = "secp384r1"
    key_size = 384

@utils.register_interface(ec.EllipticCurve)
class NISTP521R1(object):
    name = "secp521r1"
    key_size = 521

@utils.register_interface(ec.EllipticCurve)
class NISTP256R1(object):
    name = "secp256r1"
    key_size = 256

@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP192R1(object):
    name = "brainpoolP192r1"
    key_size = 192

@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP192T1(object):
    name = "brainpoolP192t1"
    key_size = 192

@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP256R1(object):
    name = "brainpoolP256r1"
    key_size = 256

@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP256T1(object):
    name = "brainpoolP256t1"
    key_size = 256

@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP384R1(object):
    name = "brainpoolP384r1"
    key_size = 384

@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP384T1(object):
    name = "brainpoolP384t1"
    key_size = 384

@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP512R1(object):
    name = "brainpoolP512r1"
    key_size = 512

@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP512T1(object):
    name = "brainpoolP512t1"
    key_size = 512


ec._CURVE_TYPES['nistP384r1'] = NISTP384R1
ec._CURVE_TYPES['nistP521r1'] = NISTP521R1
ec._CURVE_TYPES['nistP256r1'] = NISTP256R1
ec._CURVE_TYPES['brainpoolP192r1'] = BRAINPOOLP192R1
ec._CURVE_TYPES['brainpoolP192t1'] = BRAINPOOLP192T1
ec._CURVE_TYPES['brainpoolP256r1'] = BRAINPOOLP256R1
ec._CURVE_TYPES['brainpoolP256t1'] = BRAINPOOLP256T1
ec._CURVE_TYPES['brainpoolP384r1'] = BRAINPOOLP384R1
ec._CURVE_TYPES['brainpoolP384t1'] = BRAINPOOLP384T1
ec._CURVE_TYPES['brainpoolP512r1'] = BRAINPOOLP512R1
ec._CURVE_TYPES['brainpoolP512t1'] = BRAINPOOLP512T1

# 8 bytes long NULL ICV
ICV_NULL_8 = '0000000000000000'
ICV_NULL_16 = '00000000000000000000000000000000'

def RANDOM(bloc_size = 8):
    ''' 
        Returns a block_size long random hexadecimal string
        
        :param int bloc_size: the size in bye of the random string.

        :returns str rand_str: the random hexadecimal string.

    '''
    import os
    rand = os.urandom(bloc_size)
    return rand.hex().upper() 

def ISO_9797_M1_Padding_left(data, bloc_size = 8):
    ''' 
        Performs a ISO_9797_M1 Padding by left.
        This padding is done in the following way: before the original data null bytes is added 
        in order for the whole block to have a length in bytes that is a multiple of bloc_size
        If original data length is already a multiple of bloc_size, no padding is needed

        :param str data: Hexadecimal string to pad.

        :param int bloc_size: the block size modulus

        :returns str data_pad: the padded data.

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
        in order for the whole block to have a length in bytes that is a multiple of bloc_size
        If original data length is already a multiple of bloc_size, no padding is needed

        :param str data: Hexadecimal string to pad.

        :param int bloc_size: the block size modulus

        :returns str data_pad: the padded data.

    '''
    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    # Perform padding
    _data_padd  = data
    while ( ( (len (_data_padd)/2) % bloc_size) != 0):
        _data_padd = _data_padd + '00'
    return(_data_padd)

def ISO_9797_M2_Padding_left(data, bloc_size = 8):
    ''' 
        Performs a ISO_9797_M2 Padding by left.
        This padding is done in the following way: before the original data a byte '80' is added 
        in order for the whole block to have a length in bytes that is a multiple of bloc_size
        If original data length is already a multiple of bloc_size, no padding is needed
            
        :param str data: Hexadecimal string to pad.

        :param int bloc_size: the block size modulus

        :returns str data_pad: the padded data.

    '''
    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    # Perform padding
    first = True
    _data_padd  = data
    _padder = ''
    while ( ( (len (_data_padd)/2) % bloc_size) != 0):
        if first :
            _data_padd = _data_padd + '80'
            _padder = _padder +'80'
            first = False
        else:
            _data_padd = _data_padd + '00'
            _padder = _padder +'00'
        
    return(_padder  + data)



def ISO_9797_M2_Padding(data, bloc_size = 8):
    ''' 
        Performs a ISO_9797_M2 Padding.
        This padding is done in the following way: after the original data a byte '80' and then null bytes are added.
        Then, in order for the whole block to have a length in bytes that is a multiple of bloc_size, null bytes can be added
        (byte '80' and null bytes are optional and not present in case the length is already a multiple of bloc_size)

                
        :param str data: Hexadecimal string to pad.

        :param int bloc_size: the block size modulus

        :returns str data_pad: the padded data.

    '''

    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    # Perform padding
    _data_padd  = data + '80'
    while ( ( (len (_data_padd)/2) % bloc_size) != 0):
        _data_padd = _data_padd + '00'
    return(_data_padd)

def Remove_ISO_9797_M2_Padding(data ):
    ''' 
        Remove a ISO_9797_M2 Padding from an hexadecimal string .
        
        :param str data: Hexadecimal string to unpad.

        :param int bloc_size: the block size modulus

        :returns str data_pad: the unpadded data.

    '''
    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    # removing padding
    data_bytes = toByteArray(data)
    offset = len(data_bytes) - 1
    aByte = data_bytes[offset]
    while aByte == 0x00:
        offset = offset - 1
        aByte = data_bytes[offset]
    # check we find a 0x80
    if aByte != 0x80:
        return data
    else:
        # remove the last byte
        #offset = offset - 1
        return toHexString(data_bytes[0:offset])


def RSA_PKCS_1_Padding(data, key_size = 1024):
    '''
        Performs a PKCS_1 Padding use to sign data with a RSA Private Key.
        The generated block of data is:

        +----------+-------------+--------------+------+
        | Leading  |  Block Type | Padding      | Data |
        +==========+=============+=========+====+======+
        |    00    |     01      | FF...FF | 00 |   D  |
        +----------+-----------------------+----+------+


        :param str data: Hexadecimal string to pad.

        :param int key_size: the RSA key size that will be used to sign data.

        :returns str padded_data: the data padded

    '''
    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )

    padded_data="0001"

    dataLength = int(len(data)/2)

    key_size_in_byte = int ( key_size/8)
        
    numberOfFF = key_size_in_byte - 3 - dataLength

    for i in range(0,numberOfFF):
        padded_data = padded_data + "FF"

    padded_data = padded_data + "00" + data

    return padded_data 

def DES_CBC(data, key, iv="0000000000000000"):
    ''' 
    
        Performs a DES CBC on the hexadecimal string using the specified key and the specified initial vector
        
        :param str data: Hexadecimal string to cipher.

        :param str key: the key to use

        :param str iv: the initial vector (0000000000000000 by default)

        :returns str data_ret: the ciphered data.
    
    '''
    # pad data if needed
    #TODO: maybe check the key size or take only the first 8 bytes ?
    return DES3_CBC(data, key, iv)

def DES_INV_CBC(data, key, iv="0000000000000000"):
    ''' 
    
        Performs a DES-1 CBC on the hexadecimal string using the specified key and the specified initial vector
        
        :param str data: Hexadecimal string to decipher.

        :param str key: the key to use

        :param str iv: the initial vector (0000000000000000 by default)

        :returns str data_ret: the deciphered data.
    
    '''
    #TODO: maybe check the key size or take only the first 8 bytes ?
    return DES3_INV_CBC(data, key, iv)

def DES_ECB(data, key):
    ''' 

        Performs a DES ECB on the hexadecimal string using the specified key

        :param str data: Hexadecimal string to cipher.

        :param str key: the key to use

        :returns str data_ret: the ciphered data.

    '''
    #TODO: maybe check the key size or take only the first 8 bytes ?
    return DES3_ECB(data, key)

def DES_INV_ECB(data, key):
    ''' 

        Performs a DES-1 ECB on the hexadecimal string using the specified key
        
        :param str data: Hexadecimal string to decipher.

        :param str key: the key to use

        :returns str data_ret: the deciphered data.

    '''
    #TODO: maybe check the key size or take only the first 8 bytes ?
    return DES3_INV_ECB(data, key)

def DES3_CBC(data, key, iv="0000000000000000"):
    ''' 
    
        Performs a 3DES CBC on the hexadecimal string using the specified key and the specified initial vector
        
        :param str data: Hexadecimal string to cipher.

        :param str key: the key to use

        :param str iv: the initial vector (0000000000000000 by default)

        :returns str data_ret: the ciphered data.
    
    '''
    # pad data if needed
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    iv_bytes  = bytes.fromhex(iv)
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()
    return ct.hex().upper() 

def DES3_INV_CBC(data, key, iv="0000000000000000"):
    ''' 
    
        Performs a 3DES-1 CBC on the hexadecimal string using the specified key and the specified initial vector
        
        :param str data: Hexadecimal string to decipher.

        :param str key: the key to use

        :param str iv: the initial vector (0000000000000000 by default)

        :returns str data_ret: the deciphered data.
    
    '''
    # pad data if needed
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    iv_bytes  = bytes.fromhex(iv)
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = decryptor.update(data_bytes) + decryptor.finalize()
    return ct.hex().upper() 

def DES3_ECB(data, key):
    ''' 

        Performs a 3DES ECB on the hexadecimal string using the specified key
        
        :param str data: Hexadecimal string to cipher.

        :param str key: the key to use

        :returns str data_ret: the ciphered data.

    '''
    # pad data if needed
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()
    return ct.hex().upper() 

def DES3_INV_ECB(data, key):
    ''' 

        Performs a 3DES-1 ECB on the hexadecimal string using the specified key
        
        :param str data: Hexadecimal string to cipher.

        :param str key: the key to use

        :returns str data_ret: the ciphered data.

    '''
    # pad data if needed
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = decryptor.update(data_bytes) + decryptor.finalize()
    return ct.hex().upper() 

def AES_CMAC(data, key):
    ''' 
    
        Performs a AES CMAC on the hexadecimal string using the specified key
        
        :param str data: Hexadecimal string to cipher.

        :param str key: the key to use

        :returns str data_ret: the ciphered data.
    
    '''
    
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    c = cmac.CMAC(algorithms.AES(key_bytes), backend=default_backend())
    c.update(data_bytes)
    ct = c.finalize()
    return ct.hex().upper()

def AES_ECB(data, key):
    ''' 
    
        Performs a AES ECB on the hexadecimal string using the specified key
        
        :param str data: Hexadecimal string to cipher.

        :param str key: the key to use

        :returns str data_ret: the ciphered data.
    
    '''
    # pad data if needed
    data = ISO_9797_M1_Padding(data, 16)
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()
    return ct.hex().upper()


def AES_CBC(data, key, iv="00000000000000000000000000000000"):
    ''' 
    
        Performs a AES CBC on the hexadecimal string using the specified key and the specified initial vector
        
        :param str data: Hexadecimal string to cipher.

        :param str key: the key to use

        :param str iv: the initial vector (00000000000000000000000000000000 by default)

        :returns str data_ret: the ciphered data.
    
    '''
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
    ''' 
    
        Performs a AES-1 ECB on the hexadecimal string using the specified key
        
        :param str data: Hexadecimal string to decipher.

        :param str key: the key to use

        :returns str data_ret: the deciphered data.
    
    '''
    # pad data if needed
    data = ISO_9797_M1_Padding(data, 16)
    data_bytes  = bytes.fromhex(data)
    key_bytes  = bytes.fromhex(key)
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = decryptor.update(data_bytes) + decryptor.finalize()
    return ct.hex().upper()


def AES_INV_CBC(data, key, iv="00000000000000000000000000000000"):
    ''' 
    
        Performs a AES-1 CBC on the hexadecimal string using the specified key and the specified initial vector
        
        :param str data: Hexadecimal string to decipher.

        :param str key: the key to use

        :param str iv: the initial vector (00000000000000000000000000000000 by default)

        :returns str data_ret: the deciphered data.
    
    '''
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
    ''' 
    
        Performs a MAC33 on the hexadecimal string using the specified key and the specified initial vector
        
        :param str data: Hexadecimal string to mac.

        :param str key: the key to use

        :param str iv: the initial vector (0000000000000000 by default)

        :returns str data_ret: the MAC33 of the data.
    
    '''
    value = DES3_CBC(data, key, iv)
    return value[-16:]

def MAC3(data, key, padding='ISO_9797_M2', iv="0000000000000000"):
    ''' 
        Performs a MAC3 on the hexadecimal string using the specified key and the specified initial vector
        
        :param str data: Hexadecimal string to mac.
        
        :param str key: the key to use
        
        :param str padding: the padding method to use. Could be ISO_9797_M1, ISO_9797_M2 (default), None
        
        :param str iv: the initial vector (0000000000000000 by default)
        
        :returns str data_ret: the MAC3 of the data.
    
    '''
    # must check the key size
    # remove space if any
    import re
    key = ''.join( re.split( '\W+', key.upper() ) )
    if len(key) < 16*2:
        raise BaseException("Invalid key length for the MAC3 operation")

    if padding == 'ISO_9797_M2':
        data = ISO_9797_M2_Padding(data)
    elif padding == 'ISO_9797_M1':
        data = ISO_9797_M1_Padding(data)
    else:
        # no padding on data, just pass
        pass
    
    value = DES_CBC(data, key[0:16], iv)
    value = DES_INV_ECB(value[-16:], key[16:32])
    value = DES_ECB(value, key[0:16])
    return value[-16:]

def MAC(data, key, iv="0000000000000000"):
    ''' 
    
        Performs a MAC on the hexadecimal string using the specified key and the specified initial vector
        
        :param str data: Hexadecimal string to mac.

        :param str key: the key to use

        :param str iv: the initial vector (0000000000000000 by default)

        :returns str data_ret: the MAC of the data.
    
    '''
    value = DES_CBC(data, key, iv)
    return value[-16:]

def SHA1(data):
    ''' 
        Performs the SHA-1 algorithm on hexadecimal data
        
        :param str data: Hexadecimal string.

        :returns str data_ret: the hash data.
 
    '''
    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def SHA224(data):
    ''' 
        Performs the SHA-224 algorithm on hexadecimal data
        
        :param str data: Hexadecimal string.

        :returns str data_ret: the hash data.
 
    '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.SHA224(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def SHA256(data):
    ''' 
        Performs the SHA-256 algorithm on hexadecimal data
        
        :param str data: Hexadecimal string.

        :returns str data_ret: the hash data.
 
    '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def SHA384(data):
    ''' 
        Performs the SHA-384 algorithm on hexadecimal data
        
        :param str data: Hexadecimal string.

        :returns str data_ret: the hash data.
 
    '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def SHA512(data):
    ''' 
        Performs the SHA-512 algorithm on hexadecimal data
        
        :param str data: Hexadecimal string.

        :returns str data_ret: the hash data.
 
    '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def MD5(data):
    ''' 
        Performs the MD5 algorithm on hexadecimal data
        
        :param str data: Hexadecimal string.

        :returns str data_ret: the hash data.
 
    '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def HMAC(data, key, hash_algorithm = 'SHA1'):
    ''' 
        Performs the SHA-512 algorithm on hexadecimal data
        
        :param str data: Hexadecimal string.

        :param str key: Hexadecimal string.

        :param str hash_algorithm: the hash algorithm if the message you want to sign has already been hashed. Could be  'SHA1', 'SHA224', 'SHA256', 'SHA384' or 'SHA512'

        :returns str data_ret: the hash data.
 
    '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    key = ''.join( re.split( '\W+', key.upper() ) )
    data_bytes  = bytes.fromhex(data)
    key_bytes = bytes.fromhex(key)

    # managing the hash algorithm
    hash = hashes.SHA1()
    if hash_algorithm == 'SHA1':
        hash = hashes.SHA1()
    elif hash_algorithm == 'SHA224':
        hash = hashes.SHA224()
    elif hash_algorithm == 'SHA256':
        hash = hashes.SHA256()
    elif hash_algorithm == 'SHA384':
        hash = hashes.SHA384()
    elif hash_algorithm == 'SHA512':
        hash = hashes.SHA512()
    else:
        return None
    
    h = hmac.HMAC(key_bytes, hash, backend=default_backend())
    h.update(data_bytes)
    dg = h.finalize()

    return dg.hex().upper()

def generate_RSA_keys(exponent, key_size = 1024 ):
    ''' 
        RSA keys generation
        
        :param str exponent: the public key exponent.

        :param int key_size: the key size in bit (1024 by default).

        :returns tuple data_ret: the private and public key objects
 
    '''
    # call the library key generation
    private_key = rsa.generate_private_key(public_exponent = int(exponent,16), key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()
    
    # get the public key implementation values in order to create our own public key class
    public_numbers = public_key.public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    # to compliant with the type of the class
    n = hex(n).lstrip("0x").upper()
    e = hex(e).lstrip("0x").upper()


    # create our RSA public key object
    publicKey = RSA_public_key(n, e, public_key)
    # get the private key implementation values in order to create our own private key class
    private_numbers = private_key.private_numbers()
    p = private_numbers.p
    q = private_numbers.q
    d = private_numbers.d
    dmp1 = private_numbers.dmp1
    dmq1 = private_numbers.dmq1
    iqmp = private_numbers.iqmp

    # to compliant with the type of the class
    p = hex(p).lstrip("0x").upper()
    q = hex(q).lstrip("0x").upper()
    d = hex(d).lstrip("0x").upper()
    dmp1 = hex(dmp1).lstrip("0x").upper()
    dmq1 = hex(dmq1).lstrip("0x").upper()
    iqmp = hex(iqmp).lstrip("0x").upper()
    
    # create our RSA private key object
    privateKey = RSA_private_key(p, q, d, dmp1, dmq1, iqmp, private_key)
    
    return privateKey, publicKey

def build_RSA_SFM_keys(public_modulus, public_exponent, private_exponent):
    ''' 
        Build RSA keys using specific values

        :param str public_modulus: the public key modulus.
        
        :param str public_exponent: the public key exponent.

        :param str private_exponent: The private key exponent 
        
        :returns tuple data_ret: the private and public key objects
 
    '''
    import re
    # remove space if any
    public_modulus = ''.join( re.split( '\W+', public_modulus.upper() ) )
    public_exponent = ''.join( re.split( '\W+', public_exponent.upper() ) )
    private_exponent = ''.join( re.split( '\W+', private_exponent.upper() ) )

    # Computes the prime factors (p, q) given the modulus, public exponent, and private exponent
    public_modulus_as_int = int(public_modulus,16)
    public_exponent_as_int = int(public_exponent,16)
    d = int(private_exponent,16)
    
    p, q = rsa.rsa_recover_prime_factors(public_modulus_as_int, public_exponent_as_int, d)
    # Computes the dmp1 parameter from the RSA private exponent (d) and prime p.
    dmp1 = rsa.rsa_crt_dmp1(d, p)
    # Computes the iqmp (also known as qInv) parameter from the RSA primes p and q.
    iqmp = rsa.rsa_crt_iqmp(p, q)
    # Computes the dmq1 parameter from the RSA private exponent (d) and prime q.
    dmq1 = rsa.rsa_crt_dmq1(d, q)

    # wrap parameter to string in order to be compliant with class memebers


    p = hex(p).lstrip("0x")
    q = hex(q).lstrip("0x")
    d = hex(d).lstrip("0x")
    dmq1 = hex(dmq1).lstrip("0x")
    iqmp = hex(iqmp).lstrip("0x")
    dmp1 = hex(dmp1).lstrip("0x")

    private_key = RSA_private_key(p, q, d, dmp1, dmq1, iqmp)
    private_key.set_public_key(public_modulus, public_exponent)
    private_key.build()
    
    public_key = RSA_public_key(public_modulus, public_exponent)
    public_key.build()

    return private_key, public_key

def build_RSA_keys(public_modulus, public_exponent, p, q, d, dmp1, dmq1, iqmp):
    ''' 
        Build RSA keys using specific values

        :param str public_modulus: the public key modulus.
        
        :param str public_exponent: the public key exponent.

        :param str p: the private key large_modulus 
        
        :param str q: the private key small_modulus 

        :param str d: The private key exponent
        
        :param str dmp1: the key component d mod (p-1)
        
        :param str dmq1: the key component d mod (q-1)
        
        :param str iqmp: the key component q-1 mod p

        :returns tuple data_ret: the private and public key objects
 
    '''
    import re
    # remove space if any
    public_modulus = ''.join( re.split( '\W+', public_modulus.upper() ) )
    public_exponent = ''.join( re.split( '\W+', public_exponent.upper() ) )
    p = ''.join( re.split( '\W+', p.upper() ) )
    q = ''.join( re.split( '\W+', q.upper() ) )
    d = ''.join( re.split( '\W+', d.upper() ) )
    dmp1 = ''.join( re.split( '\W+', dmp1.upper() ) )
    dmq1 = ''.join( re.split( '\W+', dmq1.upper() ) )
    iqmp = ''.join( re.split( '\W+', iqmp.upper() ) )

    private_key = RSA_private_key(p, q, d, dmp1, dmq1, iqmp)
    private_key.set_public_key(public_modulus, public_exponent)
    private_key.build()
    
    public_key = RSA_public_key(public_modulus, public_exponent)
    public_key.build()

    return private_key, public_key


def build_RSA_public_keys(public_modulus, public_exponent):
    ''' 
        Build RSA public keys using specific values

        :param str public_modulus: the public key modulus.
        
        :param str public_exponent: the public key exponent.

        :returns data_ret: the public key objects
 
    '''
    import re
    # remove space if any
    public_modulus = ''.join( re.split( '\W+', public_modulus.upper() ) )
    public_exponent = ''.join( re.split( '\W+', public_exponent.upper() ) )

    public_key = RSA_public_key(public_modulus, public_exponent)
    public_key.build()

    return public_key


def RSA_signature(message, private_key, padding_algorithm = 'PKCS1', hash_algorithm = 'SHA1'):
    ''' 
        Performs a RSA signature on data using the padding and hash algorithm.

        :param str message: the message to sign as hexadecimal string.
        
        :param str private_key: the private key object see :func:`build_RSA_keys()` or :func:`generate_RSA_keys()`

        :param str padding_algorithm: the padding to apply on data. Could be  'PKCS1', 'PSS' or 'OEAP'
        
        :param str hash_algorithm: the hash algorithm if the message you want to sign has already been hashed. Could be  'SHA1', 'SHA224', 'SHA256', 'SHA384' or 'SHA512'

        :returns str data_ret: the signature
 
    '''
    import re
    message = ''.join( re.split( '\W+', message.upper() ) )
    # managing the padding
    pad = padding.PKCS1v15
    if padding_algorithm == 'PKCS1':
        pad = padding.PKCS1v15()
    elif padding_algorithm == 'PSS':
        pad = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH)
    elif padding_algorithm == 'OEAP':
        pad = hashes.OEAP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    
    else:
        return None
    
    
    # managing the hash algorithm
    hash = hashes.SHA1()
    if hash_algorithm == 'SHA1':
        hash = hashes.SHA1()
    elif hash_algorithm == 'SHA224':
        hash = hashes.SHA224()
    elif hash_algorithm == 'SHA256':
        hash = hashes.SHA256()
    elif hash_algorithm == 'SHA384':
        hash = hashes.SHA384()
    elif hash_algorithm == 'SHA512':
        hash = hashes.SHA512()
    else:
        return None

    signature = private_key.sign(message,pad, hash)

    return signature

def RSA_verify( message, signature, public_key, padding_algorithm= 'PKCS1', hash_algorithm= 'SHA1'):
    ''' 
        Performs a RSA signature verification on data using the padding and hash algorithm.

        :param str message: the message to sign as hexadecimal string.

        :param str signature: the signature of the message.
        
        :param str public_key: the public key object see :func:`build_RSA_keys()` or :func:`generate_RSA_keys()`

        :param str padding_algorithm: the padding to apply on data. Could be  'PKCS1', 'PSS' or 'OEAP'
        
        :param str hash_algorithm: the hash algorithm if the message you want to sign has already been hashed. Could be  'SHA1', 'SHA224', 'SHA256', 'SHA384' or 'SHA512'

        :returns bool data_ret: True if the signature is verified, False otherwize
 
    '''

    # remove space if any
    import re
    message = ''.join( re.split( '\W+', message.upper() ) )
    signature = ''.join( re.split( '\W+', signature.upper() ) )
    
    # managing the padding
    pad = padding.PKCS1v15
    if padding_algorithm == 'PKCS1':
        pad = padding.PKCS1v15()
    elif padding_algorithm == 'PSS':
        pad = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH)
    elif padding_algorithm == 'OEAP':
        pad = hashes.OEAP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    
    else:
        return None
    
    # managing the hash algorithm
    hash = hashes.SHA1()

    if hash_algorithm == 'SHA1':
        hash = hashes.SHA1()
    elif hash_algorithm == 'SHA224':
        hash = hashes.SHA224()
    elif hash_algorithm == 'SHA256':
        hash = hashes.SHA256()
    elif hash_algorithm == 'SHA384':
        hash = hashes.SHA384()
    elif hash_algorithm == 'SHA512':
        hash = hashes.SHA512()
    else:
        return False
    signature_verified = public_key.verify(message, signature, pad, hash)
    return signature_verified

def DSA_signature(message, private_key, hash_algorithm = 'SHA1'):
    ''' 
        Performs a DSA signature on data using hash algorithm.

        :param str message: the message to sign as hexadecimal string.
        
        :param str private_key: the private key object see :func:`build_DSA_keys()` or :func:`generate_DSA_keys()`

        :param str hash_algorithm: the hash algorithm if the message you want to sign has already been hashed. Could be  'SHA1', 'SHA224', 'SHA256', 'SHA384' or 'SHA512'

        :returns str data_ret: the signature
 
    '''
    import re
    message = ''.join( re.split( '\W+', message.upper() ) )
    hash = hashes.SHA1()
    # managing the hash algorithm
    if hash_algorithm == 'SHA1':
        hash = hashes.SHA1()
    elif hash_algorithm == 'SHA224':
        hash = hashes.SHA224()
    elif hash_algorithm == 'SHA256':
        hash = hashes.SHA256()
    elif hash_algorithm == 'SHA384':
        hash = hashes.SHA384()
    elif hash_algorithm == 'SHA512':
        hash = hashes.SHA512()
    else:
        return None

    signature = private_key.sign(message,hash)

    return signature

def DSA_verify(message, signature, public_key, hash_algorithm= 'SHA1'):
    ''' 
        Performs a DSA signature verification on data using the hash algorithm.

        :param str message: the message to sign as hexadecimal string.

        :param str signature: the signature of the message.
        
        :param str public_key: the public key object see :func:`build_RSA_keys()` or :func:`generate_RSA_keys()`

        :param str hash_algorithm: the hash algorithm if the message you want to sign has already been hashed. Could be  'SHA1', 'SHA224', 'SHA256', 'SHA384' or 'SHA512'

        :returns bool data_ret: True if the signature is verified, False otherwize
 
    '''
    import re
    message = ''.join( re.split( '\W+', message.upper() ) )
    signature = ''.join( re.split( '\W+', signature.upper() ) )
    
    hash = hashes.SHA1()
    # managing the hash algorithm
    if hash_algorithm == 'SHA1':
        hash = hashes.SHA1()
    elif hash_algorithm == 'SHA224':
        hash = hashes.SHA224()
    elif hash_algorithm == 'SHA256':
        hash = hashes.SHA256()
    elif hash_algorithm == 'SHA384':
        hash = hashes.SHA384()
    elif hash_algorithm == 'SHA512':
        hash = hashes.SHA512()
    else:
        return False
    signature_verified = public_key.verify(message, signature, hash)
    return signature_verified





def ECDSA_signature(message, private_key, hash_algorithm = 'SHA1'):
    ''' 
        Performs a ECDSA signature on data using hash algorithm.

        :param str message: the message to sign as hexadecimal string.
        
        :param str private_key: the private key object see :func:`build_ECDSA_keys()` or :func:`generate_ECDSA_keys()`

        :param str hash_algorithm: the hash algorithm if the message you want to sign has already been hashed. Could be  'SHA1', 'SHA224', 'SHA256', 'SHA384' or 'SHA512'

        :returns str data_ret: the signature
 
    '''
    import re
    message = ''.join( re.split( '\W+', message.upper() ) )
    hash = hashes.SHA1()
    # managing the hash algorithm
    if hash_algorithm == 'SHA1':
        hash = hashes.SHA1()
    elif hash_algorithm == 'SHA224':
        hash = hashes.SHA224()
    elif hash_algorithm == 'SHA256':
        hash = hashes.SHA256()
    elif hash_algorithm == 'SHA384':
        hash = hashes.SHA384()
    elif hash_algorithm == 'SHA512':
        hash = hashes.SHA512()
    else:
        return None

    signature = private_key.sign(message,hash)

    return signature

def ECDSA_verify(message, signature, public_key, hash_algorithm= 'SHA1'):
    ''' 
        Performs a ECDSA signature verification on data using the hash algorithm.

        :param str message: the message to sign as hexadecimal string.

        :param str signature: the signature of the message.
        
        :param str public_key: the public key object see :func:`build_EC_keys()` or :func:`generate_EC_keys()`

        :param str hash_algorithm: the hash algorithm if the message you want to sign has already been hashed. Could be  'SHA1', 'SHA224', 'SHA256', 'SHA384' or 'SHA512'

        :returns bool data_ret: True if the signature is verified, False otherwize
 
    '''
    import re
    message = ''.join( re.split( '\W+', message.upper() ) )
    signature = ''.join( re.split( '\W+', signature.upper() ) )
    
    hash = hashes.SHA1()
    # managing the hash algorithm
    if hash_algorithm == 'SHA1':
        hash = hashes.SHA1()
    elif hash_algorithm == 'SHA224':
        hash = hashes.SHA224()
    elif hash_algorithm == 'SHA256':
        hash = hashes.SHA256()
    elif hash_algorithm == 'SHA384':
        hash = hashes.SHA384()
    elif hash_algorithm == 'SHA512':
        hash = hashes.SHA512()
    else:
        return False
    signature_verified = public_key.verify(message, signature, hash)
    return signature_verified

def generate_ECDH_key_agreement(private_key, public_key ):
    ''' 
        Performs a ECDH key aggrement.

        :param str private_key: the private key object see :func:`build_EC_keys()` or :func:`generate_EC_keys()`

        :param str public_key: the public key object see :func:`build_EC_keys()` or :func:`generate_EC_keys()`

        :returns str data_ret: The agreed key
 
    '''
    shared_secret = private_key.exchange(public_key) 
    return shared_secret


def generate_EC_keys( curve_name = 'brainpoolP256r1'  ):
    ''' 
        EC keys generation
        
        :param str curve_name: the name of the curve. Possible curve names:

        +-------------------+-------------------------------+
        | Value             |  Description                  |
        +===================+===============================+
        | "nistP521r1"      |  NIST P-521                   |
        +-------------------+-------------------------------+
        | "nistP256r1"      |  NIST P-256                   |
        +-------------------+-------------------------------+
        | "brainpoolP192r1" |  Brainpool P-192 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP192t1" |  Brainpool P-192 T1           |
        +-------------------+-------------------------------+
        | "brainpoolP256r1" |  Brainpool P-256 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP256t1" |  Brainpool P-256 T1           |
        +-------------------+-------------------------------+
        | "brainpoolP384r1" |  Brainpool P-384 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP384t1" |  Brainpool P-384 T1           |
        +-------------------+-------------------------------+
        | "brainpoolP512r1" |  Brainpool P-512 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP512t1" |  Brainpool P-512 T1           |
        +-------------------+-------------------------------+

            
        :returns tuple data_ret: the private and public key objects
 
    '''
    # get the EC class matching this curve name
    try:
        curve = ec._CURVE_TYPES[curve_name]
    except KeyError:

        return None,None

    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()
    
    # get the public key implementation values in order to create our own public key class
    public_numbers = public_key.public_numbers()
    x = public_numbers.x
    y = public_numbers.y
    curve = public_numbers.curve

    # to compliant with the type of the class
    x = hex(x).lstrip("0x").upper()
    y = hex(y).lstrip("0x").upper()
    
    # create our EC public key object
    publicKey = EC_public_key(x,  y, curve, public_key )

    # get the private key implementation values in order to create our own private key class
    private_numbers = private_key.private_numbers()
    p = hex(private_numbers.private_value).lstrip("0x").upper()
    privateKey = EC_private_key(p, curve, private_key)
        
    return privateKey, publicKey


def build_EC_keys( s, x, y, curve_name = 'brainpoolP256r1'):
    ''' 
        Build EC keys using parameters
        
        
        :param str s: The private value

        :param str x: The affine x component of the public point

        :param str y: The affine y component of the public point 

        :param str curve_name: the name of the curve. Possible curve names:

        +-------------------+-------------------------------+
        | Value             |  Description                  |
        +===================+===============================+
        | "nistP521r1"      |  NIST P-521                   |
        +-------------------+-------------------------------+
        | "nistP256r1"      |  NIST P-256                   |
        +-------------------+-------------------------------+
        | "brainpoolP192r1" |  Brainpool P-192 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP192t1" |  Brainpool P-192 T1           |
        +-------------------+-------------------------------+
        | "brainpoolP256r1" |  Brainpool P-256 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP256t1" |  Brainpool P-256 T1           |
        +-------------------+-------------------------------+
        | "brainpoolP384r1" |  Brainpool P-384 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP384t1" |  Brainpool P-384 T1           |
        +-------------------+-------------------------------+
        | "brainpoolP512r1" |  Brainpool P-512 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP512t1" |  Brainpool P-512 T1           |
        +-------------------+-------------------------------+

            
        :returns tuple data_ret: the private and public key objects
 
    '''
    import re
    # remove space if any
    s = ''.join( re.split( '\W+', s.upper() ) )
    x = ''.join( re.split( '\W+', x.upper() ) )
    y = ''.join( re.split( '\W+', y.upper() ) )

    try:
        curve = ec._CURVE_TYPES[curve_name]()
    except KeyError:

        return None,None

    # build keys objects
    private_key = EC_private_key(s, curve)
    private_key.set_public_key(x, y)
    private_key.build()
    
    public_key = EC_public_key(x, y, curve)
    public_key.build()
    
    return private_key, public_key


def build_EC_public_key( x, y, curve_name = 'brainpoolP256r1'):
    ''' 
        Build EC public keys using parameters
        
        :param str x: The affine x component of the public point

        :param str y: The affine y component of the public point 

        :param str curve_name: the name of the curve. Possible curve names:

        +-------------------+-------------------------------+
        | Value             |  Description                  |
        +===================+===============================+
        | "nistP521r1"      |  NIST P-521                   |
        +-------------------+-------------------------------+
        | "nistP256r1"      |  NIST P-256                   |
        +-------------------+-------------------------------+
        | "brainpoolP192r1" |  Brainpool P-192 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP192t1" |  Brainpool P-192 T1           |
        +-------------------+-------------------------------+
        | "brainpoolP256r1" |  Brainpool P-256 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP256t1" |  Brainpool P-256 T1           |
        +-------------------+-------------------------------+
        | "brainpoolP384r1" |  Brainpool P-384 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP384t1" |  Brainpool P-384 T1           |
        +-------------------+-------------------------------+
        | "brainpoolP512r1" |  Brainpool P-512 R1           |
        +-------------------+-------------------------------+
        | "brainpoolP512t1" |  Brainpool P-512 T1           |
        +-------------------+-------------------------------+

            
        :returns data_ret: the public key objects
 
    '''
    import re
    # remove space if any
    x = ''.join( re.split( '\W+', x.upper() ) )
    y = ''.join( re.split( '\W+', y.upper() ) )

    try:
        curve = ec._CURVE_TYPES[curve_name]()
    except KeyError:

        return None,None

    # build keys objects
    public_key = EC_public_key(x, y, curve)
    public_key.build()
    
    return public_key


def generate_DSA_keys(key_size = 1024 ):
    ''' 
        DSA keys generation
        
        :param int key_size: the key size in bit (1024 by default).

        :returns tuple data_ret: the private and public key objects
 
    '''
    # call the library key generation
    private_key = dsa.generate_private_key(key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()
    
    # get the public key implementation values in order to create our own public key class
    public_numbers = public_key.public_numbers()
    p = public_numbers.parameter_numbers.p
    g = public_numbers.parameter_numbers.g
    q = public_numbers.parameter_numbers.q
    y = public_numbers.y
    
    # to compliant with the type of the class
    p = hex(p).lstrip("0x").upper()
    g = hex(g).lstrip("0x").upper()
    q = hex(q).lstrip("0x").upper()
    y = hex(y).lstrip("0x").upper()

    # create our DSA public key object
    publicKey = DSA_public_key(p, q, g, y, public_key )

    # get the private key implementation values in order to create our own private key class
    private_numbers = private_key.private_numbers()
    p = private_numbers.public_numbers.parameter_numbers.p
    g = private_numbers.public_numbers.parameter_numbers.g
    q = private_numbers.public_numbers.parameter_numbers.q
    x = private_numbers.x

    # to compliant with the type of the class
    p = hex(p).lstrip("0x").upper()
    g = hex(g).lstrip("0x").upper()
    q = hex(q).lstrip("0x").upper()
    x = hex(x).lstrip("0x").upper()
    
    # create our DSA private key object
    privateKey = DSA_private_key(p, q, g, x, private_key)
    
    return privateKey, publicKey


def build_DSA_keys(p, q, g, public_key, private_key):
    ''' 
        Build DSA keys using specific values

        :param str p: the private key large_modulus 
        
        :param str q: The sub-group order. 

        :param str g: The private key generator
        
        :param str public_key: the public value.
        
        :param str private_key: the private value.

        :returns tuple data_ret: the private and public key objects
 
    '''
    import re
    # remove space if any
    p = ''.join( re.split( '\W+', p.upper() ) )
    q = ''.join( re.split( '\W+', q.upper() ) )
    g = ''.join( re.split( '\W+', g.upper() ) )
    public_key = ''.join( re.split( '\W+', public_key.upper() ) )
    private_key = ''.join( re.split( '\W+', private_key.upper() ) )
    # build keys objects
    private_key = DSA_private_key(p, q, g, private_key)
    private_key.set_public_key(public_key)
    private_key.build()
    
    public_key = DSA_public_key(p, q, g, public_key)
    public_key.build()
    return private_key, public_key
    


def generate_DH_keys(generator, key_size = 1024 ):
    ''' 
        DH keys generation

        :param str generator: The generator
        
        :param int key_size: the key size in bit (1024 by default).

        :returns tuple data_ret: the private and public key objects
 
    '''
    # call the library key generation
    parameters = dh.generate_parameters(int(generator,16), key_size, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    # get the public key implementation values in order to create our own public key class
    public_numbers = public_key.public_numbers()
    p = public_numbers.parameter_numbers.p
    g = public_numbers.parameter_numbers.g
    y = public_numbers.y

    # to compliant with the type of the class
    p = hex(p).lstrip("0x").upper()
    g = hex(g).lstrip("0x").upper()
    y = hex(y).lstrip("0x").upper()
    # create our DH public key object
    publicKey = DH_public_key(p, g, y, public_key )

    # get the private key implementation values in order to create our own private key class
    private_numbers = private_key.private_numbers()
    p = private_numbers.public_numbers.parameter_numbers.p
    g = private_numbers.public_numbers.parameter_numbers.g
    x = private_numbers.x

    # to compliant with the type of the class
    p = hex(p).lstrip("0x").upper()
    g = hex(g).lstrip("0x").upper()
    x = hex(x).lstrip("0x").upper()
    # create our DH private key object
    privateKey = DH_private_key(p, g, x, private_key)
    
    return privateKey, publicKey


def build_DH_keys(p, g, private_key, public_key):
    ''' 
        Build DH keys using specific values

        :param str p: the private key modulus 
        

        :param str g: The private key generator
        
        :param str private_key: the private value.

        :param str public_key: the public value.
        
        :returns tuple data_ret: the private and public key objects
 
    '''
    import re
    # remove space if any
    p = ''.join( re.split( '\W+', p.upper() ) )
    g = ''.join( re.split( '\W+', g.upper() ) )
    public_key = ''.join( re.split( '\W+', public_key.upper() ) )
    private_key = ''.join( re.split( '\W+', private_key.upper() ) )

    # build keys objects
    private_key = DH_private_key(p, g, private_key)
    private_key.set_public_key(public_key)
    private_key.build()
    
    public_key = DH_public_key(p, g, public_key)
    public_key.build()
    
    return private_key, public_key


def generate_DH_key_agreement(private_key, public_key ):
    ''' 
        Performs a DH key aggrement.

        :param str private_key: the private key object see :func:`build_DH_keys()` or :func:`generate_DH_keys()`

        :param str public_key: the public key object see :func:`build_DH_keys()` or :func:`generate_DH_keys()`

        :returns str data_ret: The agreed key
 
    '''
    shared_secret = private_key.exchange(public_key) 
    return shared_secret


class RSA_public_key():

    def __init__(self, public_modulus, public_exponent, key_implementation = None):
        
        self.public_modulus = public_modulus
        self.public_exponent = public_exponent
        self.key_implementation = key_implementation
        if key_implementation != None:
            self.key_len = int(key_implementation.key_size / 8) # byte length of the modulus.
        else:
            self.key_len = 0

    def get_modulus(self):
        return (self.public_modulus).rjust(self.key_len, '0')

    def get_exponent(self):
        return (self.public_exponent).rjust(6, '0')
    
    def verify(self, message, signature, padding = padding.PKCS1v15(), hash_algorithm = hashes.SHA1()):
        
        if self.key_implementation != None:
            message_bytes  = bytes.fromhex(message)
            signature_bytes  = bytes.fromhex(signature)
            try:
                self.key_implementation.verify(signature_bytes, message_bytes, padding, hash_algorithm)
            except BaseException as e:
                print(str(e))
                return False
            return True
        else:
            return False
    
    def encrypt(self, message, padding = padding.PKCS1v15()):
        message_bytes  = bytes.fromhex(message)
        encrypt_message = self.key_implementation.encrypt(message_bytes,padding)
        return encrypt_message.hex().upper()


    def build(self):
        ''' build the RSA Public key object matching the crypto library used '''
        RSAPublic = rsa.RSAPublicNumbers(int(self.public_exponent,16), int(self.public_modulus,16))
        self.key_implementation = RSAPublic.public_key(backend=default_backend())
        self.key_len = int(self.key_implementation.key_size / 8) # byte length of the modulus.

    
    def __str__(self):
        str_value = "RSA Public Key:\n"
        str_value = str_value  + "\t modulus   : " + self.get_modulus()+ "\n"
        str_value = str_value  + "\t exponent  : " + self.get_exponent()+ "\n"
        return str_value


class RSA_private_key():

    def __init__(self, p, q, d, dmp1, dmq1, iqmp, key_implementation = None):
        self.p = p
        self.q = q
        self.d = d
        self.dmp1 = dmp1
        self.dmq1 = dmq1
        self.iqmp = iqmp
        self.key_implementation = key_implementation
        self.public_modulus = None
        self.public_exponent = None
        if key_implementation != None:
            self.key_len = int(key_implementation.key_size / 8) # byte length of the modulus.
        else:
            self.key_len = 0

    def get_p(self):
        return (self.p).rjust(self.key_len, '0')
    def get_q(self):
        return (self.q).rjust(self.key_len, '0')
    def get_d(self):
        return (self.d).rjust(self.key_len * 2, '0')
    def get_dmp1(self):
        return (self.dmp1).rjust(self.key_len, '0')
    def get_dmq1(self):
        return (self.dmq1).rjust(self.key_len, '0')
    def get_iqmp(self):
        return (self.iqmp).rjust(self.key_len, '0')
    
    def set_public_key(self, modulus, exponent):
        self.public_modulus = modulus
        self.public_exponent = exponent

    
    def sign(self, message, padding = padding.PKCS1v15(), hash_algorithm = hashes.SHA1()):
        message_bytes  = bytes.fromhex(message)
        signature = self.key_implementation.sign(message_bytes,padding, hash_algorithm)
        return signature.hex().upper().rjust(self.key_len * 2, '0')
    
    def decrypt(self, message, padding = padding.PKCS1v15()):
        message_bytes  = bytes.fromhex(message)
        decrypt_message = self.key_implementation.decrypt(message_bytes,padding)
        return decrypt_message.hex().upper()

    def build(self):
       
        # build the DSA Private key object matching the crypto library used
        RSAPublic = rsa.RSAPublicNumbers(int(self.public_exponent,16), int(self.public_modulus,16))
        RSA_private_numbers = rsa.RSAPrivateNumbers(int(self.p, 16), int(self.q, 16), int(self.d, 16), int(self.dmp1, 16), int(self.dmq1, 16), int(self.iqmp, 16) ,RSAPublic)
        self.key_implementation = RSA_private_numbers.private_key(backend=default_backend())
        self.key_len = int(self.key_implementation.key_size / 8) # byte length of the modulus. It will be set 

    def __str__(self):
        str_value = "RSA Private Key:\n"
        str_value = str_value  + "\t p  : " + self.get_p()+ "\n"
        str_value = str_value  + "\t q  : " + self.get_q()+ "\n"
        str_value = str_value  + "\t d  : " + self.get_d()+ "\n"
        str_value = str_value  + "\t dmp1  : " + self.get_dmp1()+ "\n"
        str_value = str_value  + "\t dmq1  : " + self.get_dmq1()+ "\n"
        str_value = str_value  + "\t iqmp  : " + self.get_iqmp()+ "\n"
        return str_value

class DH_public_key():

    def __init__(self, p, g, key, key_implementation = None):
        self.p = p
        self.g = g
        self.key = key
        self.key_implementation = key_implementation
    
    def get_p(self):
        return str(self.p)
    def get_g(self):
        return str(self.g)
    def get_key(self):
        return str(self.key)

    def verify(self, message, signature, hash_algorithm = hashes.SHA1()):
        
        if self.key_implementation != None:
            message_bytes  = bytes.fromhex(message)
            signature_bytes  = bytes.fromhex(signature)
            try:
                self.key_implementation.verify(signature_bytes, message_bytes,hash_algorithm)
            except:
                return False
            return True
        else:
            return False


    def build(self):
        ''' build the DH Public key object matching the crypto library used '''
        DH_parameter = dh.DHParameterNumbers(int(self.p, 16),  int(self.g, 16))
        DHPublic = dh.DHPublicNumbers(int(self.key, 16), DH_parameter)
        self.key_implementation = DHPublic.public_key(backend=default_backend())
        
    
    def __str__(self):
        str_value = "DH Public Key:\n"
        str_value = str_value  + "\t p  : " + self.get_p()+ "\n"
        str_value = str_value  + "\t g  : " + self.get_g()+ "\n"
        str_value = str_value  + "\t key: " + self.get_key()+ "\n"
        return str_value

class DH_private_key():

    def __init__(self, p, g, key, key_implementation = None):
        self.p = p
        self.g = g
        self.key = key
        self.key_implementation = key_implementation
        self.public_key = None
    
    def get_p(self):
        return str(self.p)
    def get_g(self):
        return str(self.g)
    def get_key(self):
        return str(self.key)
    def set_public_key(self, y):
        self.public_key = y

    
    def exchange(self, public_key):
        
        secret = self.key_implementation.exchange(public_key.key_implementation)
        return secret.hex().upper()

    def build(self):

        # build the DSA Private key object matching the crypto library used
        DH_parameter = dh.DHParameterNumbers(int(self.p, 16),  int(self.g, 16))
        DH_public_numbers = dh.DHPublicNumbers(int(self.public_key, 16), DH_parameter)
        DH_private_numbers = dh.DHPrivateNumbers(int(self.key, 16), DH_public_numbers)
        self.key_implementation = DH_private_numbers.private_key(backend=default_backend())
    
    def __str__(self):
        str_value = "DH Private Key:\n"
        str_value = str_value  + "\t p  : " + self.get_p()+ "\n"
        str_value = str_value  + "\t g  : " + self.get_g()+ "\n"
        str_value = str_value  + "\t key: " + self.get_key()+ "\n"
        return str_value

class EC_public_key():
    
    def __init__(self, x, y, curve, key_implementation = None):
        self.x = x
        self.y = y
        self.curve = curve
        self.key_len = int(curve.key_size / 8) # Size (in bytes) of a secret scalar for the curve
        self.key_implementation = key_implementation
    
    def get_x(self):
        return (self.x).rjust(self.key_len * 2, '0')
    def get_y(self):
        return (self.y).rjust(self.key_len * 2, '0')
    def get_curve(self):
        return self.curve
    def get_curve_name(self):
        return self.curve.name
    
    def verify(self, message, signature, hash_algorithm = hashes.SHA1()):
        
        if self.key_implementation != None:
            message_bytes  = bytes.fromhex(message)
            signature_centerposition = int(len(signature) / 2)
            signature_x = int(signature[:signature_centerposition], 16)
            signature_y = int(signature[signature_centerposition:], 16)
            signature_dss_encoded = asymmetric_utils.encode_dss_signature(signature_x, signature_y)
            try:
                self.key_implementation.verify(signature_dss_encoded, message_bytes, ec.ECDSA(hash_algorithm))
            except:
                return False
            return True
        else:
            return False


    def build(self):
        ''' build the EC Public key object matching the crypto library used '''
        ECPublicNumbers = ec.EllipticCurvePublicNumbers(int(self.x, 16), int(self.y, 16), self.curve)
        self.key_implementation = ECPublicNumbers.public_key(backend=default_backend())
        
    
    def __str__(self):
        str_value = "EC Public Key:\n"
        str_value = str_value  + "\t x      : " + self.get_x()+ "\n"
        str_value = str_value  + "\t y      : " + self.get_y()+ "\n"
        str_value = str_value  + "\t curve  : " + self.get_curve_name()+ "\n"
        return str_value


class EC_private_key():

    def __init__(self, p, curve, key_implementation = None):
        self.p = p
        self.curve = curve
        self.key_len = int(curve.key_size / 8) # Size (in bytes) of a secret scalar for the curve
        self.key_implementation = key_implementation
        self.x = None
        self.y = None
    
    def get_p(self):
        return (self.p).rjust(self.key_len * 2, '0')

    def get_curve(self):
        return self.curve
    
    def get_curve_name(self):
        return self.curve.name

    def set_public_key(self, x, y):
        self.x = x
        self.y = y


    def build(self):
        ''' build the EC Public key object matching the crypto library used '''
        ECPublicNumbers = ec.EllipticCurvePublicNumbers(int(self.x, 16), int(self.y, 16), self.curve)
        ECPrivateNumbers = ec.EllipticCurvePrivateNumbers(int(self.p, 16),ECPublicNumbers)
        self.key_implementation = ECPrivateNumbers.private_key(backend=default_backend())
    
    def sign(self, message, hash_algorithm = hashes.SHA1()):
            message_bytes  = bytes.fromhex(message)
            signature = self.key_implementation.sign(message_bytes, ec.ECDSA(hash_algorithm))
            r, s = asymmetric_utils.decode_dss_signature(signature)
            str_r = format(r, 'X').rjust(self.key_len * 2,'0')
            str_s = format(s, 'X').rjust(self.key_len * 2,'0')
            return str_r + str_s


    def exchange(self, public_key):
        
        secret = self.key_implementation.exchange(ec.ECDH(), public_key.key_implementation)
        return secret.hex().upper()
    
    def __str__(self):
        str_value = "EC Private Key:\n"
        str_value = str_value  + "\t p      : " + self.get_p()+ "\n"
        str_value = str_value  + "\t curve  : " + self.get_curve_name()+ "\n"
        return str_value

class DSA_public_key():

    def __init__(self, p, q, g, key, key_implementation = None):
        self.p = p
        self.q = q
        self.g = g
        self.key = key
        self.key_implementation = key_implementation
    
    def get_p(self):
        return str(self.p)
    def get_q(self):
        return str(self.q)
    def get_g(self):
        return str(self.g)
    def get_key(self):
        return str(self.key)

    def verify(self, message, signature, hash_algorithm = hashes.SHA1()):
        
        if self.key_implementation != None:
            message_bytes  = bytes.fromhex(message)
            signature_bytes  = bytes.fromhex(signature)
            try:
                self.key_implementation.verify(signature_bytes, message_bytes,hash_algorithm)
            except:
                return False
            return True
        else:
            return False


    def build(self):
        ''' build the DSA Public key object matching the crypto library used '''
        DSA_parameter = dsa.DSAParameterNumbers(int(self.p, 16), int(self.q, 16), int(self.g, 16))
        DSAPublic = dsa.DSAPublicNumbers(int(self.key,16), DSA_parameter)
        self.key_implementation = DSAPublic.public_key(backend=default_backend())
        
    
    def __str__(self):
        str_value = "DSA Public Key:\n"
        str_value = str_value  + "\t p  : " + self.get_p()+ "\n"
        str_value = str_value  + "\t q  : " + self.get_q()+ "\n"
        str_value = str_value  + "\t g  : " + self.get_g()+ "\n"
        str_value = str_value  + "\t key: " + self.get_key()+ "\n"
        return str_value


class DSA_private_key():

    def __init__(self, p, q, g, key, key_implementation = None):
        self.p = p
        self.q = q
        self.g = g
        self.key = key
        self.key_implementation = key_implementation
        self.public_key = None
    
    def get_p(self):
        return str(self.p)
    def get_q(self):
        return str(self.q)
    def get_g(self):
        return str(self.g)
    def get_key(self):
        return str(self.key)
    def set_public_key(self, y):
        self.public_key = y

    
    def sign(self, message, hash_algorithm = hashes.SHA1()):
        message_bytes  = bytes.fromhex(message)
        signature = self.key_implementation.sign(message_bytes,hash_algorithm)
        return signature.hex().upper()

    def build(self):
       
        # build the DSA Private key object matching the crypto library used
        DSA_parameter = dsa.DSAParameterNumbers(int(self.p, 16), int(self.q, 16), int(self.g, 16))
        DSA_public_numbers = dsa.DSAPublicNumbers(int(self.public_key, 16), DSA_parameter)
        DSA_private_numbers = dsa.DSAPrivateNumbers(int(self.key, 16), DSA_public_numbers)
        self.key_implementation = DSA_private_numbers.private_key(backend=default_backend())
    
    def __str__(self):
        str_value = "DSA Private Key:\n"
        str_value = str_value  + "\t p  : " + self.get_p()+ "\n"
        str_value = str_value  + "\t q  : " + self.get_q()+ "\n"
        str_value = str_value  + "\t g  : " + self.get_g()+ "\n"
        str_value = str_value  + "\t key: " + self.get_key()+ "\n"
        return str_value
