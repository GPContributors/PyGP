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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat




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

def ISO_9797_M2_Padding_left(data, bloc_size = 8):
    ''' 
    Performs a ISO_9797_M2 Padding by left.
    This padding is done in the following way: before the original data a byte '80' is added 
    in order for the whole block to have a length in bytes that is a multiple of 8
    If original data length is already a multiple of 8, no padding is needed
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
    Then, in order for the whole block to have a length in bytes that is a multiple of 8, null bytes can be added
    (byte '80' and null bytes are optional and not present in case the length is already a multiple of 8)
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
    Remove a ISO_9797_M2 Padding into data and returns the new data
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
        offset = offset - 1
        return toHexString(data_bytes[0:offset])




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

def SHA1(data):
    ''' return the SHA-1 algorithm on data '''
    # remove space if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def SHA224(data):
    ''' return the SHA 224 algorithm on data '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.SHA224(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def SHA256(data):
    ''' return the SHA 256 algorithm on data '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def SHA384(data):
    ''' return the SHA 384 algorithm on data '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def SHA512(data):
    ''' return the SHA 512 algorithm on data '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()

def MD5(data):
    ''' return the MD5 algorithm on data '''
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    data_bytes  = bytes.fromhex(data)
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(data_bytes)
    dg = digest.finalize()
    return dg.hex().upper()


def generate_RSA_keys(exponent, key_size = 1024 ):
    #TODO: need to put comments
    # call the library key generation
    private_key = rsa.generate_private_key(public_exponent = int(exponent,16), key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()
    
    # get the public key implementation values in order to create our own public key class
    public_numbers = public_key.public_numbers()
    n = public_numbers.n
    e = public_numbers.e
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
    
    # create our RSA private key object
    privateKey = RSA_private_key(p, q, d, dmp1, dmq1, iqmp, private_key)
    
    return privateKey, publicKey


def build_RSA_keys(public_modulus, public_exponent, p, q, d, dmp1, dmq1, iqmp):
    #TODO: need to put comments
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

def RSA_signature(message, private_key, padding_algorithm = 'PKCS1', hash_algorithm = 'SHA1'):
    #TODO: need to put comments
    import re
    message = ''.join( re.split( '\W+', message.upper() ) )
    # managing the padding
    pad = padding.PKCS1v15
    if padding_algorithm == 'PKCS1':
        pad = padding.PKCS1v15()
    elif padding_algorithm == 'PSS':
        pad = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.PSS.MAX_LENGTH)
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
    #TODO: need to put comments

    # remove space if any
    import re
    message = ''.join( re.split( '\W+', message.upper() ) )
    signature = ''.join( re.split( '\W+', signature.upper() ) )
    
    # managing the padding
    pad = padding.PKCS1v15
    if padding_algorithm == 'PKCS1':
        pad = padding.PKCS1v15()
    elif padding_algorithm == 'PSS':
        pad = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.PSS.MAX_LENGTH)
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
    #TODO: need to put comments
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
    #TODO: need to put comments
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


def generate_DSA_keys(key_size = 1024 ):
    #TODO: need to put comments
    # call the library key generation
    private_key = dsa.generate_private_key(key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()
    
    # get the public key implementation values in order to create our own public key class
    public_numbers = public_key.public_numbers()
    p = public_numbers.parameter_numbers.p
    g = public_numbers.parameter_numbers.g
    q = public_numbers.parameter_numbers.q
    y = public_numbers.y
    # create our DSA public key object
    publicKey = DSA_public_key(p, q, g, y, public_key )

    # get the private key implementation values in order to create our own private key class
    private_numbers = private_key.private_numbers()
    p = private_numbers.public_numbers.parameter_numbers.p
    g = private_numbers.public_numbers.parameter_numbers.g
    q = private_numbers.public_numbers.parameter_numbers.q
    x = private_numbers.x
    # create our DSA private key object
    privateKey = DSA_private_key(p, q, g, x, private_key)
    
    return privateKey, publicKey


def build_DSA_keys(p, q, g, public_key, private_key):
    #TODO: need to put comments
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
    #TODO: need to put comments
    # call the library key generation
    parameters = dh.generate_parameters(int(generator,16), key_size, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    # get the public key implementation values in order to create our own public key class
    public_numbers = public_key.public_numbers()
    p = public_numbers.parameter_numbers.p
    g = public_numbers.parameter_numbers.g
    y = public_numbers.y
    # create our DH public key object
    publicKey = DH_public_key(p, g, y, public_key )

    # get the private key implementation values in order to create our own private key class
    private_numbers = private_key.private_numbers()
    p = private_numbers.public_numbers.parameter_numbers.p
    g = private_numbers.public_numbers.parameter_numbers.g
    x = private_numbers.x
    # create our DH private key object
    privateKey = DH_private_key(p, g, x, private_key)
    
    return privateKey, publicKey


def build_DH_keys(p, g, private_key, public_key):
    #TODO: need to put comments
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
    #TODO: need to put comments
    shared_secret = private_key.exchange(public_key) 
    return shared_secret


class RSA_public_key():

    def __init__(self, public_modulus, public_exponent, key_implementation = None):
        
        self.public_modulus = public_modulus
        self.public_exponent = public_exponent
        self.key_implementation = key_implementation
    
    def get_modulus(self):
        return str(self.public_modulus)

    def get_exponent(self):
        
        return str(self.public_exponent)
    
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


    def build(self):
        ''' build the RSA Public key object matching the crypto library used '''
        RSAPublic = rsa.RSAPublicNumbers(int(self.public_exponent,16), int(self.public_modulus,16))
        self.key_implementation = RSAPublic.public_key(backend=default_backend())
        
    
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
    
    def get_p(self):
        return str(self.p)
    def get_q(self):
        return str(self.q)
    def get_d(self):
        return str(self.d)
    def get_dmp1(self):
        return str(self.dmp1)
    def get_dmq1(self):
        return str(self.dmq1)
    def get_iqmp(self):
        return str(self.iqmp)
    
    def set_public_key(self, modulus, exponent):
        self.public_modulus = modulus
        self.public_exponent = exponent

    
    def sign(self, message, padding = padding.PKCS1v15(), hash_algorithm = hashes.SHA1()):
        message_bytes  = bytes.fromhex(message)
        signature = self.key_implementation.sign(message_bytes,padding, hash_algorithm)
        return signature.hex().upper()

    def build(self):
       
        # build the DSA Private key object matching the crypto library used
        RSAPublic = rsa.RSAPublicNumbers(int(self.public_exponent,16), int(self.public_modulus,16))
        RSA_private_numbers = rsa.RSAPrivateNumbers(int(self.p, 16), int(self.q, 16), int(self.d, 16), int(self.dmp1, 16), int(self.dmq1, 16), int(self.iqmp, 16) ,RSAPublic)
        self.key_implementation = RSA_private_numbers.private_key(backend=default_backend())
    
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
