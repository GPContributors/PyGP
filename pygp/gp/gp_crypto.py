import pygp.logger as logger
from pygp.error import *
from pygp.constants import *
import pygp.crypto as crypto


def __SCP03_KDF_CounterMode__( data, key, counter):

    bytearray_data = toByteArray(data)            
    
    # perform a loop of aes with derivation data
    result = ''
    for i in range(int(counter)):
        tempResult = crypto.AES_CMAC(toHexString(bytearray_data),key )
        result  = result + tempResult
        #update index with 1
        bytearray_data[15] = bytearray_data[15] + 1
        
    # get only a dedicated value depending of the key size
    keyFormat_High = bytearray_data[13]
    keyFormat_Low = bytearray_data[14]
    
    if keyFormat_Low == 0x40 and keyFormat_High == 0x00:
        return result[:16]
    if keyFormat_Low == 0x80 and keyFormat_High == 0x00:
        return result[:32]
    if keyFormat_Low == 0xC0 and keyFormat_High == 0x00:
        return result[:48]
    if keyFormat_Low == 0x00 and keyFormat_High == 0x10:
        return result[:64]
    else:
        return None


    return result

def calculate_card_challenge_SCP02(data, key):
    '''
    Calculate the card challenge in case of pseudo ramdom

    :param data (str): Data uses to calculate card challenge.
    :param key (str) : The Secure Channel Message Authentication Code Key.

	:returns: (tuple): tuple containing:
			- class:`ErrorStatus` with error status ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the class :class:`ErrorStatus`.
			- The card challenge (str) if no error occurs, None otherwize.
    '''
    logger.log_start("calculate_card_challenge_SCP02")
    
    logger.log_debug(" Calculate card challenge using %s " %data)
    
    error_status, challenge =  compute_mac(data, key, crypto.ICV_NULL_8 )
    
    logger.log_end("calculate_card_challenge_SCP02", error_status.status)
    
    # card challenge is the 6 first bytes of the MAC
    return challenge[0:6*2]




def calculate_card_challenge_SCP03(data, key):
    '''
    Calculate the card challenge in case of pseudo ramdom

    :param data (str): Data uses to calculate card challenge.
    :param key (str) : The Secure Channel Message Authentication Code Key.

	:returns: (tuple): tuple containing:
			- class:`ErrorStatus` with error status ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the class :class:`ErrorStatus`.
			- The card challenge (str) if no error occurs, None otherwize.
    '''
    logger.log_start("calculate_card_challenge_SCP03")
    
    logger.log_debug(" Calculate card challenge using %s " %data)
    SCP03_CST_DERIVATION_CARD_CHALLENGE = '02'
                
    # 1. first build the derivation data
    der_data = ''
    der_data = '00 00 00 00 00 00 00 00 00 00 00' + SCP03_CST_DERIVATION_CARD_CHALLENGE
    der_data += '00'                                                           

    der_data += '0040'                                                         
    der_data += '01'                                                           
        
    der_data += data
    # 2. calculate cryptogram
    cryptogram = __SCP03_KDF_CounterMode__(der_data, key, 0x01 )
         
    logger.log_end("calculate_card_challenge_SCP03")

    return cryptogram



def calculate_card_cryptogram_SCP02(sequenceCounter, cardChallenge, hostChallenge, session_enc_key):
    '''
    Calculates the card cryptogram for SCP02.
    
    :param sequenceCounter (str): The sequence counter.
    :param cardChallenge (str): The card challenge.
    :param hostChallenge (str): The host challenge.
    :param key (str) : The Session Encryption Key for calculating the card cryptogram.

	:returns: (tuple): tuple containing:
			- class:`ErrorStatus` with error status ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the class :class:`ErrorStatus`.
			- The card cryptogram (str) if no error occurs, None otherwize.
    

    '''
    
    logger.log_start("calculate_card_cryptogram_SCP02")
 
    data = hostChallenge + sequenceCounter + cardChallenge
 
    logger.log_debug("\tCalculates card cryptogram using %s " %data)
 
    # padd data if needed
    data = crypto.ISO_9797_M2_Padding(data, 8)
 
    logger.log_debug("\tData padded: %s " %data)
 
    #calculate the cryptogram
    cryptogram = crypto.MAC33(data, session_enc_key, crypto.ICV_NULL_8)
 
    logger.log_debug("\tCard cryptogram: %s " %cryptogram)
 
    logger.log_end("calculate_card_cryptogram_SCP02")
 
    return cryptogram


def calculate_card_cryptogram_SCP03(cardChallenge, hostChallenge, session_mac_key):
    '''
    Calculates the card cryptogram for SCP03.
    
    :param cardChallenge (str): The card challenge.
    :param hostChallenge (str): The host challenge.
    :param key (str) : The Secure Channel Message Authentication Code Key.

	:returns: str: The card cryptogram if no error occurs, None otherwize.
    

    '''
    SCP03_CST_DERIVATION_CARD_CRYPTO = '00'
    logger.log_start("calculate_card_cryptogram_SCP03")
    
    data = hostChallenge + cardChallenge

    # 1. first build the derivation data
    der_data = ''
    der_data = '00 00 00 00 00 00 00 00 00 00 00' + SCP03_CST_DERIVATION_CARD_CRYPTO
    der_data += '00'                                                           

    der_data += '0040'                                                         
    der_data += '01'                                                           
        
    der_data += data

    logger.log_debug("\tCalculates card cryptogram using %s " %der_data)
    
    # 2. calculate cryptogram
    cryptogram = __SCP03_KDF_CounterMode__(der_data, session_mac_key, 0x01 )
    
    logger.log_debug("\tCard cryptogram: %s " %cryptogram)
 
    logger.log_end("calculate_card_cryptogram_SCP03")

    return cryptogram
 

 
    # padd data if needed
    data = crypto.ISO_9797_M2_Padding(data, 8)
 
    logger.log_debug("\tData padded: %s " %data)
 
    #calculate the cryptogram
    cryptogram = crypto.MAC33(data, session_enc_key, crypto.ICV_NULL_8)
 
    logger.log_debug("\tCard cryptogram: %s " %cryptogram)
 
    logger.log_end("calculate_card_cryptogram_SCP02")
 
    return cryptogram

def calculate_host_cryptogram_SCP02(sequenceCounter, cardChallenge, hostChallenge, session_enc_key):
    
    # padd data if needed
    logger.log_start("calculate_host_cryptogram_SCP02")
 
    data =  sequenceCounter + cardChallenge + hostChallenge
 
    logger.log_debug(" Calculates host cryptogram using %s " %data)

    data = crypto.ISO_9797_M2_Padding(data, 8)

    cryptogram = crypto.MAC33(data,session_enc_key, crypto.ICV_NULL_8)
    
    logger.log_debug("host cryptogram: %s " %cryptogram)
 
    logger.log_end("calculate_host_cryptogram_SCP02")

    return cryptogram

def calculate_host_cryptogram_SCP03(cardChallenge, hostChallenge, session_mac_key):
    
    # padd data if needed
    logger.log_start("calculate_host_cryptogram_SCP03")

    SCP03_CST_DERIVATION_HOST_CRYPTO = '01'
 
    data =  hostChallenge + cardChallenge
 
    # 1. first build the derivation data
    der_data = ''
    der_data = '00 00 00 00 00 00 00 00 00 00 00' + SCP03_CST_DERIVATION_HOST_CRYPTO
    der_data += '00'                                                           

    der_data += '0040'                                                         
    der_data += '01'  

    der_data += data

    logger.log_debug("\tCalculates host cryptogram using %s " %der_data)

    cryptogram = __SCP03_KDF_CounterMode__(der_data, session_mac_key, 0x01 )
    
    logger.log_debug("\tHost cryptogram: %s " %cryptogram)
 
    logger.log_end("calculate_host_cryptogram_SCP03")

    return cryptogram

def encipher_data_SCP02(data, key, iv):
    '''
    encipher message according to SCP02 protocol.
    
    :param str data : The message to authenticate.
    :param str key : A 3DES key used to encipher 
    :param str iv : The initial chaining vector

	:returns: (str): The enciphered data
    '''
    data = crypto.ISO_9797_M2_Padding(data, 8)
    return crypto.DES3_CBC(data, key, iv)


def encipher_data_SCP03(data, key, iv):
    '''
    encipher message according to SCP03 protocol.
    
    :param str data : The message to authenticate.
    :param str key : A AES key used to encipher 
    :param str iv : The initial chaining vector

	:returns: (str): The enciphered data
    '''
    data = crypto.ISO_9797_M2_Padding(data, 8)
    return crypto.AES_CBC(data, key, iv)

def encipher_iv_SCP02(data, key):
    '''
    encipher initial chaining vector according to SCP02 protocol.
    
    :param str data : The message to authenticate.
    :param str key : A 3DES key used to encipher 

	:returns: (str): The enciphered iv
    '''
    return crypto.DES_ECB(data, key)

def encipher_iv_SCP03(data, key):
    '''
    encipher initial chaining vector according to SCP03 protocol.
    
    :param str data : The message to authenticate.
    :param str key : A AES key used to encipher 

	:returns: (str): The enciphered iv
    '''
    return crypto.AES_CBC(data, key)

def calculate_mac_SCP02(data, key, iv):
    '''
    Computes a message authentication code according to SCP02 protocol.
    
    :param str data : The message to authenticate.
    :param str key : A 3DES key used to sign 
    :param str iv : The initial chaining vector

	:returns: (str): The calculated MAC
    '''
    # padd data if needed
    data = crypto.ISO_9797_M2_Padding(data, 8)
    return crypto.MAC3(data, key, iv)


def calculate_mac_SCP03(data, key, iv):
    '''
    Computes a message authentication code according to SCP03 protocol.
    
    :param str data : The message to authenticate.
    :param str key : A 3DES key used to sign 
    :param str iv : The initial chaining vector

	:returns: (str): The calculated MAC
    '''
    input_data = iv + data

    mac = crypto.AES_CMAC(input_data, key)

    return mac

def cipher_key_SCP02(key_value, key):
    '''
    cipher a sensitive key to SCP02 protocol.
    
    :param str key_value : The sensitive key to cipher.
    :param str key : A 3DES key used to sign 


	:returns: (str): The ciphered key with its key check value
    '''
    
    cipher_key = crypto.DES3_ECB(key_value, key)
    key_kcv = crypto.DES3_ECB(crypto.ICV_NULL_8, key_value  )
    key_kcv = key_kcv[0:6] #only the first 3 bytes
    return cipher_key,key_kcv 


def cipher_key_SCP03(key_value, key):
    '''
    cipher a sensitive key to SCP03 protocol.
    
    :param str key_value : The sensitive key to cipher.
    :param str key : A AES key used to sign 


	:returns: (str): The ciphered key with its key check value
    '''
    
    cipher_key = crypto.AES_CBC(key_value, key, crypto.ICV_NULL_16)
    key_kcv = crypto.AES_ECB('01010101010101010101010101010101', key_value)
    key_kcv = key_kcv[0:6] #only the first 3 bytes
    return cipher_key,key_kcv 


def create_session_key_SCP02(key, k_type, sequenceCounter ):
    '''
    Creates the session key according to SCP02 protocol.
    
    :param str key : The Secure Channel Encryption Key.
    :param str k_type : The key type of the key. 
    :param str sequenceCounter: The sequence counter.

	:returns: str the calculated 3DES session key.
    
    '''
    if k_type == KENC_TYPE:
        der_data = crypto.ISO_9797_M1_Padding('0182' + sequenceCounter, 16)
    elif k_type == KMAC_TYPE:
        der_data = crypto.ISO_9797_M1_Padding('0101' + sequenceCounter, 16)
    elif k_type == KDEK_TYPE:
        der_data = crypto.ISO_9797_M1_Padding('0181' + sequenceCounter, 16)
    elif k_type == KRMAC_TYPE:
        der_data = crypto.ISO_9797_M1_Padding('0102' + sequenceCounter, 16)
    else:
        raise BaseException("create session key for SCP02: key type not supported")

    return crypto.DES3_CBC(der_data, key, crypto.ICV_NULL_8)

def create_session_key_SCP03(key, k_type, cardChallenge, hostChallenge ):
    '''
    Creates the session key according to SCP03 protocol.
    
    :param str key : The Secure Channel Encryption Key.
    :param str k_type : The key type of the key. 
    :param str sequenceCounter: The sequence counter.

	:returns: str the calculated AES session key.
    
    '''
    SCP03_CST_DERIVATION_S_ENC = '04'
    SCP03_CST_DERIVATION_S_MAC = '06'
    SCP03_CST_DERIVATION_R_MAC = '07'
    # define derivation constants see amendement D
    CST_DERIVATION = ''
    if k_type == KENC_TYPE:
        CST_DERIVATION = SCP03_CST_DERIVATION_S_ENC
    elif k_type == KMAC_TYPE:
        CST_DERIVATION = SCP03_CST_DERIVATION_S_MAC
    elif k_type == KDEK_TYPE:
        CST_DERIVATION = SCP03_CST_DERIVATION_R_MAC
    elif k_type == KRMAC_TYPE:
        CST_DERIVATION = SCP03_CST_DERIVATION_R_MAC
    else:
        raise BaseException("create session key for SCP03: key type not supported")

    KDF_COUNTER_MAX_VALUE = '00'
      
          
    # 1. first build the derivation data for each type of keys
    der_data = ''
    der_data = '00 00 00 00 00 00 00 00 00 00 00' + CST_DERIVATION # 12 byte label consisting of 11 bytes with value 00 followed by a one byte derivation constant
    der_data += '00'  

    # get the length of the key (could be 16, 24, 32)
    key_length = len(toByteArray(key))

    if (key_length == 16):
        der_data += '0080'                                                         #A 2 byte integer L specifying the length in bits of the derived data (value 0040, 0080, 00C0 or 0100).
        der_data += '01'                                                           # A 1 byte counter i as specified in the KDF (which may take the values 01 or 02; value 02 is used when L takes the values 00C0 and 0100,
        KDF_COUNTER_MAX_VALUE = '01'
    elif (key_length == 24):
        der_data += '00C0'                                                           #A 2 byte integer L specifying the length in bits of the derived data (value 0040, 0080, 00C0 or 0100).
        #TODO : Voir si on met pas 02 comme dans la spec
        der_data += '01'                                                            # A 1 byte counter i as specified in the KDF (which may take the values 01 or 02; value 02 is used when L takes the values 00C0 and 0100,
        KDF_COUNTER_MAX_VALUE = '02'
    elif (key_length == 32):
        der_data += '0100'                                                          #A 2 byte integer L specifying the length in bits of the derived data (value 0040, 0080, 00C0 or 0100).
        #TODO : Voir si on met pas 02 comme dans la spec                            
        der_data += '01'                                                            # A 1 byte counter i as specified in the KDF (which may take the values 01 or 02; value 02 is used when L takes the values 00C0 and 0100,
        KDF_COUNTER_MAX_VALUE = '02'
    else:
       raise BaseException("create session key for SCP03: key size not supported")
        
    der_data += hostChallenge                                                 # Host challenge
    der_data += cardChallenge                                                 # card challenge
    
    # 2. Calculate session key
    sessionKey = __SCP03_KDF_CounterMode__(der_data, key , KDF_COUNTER_MAX_VALUE )

    return sessionKey