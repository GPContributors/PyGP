import importlib
from pygp.connection.pcsc import *
from pygp.utils import *
from pygp.error import *
from pygp.logger import *


# global variable indicating the connection module to use
# PCSC by default
connection_module = importlib.import_module("pygp.connection.pcscconnection")

# Global variables 
context      = None
cardinfo     = None

# ISO case
CASE_1        = 0x01
CASE_2S        = 0x02
CASE_2E        = 0x2E    
CASE_3S        = 0x03
CASE_3E        = 0x3E    
CASE_4S        = 0x04
CASE_4E        = 0x4E

# APDU Direction
TO_CARD        = 0x01
TO_READER   = 0x02

'''
Protocol values;
'''
SCARD_PROTOCOL_UNDEFINED    = 0x00000000
SCARD_PROTOCOL_T0           = 0x00000001
SCARD_PROTOCOL_T1           = 0x00000002
SCARD_PROTOCOL_RAW          = 0x00010000
SCARD_PROTOCOL_Tx           = (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)

def __check_context__():
    global card_context

    if card_context == None:
        error_status = create_error_status(ERROR_NO_CARD_CONTEXT_INITIALIZED, runtimeErrorDict[ERROR_NO_CARD_CONTEXT_INITIALIZED])
    else:
        error_status = create_no_error_status(0x00)
    return error_status

def __check_card_info__():
    global card_info

    if card_info == None:
        error_status = create_error_status(ERROR_NO_CARD_INFO_INITIALIZED, runtimeErrorDict[ERROR_NO_CARD_INFO_INITIALIZED])
        return error_status
    else:
        error_status = create_no_error_status(0x00)
    return error_status

def create_card_info_dict(p_str_atr, p_byte_logicalChannel, p_str_specVersion, p_byte_protocol, p_handle_card):
    global card_info

    card_info = {}
    card_info['atr']  = p_str_atr 
    card_info['logicalChannel']  = p_byte_logicalChannel 
    card_info['specVersion']  = p_str_specVersion 
    card_info['protocol']  = p_byte_protocol
    card_info['cardHandle']  = p_handle_card 
    return card_info

def establish_context():
    global connection_module
    global card_context
    error_status, card_context = connection_module.establish_context()
    return error_status

def release_context():
    global connection_module
    global card_context
    error_status = connection_module.release_context(card_context)

    context = None
    cardInfo = None
    return error_status

def card_connect(reader_name,  protocol):
    global connection_module
    global card_context
    global card_info
    error_status, card_info = connection_module.card_connect(card_context, reader_name, protocol)
    return error_status
    
def card_disconnect(disposition ):
    global connection_module
    global card_info
    return connection_module.card_disconnect(card_info, disposition )

def list_readers():
    global connection_module
    global card_context
    return connection_module.list_readers(card_context )

def getATR():
    global card_context
    global card_info
    return card_info['atr']



def send_apdu(capdu):
    global connection_module

    error_status = __check_context__()
    if error_status['errorStatus'] != 0x00:
        return error_status
    
    error_status = __check_card_info__()
    if error_status['errorStatus'] != 0x00:
        return error_status

    

    #convert capdu from string to list of bytes
    bytelist_capdu = toByteArray(capdu)
    
    # manage the selected channel
    bytelist_capdu[0] |= card_info['logicalChannel']
    log_apdu(TO_CARD, bytelist_capdu)
    if card_info['protocol'] == SCARD_PROTOCOL_T1:
        error_status, rapdu = connection_module.send_apdu_T1(card_info, bytelist_capdu)
        return error_status, toHexString(rapdu)
    else:
        # T=0 management
        ISO_case = -1
        if len(bytelist_capdu) == 4:
            ISO_case = CASE_1
        elif len(bytelist_capdu) == 5:
            ISO_case = CASE_2S
        else:
             if len(bytelist_capdu) > 5:
                if (bytelist_capdu[4] != 0):
                    if (bytelist_capdu[4] == len(bytelist_capdu) - 5):
                        ISO_case = CASE_3S
                    elif (bytelist_capdu[4] == len(bytelist_capdu) - 6):
                        ISO_case = CASE_4S
                else:   # bytelist_capdu[4] == 0
                    if (len(bytelist_capdu) == 7):
                        ISO_case = CASE_2E
                
                    elif (len(bytelist_capdu) > 7):
                        Lc = bytelist_capdu[5]
                        Lc = (Lc << 8) + bytelist_capdu[6]
                        if (Lc == len(bytelist_capdu) - 7):
                            ISO_case = CASE_3E

                        elif (Lc == len(bytelist_capdu) - 9):
                            ISO_case = CASE_4E
                        else:
                            pass


        if ISO_case == -1:
            # create the status structure
            error_status = create_error_status(ERROR_UNRECOGNIZED_APDU_COMMAND, runtimeErrorDict[ERROR_UNRECOGNIZED_APDU_COMMAND])
            return error_status, ''
        else:
            ############## ISO Case 1 ##############
            if ISO_case == CASE_1:
                # CASE_1: send APDu without any changes
                error_status, bytelist_rapdu = connection_module.send_apdu_T0(card_info, bytelist_capdu)

                log_apdu(TO_READER, bytelist_rapdu)

                return error_status, toHexString(bytelist_rapdu)
            
            ############## ISO Case 2S and Case 3S ##############
            elif ISO_case == CASE_2S or ISO_case == CASE_3S:
                # CASE_2S: send APDU without any changes but manage the card response
                error_status, bytelist_rapdu = connection_module.send_apdu_T0(card_info, bytelist_capdu)
                if error_status['errorCode'] != ERROR_STATUS_SUCCESS:
                    return error_status, ''
                # manage card response
                
                # status word: 6C
                if len(bytelist_rapdu) == 0x02 and bytelist_rapdu[0] == 0x6C:
                    log_management_apdu(TO_READER,bytelist_rapdu)
                    # resend the command with the rigth Le but keeping the first Le bytes ask by the user
                    if ISO_case == CASE_2S:
                        # case 2s data asked are returned
                        capdu_Le = bytelist_capdu[4]
                    else:
                        # case 3S all data must be returned
                        capdu_Le = len(bytelist_rapdu)
                    
                    if capdu_Le == 0x00:
                        capdu_Le = 256
                    bytelist_capdu[4] = bytelist_rapdu[1]
                    #resend the command
                    log_management_apdu(TO_CARD,bytelist_capdu)
                    error_status, bytelist_rapdu = connection_module.send_apdu_T0(card_info, bytelist_capdu)
                    log_management_apdu(TO_READER, bytelist_rapdu)
                    
                    log_apdu(TO_READER, bytelist_rapdu)

                    if error_status['errorCode'] != ERROR_STATUS_SUCCESS:
                        return error_status, ''


                    
                    # manage card response
                    if len(bytelist_rapdu) < capdu_Le:
                        # return all the card response
                        return error_status, toHexString(bytelist_rapdu)
                    else:
                        #returns the first Le bytes with the status
                        rapdu = toHexString(bytelist_rapdu[0:capdu_Le])
                        rapdu = rapdu + toHexString(bytelist_rapdu[-2:])
                        return error_status, rapdu
                
                # status word: 61
                elif len(bytelist_rapdu) == 0x02 and bytelist_rapdu[0] == 0x61: 
                    # resend the command with the rigth Le but keeping the first Le bytes ask by the user
                    
                    bytelist_capdu_getResponse = []
                    bytelist_capdu_getResponse.append(0x00)
                    bytelist_capdu_getResponse.append(0xC0)
                    bytelist_capdu_getResponse.append(0x00)
                    bytelist_capdu_getResponse.append(0x00)
                    bytelist_capdu_getResponse.append(bytelist_rapdu[1])
                    # perform a get response with the Le ask by the user
                    log_management_apdu(TO_CARD, bytelist_capdu_getResponse)
                    error_status, bytelist_rapdu = connection_module.send_apdu_T0(card_info, bytelist_capdu_getResponse)
                    log_management_apdu(TO_READER,bytelist_rapdu)
                    log_apdu(TO_READER, bytelist_rapdu)

                    if error_status['errorCode'] != ERROR_STATUS_SUCCESS:
                        return error_status, ''
                    
                    # return all the card response
                    return error_status, toHexString(bytelist_rapdu)
                else:
                    # return all the card response
                    log_apdu(TO_READER, bytelist_rapdu)
                    return error_status, toHexString(bytelist_rapdu)

            
            ############## ISO Case 4S ##############
            elif ISO_case == CASE_4S:
                # CASE_4S: send APDU without Le and manage the output data after
                error_status, bytelist_rapdu = connection_module.send_apdu_T0(card_info, bytelist_capdu[:-1])
                if error_status['errorCode'] != ERROR_STATUS_SUCCESS:
                    return error_status, ''
                # manage card response
                # status word: 61
                if len(bytelist_rapdu) == 0x02 and (bytelist_rapdu[0] == 0x61 or bytelist_rapdu[0] == 0x90):
                    log_management_apdu(TO_READER,bytelist_rapdu)
                    le     = bytelist_capdu[-1]
                    cardLe = bytelist_rapdu[1]
                    if le == 0x00:
                        le = 256
                    if cardLe == 0x00:
                        cardLe = 256
                    Le_to_send = le

                    if bytelist_rapdu[0] != 0x90: # rapdu == 9000 
                        Le_to_send = min(le, cardLe)

                    #send a get response with the good Le_to_send
                    bytelist_capdu_getResponse = []
                    bytelist_capdu_getResponse.append(0x00)
                    bytelist_capdu_getResponse.append(0xC0)
                    bytelist_capdu_getResponse.append(0x00)
                    bytelist_capdu_getResponse.append(0x00)
                    bytelist_capdu_getResponse.append(Le_to_send)

                    log_management_apdu(TO_CARD, bytelist_capdu_getResponse)

                    #copy the data to an intermediate buffer to restore it in case of a broken ISO implementation not supporting GET RESPONSE on 0x9000
                    store_bytelist_rapdu = bytelist_rapdu
                    bytelist_rapdu = []
                    error_status, bytelist_rapdu = connection_module.send_apdu_T0(card_info, bytelist_capdu_getResponse)
                    
                    log_management_apdu(TO_READER,bytelist_rapdu)

                    if bytelist_rapdu[0] == 0x6E and bytelist_rapdu[0] == 0x00:
                        #if the result is 0x6E00 then this should be a broken ISO implementation not supporting GET RESPONSE on 0x9000 and we return the previous response data
                        bytelist_rapdu = store_bytelist_rapdu
                    
                    log_apdu(TO_READER, bytelist_rapdu)

                    if error_status['errorCode'] != ERROR_STATUS_SUCCESS:
                        return error_status, ''
                    
                    # return all the card response
                    return error_status, toHexString(bytelist_rapdu)
                else:
                    # return all the card response
                    log_apdu(TO_READER, bytelist_rapdu)
                    return error_status, toHexString(bytelist_rapdu)
                
            


 
    
    # create the status structure
#    error_status = handle_retCode(retCode)
#    return error_status, toHexString(bytelist_rapdu)

    

