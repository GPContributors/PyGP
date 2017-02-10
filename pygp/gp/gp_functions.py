import pygp.crypto as crypto
from pygp.logger import *
from pygp.connection.connection import *
from pygp.error import *
from pygp.constants import *
from pygp.gp.gp_crypto import *
import pygp.loadfile as loadfile
from pygp.tlv import *



# global variable for gp_functions
last_apdu_response = None
last_apdu_status   = None

def last_response():
    global last_apdu_response
    return last_apdu_response

def last_status():
    global last_apdu_status
    return last_apdu_status


def __check_security_info__(security_info):
    if security_info == None:
        error_status = create_error_status(ERROR_NO_SECURITY_INFO_INITIALIZED, runtimeErrorDict[ERROR_NO_SECURITY_INFO_INITIALIZED])
        return error_status
    else:
        error_status = create_no_error_status(0x00)
    return error_status


def select_channel(card_context, card_info, logical_channel): 
    log_start("select_channel")
    
    # check the parameter value
    if logical_channel < 0x00 or logical_channel > 0x03:
        error_status = create_error_status(INVALID_LOGICAL_CHANNEL_NUMBER, runtimeErrorDict[INVALID_LOGICAL_CHANNEL_NUMBER])
        log_info("\tSelected logical channel unchanged (%-0.2X)" %card_info['logicalChannel'])
        return error_status
    
    # set the value into the cardinfo dictionary
    card_info['logicalChannel'] = logical_channel
    error_status = create_no_error_status(ERROR_STATUS_SUCCESS)
    log_info("\tLogical channel has changed to %-0.2X" %card_info['logicalChannel'])
    
    log_end("select_channel", error_status)
    
    return error_status



def wrap_command(security_info, capdu):
    ''' Wrap APDU according to the security info '''
    #TODO: update doc
    

    log_start("wrap_command")

    # no security level defined, just return
    if (security_info == None):
        error_status = create_no_error_status(ERROR_STATUS_SUCCESS)
        return error_status, capdu

    # trivial case, just return
    if security_info['securityLevel'] == SECURITY_LEVEL_NO_SECURE_MESSAGING:
        error_status = create_no_error_status(ERROR_STATUS_SUCCESS)
        return error_status, capdu

    # Determine which type of Exchange between the reader
    # Convert capdu from string to list of bytes
    bytelist_capdu = toByteArray(capdu)
    
    ISO_case = -1
    Le = None

    if len(bytelist_capdu) == 4:
        ISO_case = CASE_1

    elif len(bytelist_capdu) == 5:
        ISO_case = CASE_2S
        Le = bytelist_capdu[4]

    else:
        if (bytelist_capdu[4] != 0):
            if (bytelist_capdu[4] == len(bytelist_capdu) - 5):
                ISO_case = CASE_3S
            elif (bytelist_capdu[4] == len(bytelist_capdu) - 6):
                ISO_case = CASE_4S
                Le = bytelist_capdu[-1:]
            else:
                pass


    if ISO_case == -1:
        # create the status error structure
        error_status = create_error_status(ERROR_UNRECOGNIZED_APDU_COMMAND, runtimeErrorDict[ERROR_UNRECOGNIZED_APDU_COMMAND])
        return error_status, ''
    
    # Manage ISO case: Get Le if any and prepare APDU

    apdu_to_wrap = []

           
    # C_MAC on modified APDU
    if (    security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i04 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i05 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i14 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i15 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i55 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i45 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i54 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i44 or
            security_info['secureChannelProtocol'] == GP_SCP03):
                

                ############## ISO Case 1 & 2 ##############
                if ISO_case == CASE_1:
                    apdu_to_wrap = bytelist_capdu
                    # put lc with the length of the mac
                    apdu_to_wrap[4] = 0x08

                elif ISO_case == CASE_2S:
                    Le = bytelist_capdu[-1:]
                    apdu_to_wrap = bytelist_capdu
                    # put lc with the length of the mac
                    apdu_to_wrap[4] = 0x08
               
                elif ISO_case == CASE_3S:
                    apdu_to_wrap = bytelist_capdu
                    # put lc with the length of the mac
                    apdu_to_wrap[4] = apdu_to_wrap[4] + 0x08
                    
                elif ISO_case == CASE_4S:
                    Le = bytelist_capdu[-1:]
                    apdu_to_wrap = bytelist_capdu[:-1]
                    # put lc with the length of the mac
                    apdu_to_wrap[4] = apdu_to_wrap[4] + 0x08
                        
                else:
                    # create the status error structure
                    error_status = create_error_status(ERROR_UNRECOGNIZED_APDU_COMMAND, runtimeErrorDict[ERROR_UNRECOGNIZED_APDU_COMMAND])
                    return error_status, None
                
                #CLA - indicate security level 1 or 3
                apdu_to_wrap[0] = bytelist_capdu[0] | 0x04
    else:
        # C_MAC on unmodified APDU
        ############## ISO Case 1 & 2 ##############
            if ISO_case == CASE_1:
                apdu_to_wrap = bytelist_capdu
                # put lc with the length of the mac
                apdu_to_wrap[4] = 0x00

            elif ISO_case == CASE_2S:
                Le = bytelist_capdu[:-1]
                apdu_to_wrap = bytelist_capdu
                # put lc with the length of the mac
                apdu_to_wrap[4] = 0x00
                
            elif ISO_case == CASE_4S:
                Le = bytelist_capdu[:-1]
                apdu_to_wrap = bytelist_capdu[:-1]

                    
            else:
                # create the status error structure
                error_status = create_error_status(ERROR_UNRECOGNIZED_APDU_COMMAND, runtimeErrorDict[ERROR_UNRECOGNIZED_APDU_COMMAND])
                return error_status, None

        

    # ICV encryption
    iv = None
    if security_info['secureChannelProtocol'] == GP_SCP02:
        if (security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i14 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i15 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i1A or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i1B or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i54 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i55) :

                iv = encipher_iv_SCP02(security_info['lastC_MAC'], security_info['C_MACSessionKey'][:16])
                
                

    elif(security_info['secureChannelProtocol']== GP_SCP03):
        iv = crypto.ISO_9797_M1_Padding_left(intToHexString(security_info['icv_counter'],2), 16)
        iv = encipher_iv_SCP03(iv, security_info['encryptionSessionKey'])
        
   
    else:
        error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
        log_end("wrap_command")
        return error_status, None


    # Get the data field of the APDU
    encData = apdu_to_wrap[5:]
    # if we have to encrypt:
    if  (security_info['securityLevel'] == SECURITY_LEVEL_C_DEC_C_MAC or
        security_info['securityLevel'] == SECURITY_LEVEL_C_DEC_C_MAC or
        security_info['securityLevel'] == SECURITY_LEVEL_C_DEC_C_MAC_R_MAC):
        # retrieve only the data field (ie: remove APDU header)
        apdu_data_field = apdu_to_wrap[5:]

        # cipher data
        if security_info['secureChannelProtocol'] == GP_SCP02:
            encData = encipher_data_SCP02(toHexString(apdu_data_field), security_info['encryptionSessionKey'] , crypto.ICV_NULL_8)
            encData = toByteArray(encData) # type mismatch
            

            log_debug("wrap_command: encrypted data field: %s" %toHexString(encData))
        
        elif(security_info['secureChannelProtocol']== GP_SCP03):
            encData = encipher_data_SCP03(toHexString(apdu_data_field), security_info['encryptionSessionKey'] , iv)
            
            encData = toByteArray(encData) # type mismatch
            # re put lc with the length of the encipher data
            apdu_to_wrap[4] = len(encData) + 8 # enc data 
            
            
    
    # MAC calculation
    if security_info['secureChannelProtocol'] == GP_SCP02:
        mac = calculate_mac_SCP02(toHexString(apdu_to_wrap), security_info['C_MACSessionKey'], iv)
        # re put lc with the length of the encipher data
        apdu_to_wrap[4] = len(encData) + 8# enc data 
            

    elif(security_info['secureChannelProtocol']== GP_SCP03):
        mac = calculate_mac_SCP03(toHexString(apdu_to_wrap[:5]) + toHexString(encData), security_info['C_MACSessionKey'], security_info['lastC_MAC'])
        pass
    else:
        error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
        log_end("wrap_command")
        return error_status, None

            
    log_debug("wrap_command: Data for MAC computation: %s" %toHexString(apdu_to_wrap))
    log_debug("wrap_command: ICV for MAC: %s" %iv)
    log_debug("wrap_command: Generated MAC: %s" %mac)
    
    #update the last iv
    security_info['lastC_MAC'] = mac
    
    # create the wrapped APDU
    if security_info['secureChannelProtocol'] == GP_SCP02:
        wrappedAPDU = toHexString( apdu_to_wrap[:5]) + toHexString(encData) + mac
    

    elif(security_info['secureChannelProtocol'] == GP_SCP03):
        wrappedAPDU = toHexString( apdu_to_wrap[:5]) + toHexString(encData) + mac[:16]
        # don't forget tp update the counter for ICV_NULL_8
        security_info['icv_counter'] = security_info['icv_counter'] + 1
       

    else:
        error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
        log_end("wrap_command")
        return error_status, None


    # we have to put Le bytes !! and manage RMAC level
    if Le != None:
        wrappedAPDU = wrappedAPDU + toHexString(Le)

    error_status = create_no_error_status(0x00)

    log_end("wrap_command", error_status)

    return error_status, wrappedAPDU


def unwrap_command(security_info, rapdu):
    ''' unwrap APDU response according to the security info '''
    #TODO: update doc
   

    log_start("unwrap_command")

    # no security level defined, just return
    if (security_info == None):
        error_status = create_no_error_status(ERROR_STATUS_SUCCESS)
        log_end("unwrap_command")
        return error_status, rapdu

    # trivial case, just return
    if  (security_info['securityLevel'] != SECURITY_LEVEL_R_MAC or
        security_info['securityLevel']  != SECURITY_LEVEL_C_MAC_R_MAC or
        security_info['securityLevel']  != SECURITY_LEVEL_C_DEC_C_MAC_R_MAC or
        security_info['securityLevel']  != SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC) :
            
            error_status = create_no_error_status(ERROR_STATUS_SUCCESS)
            log_end("unwrap_command")
            return error_status, rapdu
    
    # convert to byte array
    bytelist_rapdu = toByteArray(rapdu)
    if security_info['secureChannelProtocol'] == GP_SCP02:
        # only status word so no RMAC
        if len(bytelist_rapdu) == 2:
            return error_status, rapdu
        #TODO
    

    elif(security_info['secureChannelProtocol'] == GP_SCP03):
        # only status word so no RMAC
        if len(bytelist_rapdu) == 2:
            return error_status, rapdu
        #TODO
       

    else:
        error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
        log_end("unwrap_command")
        return error_status, None


def send_APDU(card_context, card_info, securityInfo, capdu): 
    
    global last_apdu_response
    global last_apdu_status
    
    log_start("send_APDU")
    #TODO: check context ? managing security info wrapp the command

    # wrap command
    error_status, c_wrapped_apdu = wrap_command(securityInfo, capdu)
    if error_status['errorStatus'] != 0x00:
        log_end("send_APDU", error_status['errorStatus'])
        return error_status, None

    error_status, rapdu = send_apdu(card_context, card_info, c_wrapped_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("send_APDU", error_status['errorStatus'])
        return error_status, None
    

    error_status, c_unwrapped_rapdu = unwrap_command(securityInfo, rapdu)
    # update global variables
    last_apdu_response = c_unwrapped_rapdu[:-4] # response without status
    last_apdu_status   = c_unwrapped_rapdu[-4:] # only  status
    
    # check if it is an ISO7816 status word error
    error_status = check_ISO7816_status_word(rapdu)

    #log_end("send_APDU", error_status['errorStatus'])
    
    return error_status, rapdu
    

def select_issuerSecurityDomain(card_context, card_info):
    

    log_start("select_issuerSecurityDomain")

    capdu = "00 A4 04 00 00"
    
    #TODO: check context ?

    error_status, rapdu = send_APDU(card_context, card_info, None, capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("select_issuerSecurityDomain", error_status['errorStatus'])
        return error_status

    log_end("select_issuerSecurityDomain", error_status['errorStatus'])
    
    return error_status

def select_application(card_context, card_info, str_AID):
    

    log_start("select_application")

    capdu = "00 A4 04 00 " + lv (str_AID)
    
    #TODO: check context ?

    error_status, rapdu = send_APDU(card_context, card_info, None, capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("select_application", error_status['errorStatus'])
        return error_status
   
    return error_status

def set_status(card_context, card_info, securityInfo, cardElement, lifeCycleState, aid):
    
    log_start("set_status")
    # supress blank if any
    import re
    aid = ''.join( re.split( '\W+', aid.upper() ) )

    capdu = "80 F0 " + cardElement + lifeCycleState + + lv (aid)
    
    #TODO: check context ?

    error_status, rapdu = send_APDU(card_context, card_info, securityInfo, capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("set_status", error_status['errorStatus'])
        return error_status
   
    return error_status

def delete_application(card_context, card_info, securityInfo,  str_AID):
    

    log_start("delete_application")

    capdu = "80 E4 00 00 " + lv ('4F' + lv(str_AID))
    
    #TODO: check context ?

    error_status, rapdu = send_APDU(card_context, card_info, securityInfo, capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("select_application", error_status['errorStatus'])
        return error_status
   
    return error_status

def delete_package(card_context, card_info, securityInfo,  str_AID):
    

    log_start("delete_package")

    capdu = "80 E4 00 80 " + lv ('4F' + lv(str_AID))
    
    #TODO: check context ?

    error_status, rapdu = send_APDU(card_context, card_info, securityInfo, capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("delete_package", error_status['errorStatus'])
        return error_status
   
    return error_status

def get_cplc_data(card_context, card_info, security_info):
    
   
    log_start("get_cplc_data")

   
    capdu = "80 CA 9F 7F 00"
    

    error_status, rapdu = send_APDU(card_context, card_info, security_info, capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("get_cplc_data", error_status['errorStatus'])
        return error_status, None
    
    # no error so display results
    
    response_tlv = TLV(toByteArray(last_response()))
    
    # check the tag
    if response_tlv.getTAG() != '9F7F':
        error_status = create_error_status(ERROR_INVALID_RESPONSE_DATA, runtimeErrorDict[ERROR_INVALID_RESPONSE_DATA])
        return error_status, None
    
 
    log_end("get_cplc_data", error_status['errorStatus'])

    return error_status, response_tlv.getValue()


def get_key_information_template(card_context, card_info, security_info):
    
   
    log_start("get_key_information_template")

   
    capdu = "80 CA 00 E0 00"
    

    error_status, rapdu = send_APDU(card_context, card_info, security_info, capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("get_key_information_template", error_status['errorStatus'])
        return error_status, None
    
    # no error so display results
    # key information is list of Tuple : (Key id, Key version number,  KeyLength, KeyType)
    keyInformation = []
    response_tlv = TLV(toByteArray(last_response()))

    # check the tag
    if response_tlv.getTAG() != 'E0':
        error_status = create_error_status(ERROR_INVALID_RESPONSE_DATA, runtimeErrorDict[ERROR_INVALID_RESPONSE_DATA])
        return error_status, None
    # manage the list of TLV with tag C0 into this response_tlv
    key_info_list = response_tlv.list_childs_tlv() 
    for key_info in key_info_list:

        if key_info.getTAG()  != 'C0':
            error_status = create_error_status(ERROR_INVALID_RESPONSE_DATA, runtimeErrorDict[ERROR_INVALID_RESPONSE_DATA])
            return error_status, None
        else:
            index  = 0
            KeyIdentifier = key_info.getValue()[index: index + 2]
            index = index + 2
            KeyVersionNumber = key_info.getValue()[index: index + 2]
            index = index + 2
            #check key type : if coded with 2 bytes the key is in format 2
            KeyTypeIndex = key_info.getValue()[index: index + 2]
            
            if (KeyTypeIndex == 'FF'):
                p_bool_Iskey_format2 = True
                index = index + 2
                while (KeyTypeIndex == 'FF'):
                    KeyType = key_info.getValue()[index: index + 2] # 1 byte
                    KeyLength= key_info.getValue()[index + 2: index + 6] # 2 bytes 
                    keyInformation.append((KeyIdentifier, KeyVersionNumber, KeyLength, KeyTypeIndex + KeyType))
                    KeyTypeIndex = key_info.getValue()[index + 6: index + 8]
                    index  = index + 8
                #get the key usage and key access
                keyUsageLength = KeyTypeIndex
                if keyUsageLength != '00':
                    keyUsage =key_info.getValue()[index: index + 2]
                    index = index + 2
            
                keyAccessLength = key_info.getValue()[index: index + 2]
                if keyAccessLength != '00':
                    keyAccess = key_info.getValue()[index + 2: index + 4]
                    index = index + 4
                else:
                    index = index + 2
            
            else:
                while index < (len(key_info.getValue())):                             
                    KeyType = key_info.getValue()[index: index + 2]
                    index = index + 2
                    KeyLength= key_info.getValue()[index: index + 2]
                    index = index + 2 
                    keyInformation.append((KeyIdentifier, KeyVersionNumber, KeyLength, KeyType))




    log_end("get_key_information_template", error_status['errorStatus'])

    return error_status, keyInformation


def store_data(card_context, card_info, security_info, data):
    
    log_start("store_data")
    block_size =239 # 255 bytes minus 8 byte MAC minus 8 byte encryption padding
    block_number = 0x00
    
    # supress blank if any
    import re
    data = ''.join( re.split( '\W+', data.upper() ) )
    # convert to byte array
    bytelist_data = toByteArray(data)
    remaining_bytes = len(bytelist_data)
    read_bytes = 0x00
    while remaining_bytes > 0:
        # build the APDU
        capdu = "80 E2 "
        if remaining_bytes <= block_size:
            capdu = capdu + '80' + intToHexString(block_number)
            capdu = capdu + lv(toHexString(bytelist_data[read_bytes:read_bytes + remaining_bytes]) )
            read_bytes = read_bytes + remaining_bytes
            remaining_bytes = remaining_bytes - remaining_bytes
        else:
            capdu = capdu + '00' + intToHexString(block_number)
            capdu = capdu + lv(toHexString(bytelist_data[read_bytes:read_bytes + block_size]) )
            read_bytes = read_bytes + block_size
            remaining_bytes = remaining_bytes - block_size

        # send the APDU
        error_status, rapdu = send_APDU(card_context, card_info, security_info, capdu)
        block_number = block_number + 1

        if error_status['errorStatus'] != 0x00:
            log_end("store_data", error_status['errorStatus'])
            return error_status
    
    
    if error_status['errorStatus'] != 0x00:
        log_end("get_data", error_status['errorStatus'])
        return error_status
    
    log_end("store_data", error_status['errorStatus'])

    return error_status



def get_data(card_context, card_info, security_info, identifier):
    
  
    log_start("get_data")

    # build the APDU
    # supress blank if any
    import re
    identifier = ''.join( re.split( '\W+', identifier.upper() ) )
    # check the size of the identifier (it is a string so 2 byte correspond to 4 characters )
    if len(identifier) < 0x00 or len(identifier) > 0x04:
        # identifier must be 1 or two byte string
        error_status = create_error_status(ERROR_WRONG_DATA, runtimeErrorDict[ERROR_WRONG_DATA])
        return error_status
    
    capdu = "80 CA "
    
    if len(identifier) == 0x04:
         capdu = capdu +  identifier + '00'
    else:
        #one byte identifier
        capdu = capdu +  identifier + '00'  + '00'

    #TODO: check context ?

    error_status, rapdu = send_APDU(card_context, card_info, security_info, capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("get_data", error_status['errorStatus'])
        return error_status
    
    log_end("get_data", error_status['errorStatus'])

    return error_status


def get_status(card_context, card_info, security_info, card_element):
    
  
    log_start("get_status")

    # build the APDU
    # supress blank if any
    import re
    card_element = ''.join( re.split( '\W+', card_element.upper() ) )
   
    capdu = "80 F2 " + card_element + "02 02 4F 00" + "00"
    
    #TODO: check context ?

    error_status, rapdu = send_APDU(card_context, card_info, security_info, capdu)
    
    if error_status['errorStatus'] != 0x00:
        log_end("get_status", error_status['errorStatus'])
        return error_status, None
    
    # store the response
    card_response = last_response()
    # check if more data available
    while last_status() == '6310':
        # send a get status next occurence
        capdu = "80 F2 " + card_element + "03 02 4F 00" + "00"
        error_status, rapdu = send_APDU(card_context, card_info, security_info, capdu)
    
        if error_status['errorStatus'] != 0x00:
            log_end("get_status", error_status['errorStatus'])
            return error_status, None
        
        card_response = card_response + last_response()
    
    # we have the card_response TLV. create the get status response dictionnary
    response_tlvs = TLVs(toByteArray(card_response))
    app_info_list = []
    app_aid = None
    app_lifecycle = None
    app_privileges = None
    app_modules_aid = None

    for response_tlv in response_tlvs.list_childs_tlv():
        if response_tlv.getTAG() == 'E3':
            # manage the list of TLV into this response_tlv
            app_info_tlv_list = response_tlv.list_childs_tlv() 
            for app_info in app_info_tlv_list:
                if app_info.getTAG() == '4F':
                    app_aid = app_info.getValue()
                if app_info.getTAG() == '9F70':
                    app_lifecycle = app_info.getValue()
                if app_info.getTAG() == 'C5':
                    app_privileges = app_info.getValue()
                if app_info.getTAG() == '84':
                    app_modules_aid = app_info.getValue()
            app_info_list.append({'aid':app_aid, 'lifecycle':app_lifecycle[:2], 'privileges':app_privileges, 'module_aid':app_modules_aid})
        


    else:
        error_status = create_no_error_status(0x00)

    
    log_end("get_status", error_status['errorStatus'])

    return error_status, app_info_list

def initialize_update(card_context, card_info, key_set_version , base_key, enc_key , mac_key , dek_key ,  scp, scp_implementation ):
        
    global last_apdu_response
    global last_apdu_status

    log_start("initialize_update")
    # create a host challenge
    hostChallenge = crypto.RANDOM(8)
    
    log_debug("initialize_update: Host challenge Data: %s " % hostChallenge)
    # create the initialize update APDU command (with Le = Max data)
    initUpdateAPDU = '80' + '50' + key_set_version + '00 08' + hostChallenge + '00'
    #TODO: check context ?
    error_status, rapdu = send_APDU(card_context, card_info, None,  initUpdateAPDU)
    
    if error_status['errorStatus'] != 0x00:
        log_end("initialize_update", error_status['errorStatus'])
        return error_status, None, None

    

   
    # creation of the security info structure needed for all GP operations
    securityInfo = {}

    # managing authentication data
    bytearray_initUpdateResponse = toByteArray(last_apdu_response)
    # check init_update_response length, it must be 28, 29 or 32 bytes
    # SCP01/SCP02 = 30 bytes, SCP03 31 or 34 bytes
    if len (bytearray_initUpdateResponse) != 28 and len (bytearray_initUpdateResponse) != 29 and len (bytearray_initUpdateResponse) != 32:
        error_status = create_error_status(ERROR_INVALID_RESPONSE_DATA, runtimeErrorDict[ERROR_INVALID_RESPONSE_DATA])
        return error_status, None, None
    
    # managing response of INITIALIZE UPDATE
    keyDiversificationData = bytearray_initUpdateResponse[:10]
    keyInformationData = bytearray_initUpdateResponse[10:12]
   
    # check if a scp has been set by the user, if not take the scp into the init update response
    if scp == None:
        scp = keyInformationData[1]
    
    # test if reported SCP is consistent with passed SCP
    if scp != keyInformationData[1]:
        error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
        return error_status, None, None
    
    # update the security information structure
    securityInfo['secureChannelProtocol'] = scp

    
    # in SCP03 the scp implementation value is returned by the init update response
    # in SCP02 this value is not present so this value should be set by the user.
    if securityInfo['secureChannelProtocol'] == GP_SCP02:
        if scp_implementation == None:
            error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
            return error_status, None, None
    
    if securityInfo['secureChannelProtocol'] == GP_SCP03:
        # key information data on 3 bytes
        keyInformationData = bytearray_initUpdateResponse[10:13]
        scpi = keyInformationData[2]
        if scp_implementation == None:
            scp_implementation = intToHexString(scpi)
        else:
            #test if reported SCP implementation is consistent with passed SCP implementation
            if scp_implementation != scpi:
                error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
                return error_status, None, None
            



    securityInfo['secureChannelProtocolImpl'] = scp_implementation
    securityInfo['keySetVersion'] = keyInformationData[0]
    # we set it to a dummy value
    securityInfo['keyIndex'] = 0xFF

    if securityInfo['secureChannelProtocol'] == GP_SCP02:
        # manage init update response
        sequenceCounter = bytearray_initUpdateResponse[12:14] 
        cardChallenge= bytearray_initUpdateResponse[14:20] # 6 bytes
        cardCryptogram = bytearray_initUpdateResponse[20:28] # 8 bytes
    
    if securityInfo['secureChannelProtocol'] == GP_SCP03:
        # manage init update response
        cardChallenge= bytearray_initUpdateResponse[13:21] # 8 bytes
        cardCryptogram = bytearray_initUpdateResponse[21:29] # 8 bytes
        sequenceCounter = bytearray_initUpdateResponse[29:32] # 3 bytes
    

    log_debug("initialize_update: Key Diversification Data: %s " % toHexString(keyDiversificationData))

    log_debug("initialize_update: Key Information Data: %s " % toHexString(keyInformationData))

    log_debug("initialize_update: Card Challenge:  %s " % toHexString(cardChallenge))

    log_debug("initialize_update: Sequence Counter:  %s " % toHexString(sequenceCounter))

    log_debug("initialize_update: Card Cryptogram  %s " % toHexString(cardCryptogram))
    # only present when pseudo-random challenge generation is used
    #if (secInfo->secureChannelProtocol == GP_SCP03 && recvBufferLength == 34) {
#       OPGP_LOG_HEX(_T("mutual_authentication: Sequence Counter: "), sequenceCounter, 3);
    #}
    # create session key regarding the scp implementation 
    
    if securityInfo['secureChannelProtocol'] == GP_SCP02:
        ## Secure Channel base key
        if  (securityInfo['secureChannelProtocolImpl'] == SCP02_IMPL_i04 or
            securityInfo['secureChannelProtocolImpl'] == SCP02_IMPL_i14 or
            securityInfo['secureChannelProtocolImpl'] == SCP02_IMPL_i44 or
            securityInfo['secureChannelProtocolImpl'] == SCP02_IMPL_i54):

            # calculation of encryption session key using on base key
            securityInfo['encryptionSessionKey'] = create_session_key_SCP02(base_key, KENC_TYPE, sequenceCounter)
            # calculation of C-MAC session key
            securityInfo['C_MACSessionKey'] = create_session_key_SCP02(baseKey, KMAC_TYPE, sequenceCounter)
            #calculation of R-MAC session key
            securityInfo['R_MACSessionKey'] = create_session_key_SCP02(baseKey, KRMAC_TYPE, sequenceCounter)
            #calculation of data encryption session key
            securityInfo['dataEncryptionSessionKey'] = create_session_key_SCP02(baseKey, KDEK_TYPE, sequenceCounter)


            
        ## 3 Secure Channel Keys */
        elif (securityInfo['secureChannelProtocolImpl']  == SCP02_IMPL_i05 or
            securityInfo['secureChannelProtocolImpl']   == SCP02_IMPL_i15 or
            securityInfo['secureChannelProtocolImpl']   == SCP02_IMPL_i55 or
            securityInfo['secureChannelProtocolImpl']   == SCP02_IMPL_i45):
                
            # calculation of encryption session key using on 3 static key
            securityInfo['encryptionSessionKey'] = create_session_key_SCP02(enc_key, KENC_TYPE, toHexString(sequenceCounter))
            # calculation of C-MAC session key
            securityInfo['C_MACSessionKey'] = create_session_key_SCP02(mac_key, KMAC_TYPE, toHexString(sequenceCounter))
            #calculation of R-MAC session key
            securityInfo['R_MACSessionKey'] = create_session_key_SCP02(dek_key, KRMAC_TYPE, toHexString(sequenceCounter))
            #calculation of data encryption session key
            securityInfo['dataEncryptionSessionKey'] = create_session_key_SCP02(dek_key, KDEK_TYPE, toHexString(sequenceCounter))
            
        else:
            error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
            return error_status, None, None

    elif securityInfo['secureChannelProtocol'] == GP_SCP03:

        # calculation of encryption session key using on 3 static key
        session_key_value  = create_session_key_SCP03(enc_key, KENC_TYPE, toHexString(cardChallenge), hostChallenge)
        if session_key_value == None:
            error_status = create_error_status(ERROR_SESSION_KEY_CREATION, runtimeErrorDict[ERROR_SESSION_KEY_CREATION])
            return error_status, None, None
        else:
           securityInfo['encryptionSessionKey'] = session_key_value
        
        # calculation of C-MAC session key
        session_key_value  = create_session_key_SCP03(mac_key, KMAC_TYPE , toHexString(cardChallenge), hostChallenge)
        if session_key_value == None:
            error_status = create_error_status(ERROR_SESSION_KEY_CREATION, runtimeErrorDict[ERROR_SESSION_KEY_CREATION])
            return error_status, None, None
        else:
            securityInfo['C_MACSessionKey'] = session_key_value
        #calculation of R-MAC session key
        session_key_value  = create_session_key_SCP03(dek_key, KRMAC_TYPE, toHexString(cardChallenge), hostChallenge)
        if session_key_value == None:
            error_status = create_error_status(ERROR_SESSION_KEY_CREATION, runtimeErrorDict[ERROR_SESSION_KEY_CREATION])
            return error_status, None, None
        else:
            securityInfo['R_MACSessionKey'] = session_key_value
        # calculation of data encryption session key
        # warning: no session key for data encryption in SCP03
        # session_key_value  = create_session_key_SCP03(dek_key, KDEK_TYPE , toHexString(cardChallenge), hostChallenge)
        # if session_key_value == None:
        #     error_status = create_error_status(ERROR_SESSION_KEY_CREATION, runtimeErrorDict[ERROR_SESSION_KEY_CREATION])
        #     return error_status, None, None
        # else:
        securityInfo['dataEncryptionSessionKey'] = dek_key
    
    else:
        error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
        return error_status, None, None

    
    #ifdef OPGP_DEBUG
    log_debug("initialize_update: S-ENC Session Key: %s" %securityInfo['encryptionSessionKey'])
    log_debug("initialize_update: S-MAC Session Key: %s" %securityInfo['C_MACSessionKey'])
    log_debug("initialize_update:   DEK Session Key: %s" %securityInfo['dataEncryptionSessionKey'])
    log_debug("initialize_update: R-MAC Session Key: %s" %securityInfo['R_MACSessionKey'])



    if securityInfo['secureChannelProtocol'] == GP_SCP02:
        offcardCryptogram = calculate_card_cryptogram_SCP02(toHexString(sequenceCounter), toHexString(cardChallenge), hostChallenge, securityInfo['encryptionSessionKey'])
    elif securityInfo['secureChannelProtocol'] == GP_SCP03:
        offcardCryptogram = calculate_card_cryptogram_SCP03(toHexString(cardChallenge), hostChallenge, securityInfo['C_MACSessionKey'])
    else:
        error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
        return error_status, None, None

    # compare cryptograms
    if toHexString(cardCryptogram) != offcardCryptogram:
        error_status = create_error_status(ERROR_CARD_CRYPTOGRAM_VERIFICATION, runtimeErrorDict[ERROR_CARD_CRYPTOGRAM_VERIFICATION])
        return error_status , None, None


    host_cryptogram = None
    if securityInfo['secureChannelProtocol'] == GP_SCP02:
        host_cryptogram = calculate_host_cryptogram_SCP02(toHexString(sequenceCounter), toHexString(cardChallenge), hostChallenge, securityInfo['encryptionSessionKey'])

    elif  securityInfo['secureChannelProtocol'] == GP_SCP03:
        host_cryptogram = calculate_host_cryptogram_SCP03(toHexString(cardChallenge), hostChallenge, securityInfo['C_MACSessionKey'])

    else:
        error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
        return error_status, None, None
    

    error_status = create_no_error_status(0x00)
    log_end("initialize_update", error_status['errorStatus'])
    return error_status, securityInfo, host_cryptogram


def external_authenticate(card_context, card_info, security_info, security_level, host_cryptogram):


    log_start("external_authenticate")

    # create the external authenticate APDU command
    externalAuthAPDU = '84' + '82' + intToHexString(security_level) + '00' + '10' + host_cryptogram

    if  security_info['secureChannelProtocol'] == GP_SCP03:
        mac = calculate_mac_SCP03(externalAuthAPDU, security_info['C_MACSessionKey'], crypto.ICV_NULL_16)
        security_info['lastC_MAC'] = mac
        security_info['icv_counter'] = 0x01
        # add the mac to the command
        externalAuthAPDU = externalAuthAPDU + mac[:16]

    elif security_info['secureChannelProtocol'] == GP_SCP02:

        mac = calculate_mac_SCP02(externalAuthAPDU, security_info['C_MACSessionKey'], crypto.ICV_NULL_8)
        security_info['lastC_MAC'] = mac
        # add the mac to the command
        externalAuthAPDU = externalAuthAPDU + mac

    else:
        error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
        return error_status


    #TODO: check context ?
    error_status, rapdu = send_APDU(card_context, card_info, None,  externalAuthAPDU)

    if error_status['errorStatus'] != 0x00:
        log_end("external_authenticate", error_status['errorStatus'])
        return error_status


    #update security info
    security_info['securityLevel'] = security_level
        
    log_end("external_authenticate", error_status['errorStatus'])
    return error_status

def install_install(card_context, card_info, security_info, make_selectable, executable_LoadFile_AID, executable_Module_AID, application_AID, application_privileges = "00", application_specific_parameters = None, install_parameters = None, install_token = None):
    log_start("install_install_and_make_selectable")
    
    error_status = __check_security_info__(security_info)
    if error_status['errorStatus'] != 0x00:
        log_end("install_install", error_status['errorStatus'])
        return error_status
    
    # build the APDU
    # mandatory fields
    install_apdu_data = lv(remove_space(executable_LoadFile_AID)) +  lv(remove_space(executable_Module_AID)) +  lv(remove_space(application_AID)) + lv(application_privileges)
    # optionnal fields
    parameter_field = ''
    if application_specific_parameters != None:
        parameter_field = parameter_field + 'C9' + lv(remove_space(application_specific_parameters))
    else:
        parameter_field =parameter_field + 'C903000000'
    
    if install_parameters != None:
        parameter_field = parameter_field + 'EF' + lv(remove_space(install_parameters))
    else:
        parameter_field =parameter_field + 'EF00'

    if install_token != None:
        install_token = lv(install_token)
    else:
        install_token =  '00' #no token


    if make_selectable == True:
        install_apdu = '80 E6 0C 00'  + lv(install_apdu_data  + lv(parameter_field) + install_token)
    else:
        install_apdu = '80 E6 04 00'  + lv(install_apdu_data + lv(parameter_field) + install_token)
    

    
    #TODO: check context ?
    error_status, rapdu = send_APDU(card_context, card_info, security_info,  install_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("install_install", error_status['errorStatus'])
        return error_status

        
    log_end("install_install", error_status['errorStatus'])
    return error_status
        

def install_load(card_context, card_info, security_info, executable_load_file_aid, security_domain_aid, load_file_data_block_hash = None, load_parameters = None, load_token = None):
    log_start("install_load")
    
    error_status = __check_security_info__(security_info)
    if error_status['errorStatus'] != 0x00:
        log_end("install_load", error_status['errorStatus'])
        return error_status
    
    # build the APDU
    # mandatory fields
    install_apdu = lv(remove_space(executable_load_file_aid)) +  lv(remove_space(security_domain_aid))
    # optionnal fields
    if load_file_data_block_hash != None:
        install_apdu = install_apdu + lv(remove_space(load_file_data_block_hash))
    else:
        install_apdu = install_apdu + '00'
    
    if load_parameters != None:
        install_apdu = install_apdu + lv('EF' + lv(remove_space(load_parameters)))
    else:
        install_apdu = install_apdu + '00' #no parameter

    if load_token != None:
        install_apdu = install_apdu + lv(load_token)
    else:
        install_apdu = install_apdu + '00' #no token

    install_apdu = '80 E6 02 00'  + lv(install_apdu) 
    
    #TODO: check context ?
    error_status, rapdu = send_APDU(card_context, card_info, security_info,  install_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("install_load", error_status['errorStatus'])
        return error_status

        
    log_end("install_load", error_status['errorStatus'])
    return error_status

def load_blocks(card_context, card_info, security_info, load_file_path, block_size = 32):
    log_start("load_blocks")
    
    error_status = __check_security_info__(security_info)
    if error_status['errorStatus'] != 0x00:
        log_end("load_blocks", error_status['errorStatus'])
        return error_status
    
    block_number = 0x00

    load_file_obj = loadfile.Loadfile(load_file_path)

    log_debug("load_blocks: load_file_obj: %s" %load_file_obj.__str__())

    all_blocks_data = load_file_obj.get_load_blocks(block_size)

    for block in all_blocks_data:  
        blockNumber = intToHexString(block_number)
        is_last_block = (block == all_blocks_data[-1])

        if is_last_block == True:
            load_apdu = '80' + 'E8' + '80' + blockNumber + lv(block)
        else:
            load_apdu = '80' + 'E8' + '00'+ blockNumber + lv(block)

        #TODO: check context ?
        error_status, rapdu = send_APDU(card_context, card_info, security_info,  load_apdu)

        if error_status['errorStatus'] != 0x00:
            log_end("extradite", error_status['errorStatus'])
            return error_status
        
        block_number = block_number + 1
    
    log_end("load_blocks", error_status['errorStatus'])
    return error_status





def extradite(card_context, card_info, security_info, security_domain_AID, application_aid, identification_number = None,  image_Number = None, application_provider_identifier = None, token_identifier = None, extraditeToken = None):
    log_start("extradite")
    
    error_status = __check_security_info__(security_info)
    if error_status['errorStatus'] != 0x00:
        log_end("extradite", error_status['errorStatus'])
        return error_status
    

    strControlReferenceTemplate     = ''
    str_ExtraditionParametersfield  = ''
    
    if (identification_number != None):
        strControlReferenceTemplate  += "42" + lv(remove_space(identification_number))
    
    if (image_Number != None):
        strControlReferenceTemplate  += "45" + lv(remove_space(image_Number))
    
    if (application_provider_identifier != None):
        strControlReferenceTemplate  += "5F20" + lv(remove_space(application_provider_identifier))
    
    if (strControlReferenceTemplate != ''):
        str_ExtraditionParametersfield = str_ExtraditionParametersfield + "B6"
        str_ExtraditionParametersfield = str_ExtraditionParametersfield + lv(strControlReferenceTemplate)
    
    # build the APDU
    extradite_apdu = lv(remove_space(security_domain_AID)) + '00' +  lv(remove_space(application_aid)) + '00'  + lv(str_ExtraditionParametersfield)
        
    if extraditeToken != None:
        extradite_apdu = extradite_apdu + lv(extraditeToken)
    else:
        extradite_apdu = extradite_apdu + '00' #no token

    extradite_apdu = '80 E6 10 00'  + lv(extradite_apdu)
    
    #TODO: check context ?
    error_status, rapdu = send_APDU(card_context, card_info, security_info,  extradite_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("extradite", error_status['errorStatus'])
        return error_status

        
    log_end("extradite", error_status['errorStatus'])
    return error_status


def put_key(card_context, card_info, security_info, key_version_number, key_identifier, key_type, key_value, replace = False ):
    
    log_start("put_key")
    
    error_status = __check_security_info__(security_info)
    if error_status['errorStatus'] != 0x00:
        log_end("put_key", error_status['errorStatus'])
        return error_status

    # build the extradition parameter fields
    
    if replace == False:
        p1 = '00'
    else:
        p1 = key_version_number

    # cipher key regarding the SCP protocol
    if  security_info['secureChannelProtocol'] == GP_SCP03:
        cipher_key, cipher_key_kcv = cipher_key_SCP03(key_value, security_info['dataEncryptionSessionKey'] )
        cipher_key_len = intToHexString(int(len(cipher_key)/2))
        put_key_apdu = '80 D8' + p1 + '01' + lv(key_version_number + key_type_coding_dict[key_type] + lv( cipher_key_len + cipher_key) + lv(cipher_key_kcv))
        

    elif security_info['secureChannelProtocol'] == GP_SCP02:

        cipher_key, cipher_key_kcv = cipher_key_SCP02(key_value, security_info['dataEncryptionSessionKey'] )
        put_key_apdu = '80 D8' + p1 + '01' + lv(key_version_number + key_type_coding_dict[key_type] + lv(cipher_key) + lv(cipher_key_kcv))


    else:
        error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
        return error_status
    
  
    #TODO: check context ?
    error_status, rapdu = send_APDU(card_context, card_info, security_info,  put_key_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("put_key", error_status['errorStatus'])
        return error_status

        
    log_end("put_key", error_status['errorStatus'])
    return error_status
    

def put_scp_key(card_context, card_info, security_info, key_version_number, key_list, replace = False ):

    log_start("put_scp_key")

    error_status = __check_security_info__(security_info)
    if error_status['errorStatus'] != 0x00:
        log_end("put_key", error_status['errorStatus'])
        return error_status

    # build the extradition parameter fields

    if replace == False:
        p1 = '00'
    else:
        p1 = key_version_number

    apdu_data = key_version_number
    # cipher key regarding the SCP protocol
    if  security_info['secureChannelProtocol'] == GP_SCP03:
        for ( key_vn, key_id, key_type, key_value ) in key_list:
            cipher_key, cipher_key_kcv = cipher_key_SCP03(key_value, security_info['dataEncryptionSessionKey'] )
                        
            apdu_data = apdu_data + key_type_coding_dict[key_type]  + lv( getLength(key_value) + cipher_key) + lv(cipher_key_kcv)

    elif security_info['secureChannelProtocol'] == GP_SCP02:
        
        for ( key_vn, key_id, key_type, key_value ) in key_list:
            cipher_key, cipher_key_kcv = cipher_key_SCP02(key_value, security_info['dataEncryptionSessionKey'] )
            apdu_data = apdu_data  + key_type_coding_dict[key_type]  + lv(cipher_key) + lv(cipher_key_kcv)
 
    else:
        error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
        return error_status

    put_scp_key_apdu = '80 D8' + p1 + '81' + lv(apdu_data)
    #TODO: check context ?
    error_status, rapdu = send_APDU(card_context, card_info, security_info,  put_scp_key_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("put_scp_key", error_status['errorStatus'])
        return error_status

        
    log_end("put_scp_key", error_status['errorStatus'])
    return error_status   


    


        
    


