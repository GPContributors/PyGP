import time
import pygp.crypto as crypto
from pygp.logger import *
from pygp.connection.connection import *
from pygp.error import *
from pygp.constants import *
from pygp.gp.gp_crypto import *
import pygp.loadfile as loadfile
from pygp.tlv import *



# global variable for gp_functions
# information of each channel.
# [0] for channel 0, [1] for channel 1, [2] for channel 2, [3] for channel 3
# [4] it save current working channel number. This channel number used when sending APDU.
securityInfo       = [{'channelStatus':'ON'}, {}, {}, {}, 0]

last_apdu_response = None
last_apdu_status   = None
apdu_timing        = False

payload_mode_activated = False
payload_list       = []

total_time = 0.0

def clear_securityInfo():
    global securityInfo
    securityInfo = [{'channelStatus':'ON'}, {}, {}, {}, 0]

def get_payload_list():
    global payload_list
    return payload_list

def set_payload_mode(activate):
    global payload_mode_activated
    global payload_list
    payload_mode_activated = activate
    # clear the list on activation
    if (activate == True):
        payload_list.clear()

def last_response():
    global last_apdu_response
    return last_apdu_response

def last_status():
    global last_apdu_status
    return last_apdu_status

def set_apdu_timing(activated):
    global apdu_timing
    apdu_timing = activated

def set_start_timing():
    global total_time
    total_time = 0.0

def get_total_execution_time():
    return total_time

def __check_security_info__(security_info):
    if security_info == None:
        error_status = create_error_status(ERROR_NO_SECURITY_INFO_INITIALIZED, runtimeErrorDict[ERROR_NO_SECURITY_INFO_INITIALIZED])
        return error_status
    else:
        error_status = create_no_error_status(0x00)
    return error_status


def select_channel(logical_channel):
    global securityInfo

    log_start("select_channel")
    
    # Display All Channel Information
    logger.log_info("Channel Status Information [0~3]")
    logger.log_info("Channel SCP SCPi SecurityLevel AID")
    logger.log_info("------- --- ---- ------------- -----------------")
    channel_id = 0
    for sChannelInfo in securityInfo[0:4]:
        if (securityInfo[4] == channel_id):
            strWorking = '*'
        else:
            strWorking = ' '
        if (('channelStatus' in sChannelInfo.keys())  and (sChannelInfo['channelStatus'] == "ON")):
            if 'selectedAID' in sChannelInfo.keys():
                strAID = sChannelInfo['selectedAID']
            else:
                strAID = 'NONE'
            
            if 'secureChannelProtocolImpl' in sChannelInfo.keys():
                logger.log_info(" %s 0%d    %d   %s      %d        %s" \
                %(strWorking, channel_id, sChannelInfo['secureChannelProtocol'],\
                 sChannelInfo['secureChannelProtocolImpl'], sChannelInfo['securityLevel'], strAID ))
            else:
                logger.log_info(" %s 0%d   n/a  n/a      n/a     %s" % (strWorking, channel_id, strAID))
        else:
            logger.log_info("   0%d  CHANNEL NOT AVAILABLE" %(channel_id))

        channel_id += 1

    # check the parameter value
    if logical_channel == None or logical_channel < 0x00 or logical_channel > 0x03:
        error_status = create_error_status(INVALID_LOGICAL_CHANNEL_NUMBER, runtimeErrorDict[INVALID_LOGICAL_CHANNEL_NUMBER])
        log_info("\tSelected logical channel unchanged (%-0.2X)" % securityInfo[4])
        return error_status

    # check the status of logical channel
    sChannelInfo = securityInfo[logical_channel]
    if sChannelInfo['channelStatus'] == "ON":
        # set the working channel value
        securityInfo[4] = logical_channel
        error_status = create_no_error_status(ERROR_STATUS_SUCCESS)
        log_info("\tLogical channel has changed to %-0.2X" % securityInfo[4])
    else:
        error_status = create_error_status(ERROR_LOGICAL_CHANNEL_NOT_AVAILABLE, runtimeErrorDict[ERROR_LOGICAL_CHANNEL_NOT_AVAILABLE])
    
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

    # security_info level defined
    if ('securityLevel' in security_info) == False:
        error_status = create_error_status(ERROR_NO_SECURITY_INFO_INITIALIZED, runtimeErrorDict[ERROR_NO_SECURITY_INFO_INITIALIZED])
        return error_status, ''

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
        security_info['securityLevel'] == SECURITY_LEVEL_C_DEC_C_MAC_R_MAC or
        security_info['securityLevel'] == SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC):
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
        wrappedAPDU = toHexString(apdu_to_wrap[:5]) + toHexString(encData) + mac

    elif(security_info['secureChannelProtocol'] == GP_SCP03):
        wrappedAPDU = toHexString(apdu_to_wrap[:5]) + toHexString(encData) + mac[:16]
        # don't forget tp update the counter for ICV_NULL_8
        log_debug("wrap_command: current ICV counter: %s" %intToHexString(security_info['icv_counter'] ,2))
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
    error_status = create_no_error_status(ERROR_STATUS_SUCCESS)

    # no security level defined, just return
    if (security_info == None):
        error_status = create_no_error_status(ERROR_STATUS_SUCCESS)
        log_end("unwrap_command")
        return error_status, rapdu

    # trivial case, just return
    if  (security_info['securityLevel'] != SECURITY_LEVEL_R_MAC and
        security_info['securityLevel']  != SECURITY_LEVEL_C_MAC_R_MAC and
        security_info['securityLevel']  != SECURITY_LEVEL_C_DEC_C_MAC_R_MAC and
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
        else:

            # get the mac of the command (8 bytes before the rapdu status word)
            len_reponse_date_without_sw = len(bytelist_rapdu) - 2
            len_response_data_without_mac = len_reponse_date_without_sw - 8
            response_data_without_mac = bytelist_rapdu[0:len_response_data_without_mac]
            response_data_mac = bytelist_rapdu[ len_response_data_without_mac: len_reponse_date_without_sw]
            response_data_sw = bytelist_rapdu[len_reponse_date_without_sw:]
            log_debug("unwrap_command: Response MAC: %s" %toHexString(response_data_mac))
            # calculate the off card MAC
            mac = calculate_mac_SCP03(toHexString(response_data_without_mac) + toHexString(response_data_sw), security_info['R_MACSessionKey'], security_info['lastC_MAC'])
            log_debug("unwrap_command: Data for MAC computation: %s" %(toHexString(response_data_without_mac) + toHexString(response_data_sw)))
            log_debug("unwrap_command: ICV for Generated MAC: %s" %security_info['lastC_MAC'])
            log_debug("unwrap_command: Generated MAC: %s" %mac)
            if toHexString(response_data_mac) != mac[:16]: 
                error_status = create_error_status(ERROR_VALIDATION_R_MAC, runtimeErrorDict[ERROR_VALIDATION_R_MAC])
                log_end("unwrap_command")
                return error_status, None
            else:
                # check if we have to decipher the APDU
                if security_info['securityLevel']  == SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC:
                    if(security_info['secureChannelProtocol']== GP_SCP03):
                        log_debug("unwrap_command: current ICV counter: %s" %intToHexString(security_info['icv_counter'] - 1,2))
                        iv = crypto.ISO_9797_M2_Padding_left(intToHexString(security_info['icv_counter']-1 ,2), 16)
                        iv = encipher_iv_SCP03(iv, security_info['encryptionSessionKey'])
                        log_debug("unwrap_command: current ICV : %s " %iv)

                        # decipher data
                        decipher_data = decipher_data_SCP03(toHexString(response_data_without_mac), security_info['encryptionSessionKey'], iv)
                        decipher_data = crypto.Remove_ISO_9797_M2_Padding(decipher_data)
                        return error_status, decipher_data + toHexString(response_data_sw)
                    
                    pass
                else:
                    return error_status, toHexString(bytelist_rapdu)
       
    else:
        error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
        log_end("unwrap_command")
        return error_status, None


def send_APDU(capdu, raw_mode = False, exsw = None, exdata = None): 

    global securityInfo
    global last_apdu_response
    global last_apdu_status
    global apdu_timing
    global payload_mode_activated
    global payload_list
    global total_time
    
    log_start("send_APDU")
    #TODO: managing security info wrap the command

    if raw_mode == True:
        # no wrapping management, just send the apdu
        c_wrapped_apdu = capdu
    else:
        # get securityInfo of the channel
        currentChannel = securityInfo[4]
        securityInfoOfChannel = securityInfo[currentChannel]

        # wrap command
        error_status, c_wrapped_apdu = wrap_command(securityInfoOfChannel, capdu)
        if error_status['errorStatus'] != 0x00:
            log_end("send_APDU", error_status['errorStatus'])
            return error_status, None
    
    if payload_mode_activated == True:
        payload_list.append(remove_space(c_wrapped_apdu))
        error_status = create_no_error_status(0x00)
        return error_status, None
    else:
        #convert capdu from string to list of bytes
        bytelist_capdu = toByteArray(c_wrapped_apdu)

        if raw_mode == False:
            # manage the selected logical channel
            bytelist_capdu[0] |= securityInfo[4]

        start_time = time.perf_counter()

        error_status, rapdu = send_apdu(bytelist_capdu)

        end_time = time.perf_counter() 
        total_time = total_time + (end_time - start_time)
        
    if error_status['errorStatus'] != 0x00:
        log_end("send_APDU", error_status['errorStatus'])
        return error_status, None
    
    if raw_mode == True:
        c_unwrapped_rapdu = rapdu
    else:
        error_status, c_unwrapped_rapdu = unwrap_command(securityInfoOfChannel, rapdu)
        if error_status['errorStatus'] != 0x00:
            log_end("send_APDU", error_status['errorStatus'])
            return error_status, None

    if apdu_timing == True:
        log_info("command time: %3f ms" %(end_time - start_time))
    # update global variables
    last_apdu_response = c_unwrapped_rapdu[:-4] # response without status
    last_apdu_status   = c_unwrapped_rapdu[-4:] # only  status
    
    # check if it is an ISO7816 status word error
    if exsw == None:
        error_status = check_ISO7816_status_word(rapdu)
    else:
        # convert exsw to list, compare between expected status word and response.
        # The format of exsw "9000, 6Cxx, 6xxx"
        exsw = exsw.upper()
        exsw = exsw.replace(',', ' ')
        exsw = exsw.replace('X', 'F')
        byte_list_exsw = toByteArray(exsw)
        byte_list_sw = toByteArray(last_apdu_status)
        found = False
        for offset in range(0, len(byte_list_exsw), 2):
            if ((byte_list_exsw[offset] & byte_list_sw[-2]) == byte_list_sw[-2]):
                if ((byte_list_exsw[offset+1] & byte_list_sw[-1]) == byte_list_sw[-1]):
                    # the status word is same as our expectation
                    error_status = create_no_error_status(last_apdu_status)
                    found = True
        if found == False:
            error_status = create_error_status(last_apdu_status, "Differ with expected status word")
            log_error("expected status word " + exsw)
    #log_end("send_APDU", error_status['errorStatus'])
    
    if (exdata != None) and (error_status['errorStatus'] == 0x00):
        exdata = exdata.upper()
        exdata = exdata.replace(' ', '')
        for offset in range(0, len(exdata), 1):
            if exdata[offset] == 'X':
                continue
            elif exdata[offset] == rapdu[offset].upper():
                continue
            else:
                error_status = create_error_status(last_apdu_status, "Differ with expected data")
                log_error("expected data " + exdata)
                break

    return error_status, rapdu
    

def select_issuerSecurityDomain(logical_channel = 0):
    
    log_start("select_issuerSecurityDomain")

    if(logical_channel < 0 or logical_channel > 3):
        error_status = create_error_status(INVALID_LOGICAL_CHANNEL_NUMBER, runtimeErrorDict[INVALID_LOGICAL_CHANNEL_NUMBER])
        return error_status, None

    capdu = intToHexString(logical_channel, 1) + " A4 04 00 00"

    error_status, rapdu = send_APDU(capdu, raw_mode = True)

    if error_status['errorStatus'] != ERROR_STATUS_SUCCESS:
        log_end("select_issuerSecurityDomain", error_status['errorStatus'])
        return error_status, None
    
    if payload_mode_activated == False:
        # no error so the application is selected. now store its aid
        response_tlv = TLV(toByteArray(last_response()))

        # check the tag
        if response_tlv.getTAG() != '6F':
            error_status = create_error_status(ERROR_INVALID_RESPONSE_DATA, runtimeErrorDict[ERROR_INVALID_RESPONSE_DATA])
            return error_status, None
        
        for response_tlv in response_tlv.list_childs_tlv():
            if response_tlv.getTAG() == '84':
                current_selected_aid = response_tlv.getValue()
    else:
        current_selected_aid = ISD_APPLICATION_AID

    # there is no error. Do initialize securityInfo of selected channel
    securityInfo[4] = logical_channel
    securityInfo[logical_channel] = {}
    securityInfo[logical_channel]['securityLevel'] = SECURITY_LEVEL_NO_SECURE_MESSAGING
    securityInfo[logical_channel]['channelStatus'] = "ON"
    securityInfo[logical_channel]['selectedAID'] = current_selected_aid
    log_end("select_issuerSecurityDomain", error_status['errorStatus'], error_status['errorMessage'])

    return error_status, rapdu


def select_application(str_AID, logical_channel = 0):
    
    log_start("select_application")

    if(logical_channel < 0 or logical_channel > 3):
        error_status = create_error_status(INVALID_LOGICAL_CHANNEL_NUMBER, runtimeErrorDict[INVALID_LOGICAL_CHANNEL_NUMBER])
        return error_status, None

    capdu = intToHexString(logical_channel, 1) + " A4 04 00 " + lv (str_AID)
    
    error_status, rapdu = send_APDU(capdu, raw_mode = True)

    if error_status['errorStatus'] != ERROR_STATUS_SUCCESS:
        log_end("select_application", error_status['errorStatus'])
        return error_status, None
    
    # there is no error. Do initialize securityInfo of selected channel
    securityInfo[4] = logical_channel
    securityInfo[logical_channel] = {}
    securityInfo[logical_channel]['securityLevel'] = SECURITY_LEVEL_NO_SECURE_MESSAGING
    securityInfo[logical_channel]['channelStatus'] = "ON"
    securityInfo[logical_channel]['selectedAID'] = str_AID
    log_end("select_application", error_status['errorStatus'])

    return error_status, rapdu


def set_status(cardElement, lifeCycleState, aid):

    log_start("set_status")
    # supress blank if any
    import re
    aid = ''.join( re.split( '\W+', aid.upper() ) )

    capdu = "80 F0 " + cardElement + lifeCycleState + lv (aid)
    
    error_status, rapdu = send_APDU(capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("set_status", error_status['errorStatus'])
        return error_status
   
    log_end("set_status", error_status['errorStatus'])
   
    return error_status


def set_crs_status(status_type, status_value, aid):
    
    log_start("set_crs_status")
    # supress blank if any
    import re
    aid = ''.join( re.split( '\W+', aid.upper() ) )

    capdu = "80 F0 " + status_type + status_value + "4F" + lv(aid)
    
    error_status, rapdu = send_APDU(capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("set_crs_status", error_status['errorStatus'])
        return error_status, None
    
    log_end("set_crs_status", error_status['errorStatus'])

    #TODO: needs to parse the response data based on the GP Amdt.C Table 3-23
    
    return error_status, rapdu


def delete_application(str_AID, exsw):
    
    log_start("delete_application")

    capdu = "80 E4 00 00 " + lv ('4F' + lv(str_AID))
    
    error_status, rapdu = send_APDU(capdu, exsw = exsw)

    if error_status['errorStatus'] != 0x00:
        log_end("select_application", error_status['errorStatus'])
        return error_status

    log_end("select_application", error_status['errorStatus'])
   
    return error_status


def delete_package(str_AID, exsw):
    
    log_start("delete_package")

    capdu = "80 E4 00 80 " + lv ('4F' + lv(str_AID))
    
    error_status, rapdu = send_APDU(capdu, exsw = exsw)

    if error_status['errorStatus'] != 0x00:
        log_end("delete_package", error_status['errorStatus'])
        return error_status
   
    log_end("delete_package", error_status['errorStatus'])

    return error_status


def delete_key(KeyIdentifier, keyVersionNumber, exsw):
    
    log_start("delete_key")

    capdu = "80 E4 00 00 " + lv('D0' + lv(KeyIdentifier)) + lv('D2' + lv(keyVersionNumber))
    
    error_status, rapdu = send_APDU(capdu, exsw = exsw)

    if error_status['errorStatus'] != 0x00:
        log_end("delete_key", error_status['errorStatus'])
        return error_status
   
    log_end("delete_key", error_status['errorStatus'])

    return error_status


def get_cplc_data():
    
    log_start("get_cplc_data")

    capdu = "80 CA 9F 7F 00"
    
    error_status, rapdu = send_APDU(capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("get_cplc_data", error_status['errorStatus'])
        return error_status, None
    
    if payload_mode_activated == False:
        # no error so display results
        response_tlv = TLV(toByteArray(last_response()))
        
        # check the tag
        if response_tlv.getTAG() != '9F7F':
            error_status = create_error_status(ERROR_INVALID_RESPONSE_DATA, runtimeErrorDict[ERROR_INVALID_RESPONSE_DATA])
            return error_status, None
        
 
        log_end("get_cplc_data", error_status['errorStatus'])

        return error_status, response_tlv.getValue()
    else:
        return error_status, None


def get_key_information_template():
    
    log_start("get_key_information_template")

    capdu = "80 CA 00 E0 00"
    
    error_status, rapdu = send_APDU(capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("get_key_information_template", error_status['errorStatus'])
        return error_status, None
    
    if payload_mode_activated == False:
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

    else:
        keyInformation = []
    

    log_end("get_key_information_template", error_status['errorStatus'])

    return error_status, keyInformation


def store_data(data):
    
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
        error_status, rapdu = send_APDU(capdu)
        block_number = block_number + 1

        if error_status['errorStatus'] != 0x00:
            log_end("store_data", error_status['errorStatus'])
            return error_status
    
    
    if error_status['errorStatus'] != 0x00:
        log_end("get_data", error_status['errorStatus'])
        return error_status
    
    log_end("store_data", error_status['errorStatus'])

    return error_status


def get_data(identifier):
    
    log_start("get_data")

    # build the APDU
    # supress blank if any
    import re
    identifier = ''.join( re.split( '\W+', identifier.upper() ) )
    # check the size of the identifier (it is a string so 2 byte correspond to 4 characters )
    if len(identifier) < 0x00 or len(identifier) > 0x04:
        # identifier must be 1 or two byte string
        error_status = create_error_status(ERROR_WRONG_DATA, runtimeErrorDict[ERROR_WRONG_DATA])
        return error_status, None
    
    capdu = "80 CA "
    
    if len(identifier) == 0x04:
         capdu = capdu +  identifier + '00'
    else:
        #one byte identifier
        capdu = capdu +  identifier + '00'  + '00'

    error_status, rapdu = send_APDU(capdu)

    if error_status['errorStatus'] != 0x00:
        log_end("get_data", error_status['errorStatus'])
        return error_status, None
    
    log_end("get_data", error_status['errorStatus'])

    return error_status, rapdu


def get_status(card_element):
    
    log_start("get_status")

    # build the APDU
    # supress blank if any
    import re
    card_element = ''.join( re.split( '\W+', card_element.upper() ) )
   
    capdu = "80 F2 " + card_element + "02 02 4F 00" + "00"
    
    error_status, rapdu = send_APDU(capdu)
    
    if error_status['errorStatus'] != 0x00:
        log_end("get_status", error_status['errorStatus'])
        return error_status, None
    
    if payload_mode_activated == False:
        # store the response
        card_response = last_response()
        # check if more data available
        while last_status() == '6310':
            # send a get status next occurence
            capdu = "80 F2 " + card_element + "03 02 4F 00" + "00"
            error_status, rapdu = send_APDU(capdu)
        
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
                    elif app_info.getTAG() == '9F70':
                            app_lifecycle = app_info.getValue()
                    elif app_info.getTAG() == 'C5':
                            app_privileges = app_info.getValue()
                    elif app_info.getTAG() == '84':
                            app_modules_aid = app_info.getValue()
                app_info_list.append({'aid':app_aid, 'lifecycle':app_lifecycle[:2], 'privileges':app_privileges, 'module_aid':app_modules_aid})
    else:
        app_info_list = None
        error_status = create_no_error_status(0x00)

    
    log_end("get_status", error_status['errorStatus'])

    return error_status, app_info_list



def get_crs_status(aid, tag_list):
    
    log_start("get_crs_status")

    # build data field tag with given aid and tag list
    if aid == '': data_field = "4F00"
    else: data_field = "4F" + lv(aid)

    if tag_list == '': pass
    else: data_field = data_field + "5C" + lv(tag_list)
    
    capdu = "80 F2 40 00 " + lv(data_field) + "00"
    
    error_status, rapdu = send_APDU(capdu)
    
    if error_status['errorStatus'] != 0x00:
        log_end("get_crs_status", error_status['errorStatus'])
        return error_status, None
    
    # store the response
    card_response = last_response()
    # check if more data available
    while last_status() == '6310':
        # send a get status next occurence
        capdu = "80 F2 40 01 " + lv(data_field) + "00"
        error_status, rapdu = send_APDU(capdu)
    
        if error_status['errorStatus'] != 0x00:
            log_end("get_crs_status", error_status['errorStatus'])
            return error_status, None
        
        card_response = card_response + last_response()
    
    # we have the card_response TLV. create the get status response dictionnary
    response_tlvs = TLVs(toByteArray(card_response))
    app_info_list = []
    app_aid = None
    app_lifecycle = None
    uniform_resource_locator = None
    app_image_template = None
    display_message = None
    app_update_counter = None
    selection_priority = None
    app_group_head = None
    app_group_members = None
    crel_application_aid_list = None
    policy_restricted_app = None
    app_discretionary_data = None
    application_family = None
    display_required_indicator = None
    assinged_protocol = None
    continuous_processing = None
    recognition_algorithm = None


    for response_tlv in response_tlvs.list_childs_tlv():
        if response_tlv.getTAG() == '61':
            # manage the list of TLV into this response_tlv
            app_info_tlv_list = response_tlv.list_childs_tlv()
            for app_info in app_info_tlv_list:
                if app_info.getTAG() == '4F': app_aid = app_info.getValue()
                elif app_info.getTAG() == '9F70': app_lifecycle = app_info.getValue()
                elif app_info.getTAG() == '7F20':
                    display_control_tlv_list = app_info.list_childs_tlv()
                    for display_control_info in display_control_tlv_list:
                        if display_control_info.getTAG() == '5F50': 
                            uniform_resource_locator = display_control_info.getValue()
                        elif display_control_info.getTAG() == '6D': 
                            app_image_template = display_control_info.getValue()
                        elif display_control_info.getTAG() == '5F45': 
                            display_message = display_control_info.getValue()
                elif app_info.getTAG() == '80': app_update_counter = app_info.getValue()
                elif app_info.getTAG() == '81': selection_priority = app_info.getValue()
                elif app_info.getTAG() == 'A2':
                    app_group_head_tlv_list = app_info.list_childs_tlv()
                    for app_group_head in app_group_head_tlv_list:
                        if app_group_head.getTAG() == '4F': 
                            app_group_head = app_group_head.getValue()
                # below 3 parameters tag 'A3' to 'A5' can be multiple so need to find a better way to handle
                elif app_info.getTAG() == 'A3':
                    app_group_members_tlv_list = app_info.list_childs_tlv()
                    for app_group_info in app_group_members_tlv_list:
                        if app_group_info.getTAG() == '4F': 
                            app_group_members = app_group_info.getValue()
                elif app_info.getTAG() == 'A4':
                    crel_app_aid_list_tlv_list = app_info.list_childs_tlv()
                    for crel_app_aid_info in crel_app_aid_list_tlv_list:
                        if crel_app_aid_info.getTAG() == '4F': 
                            crel_app_aid_list = crel_app_aid_info.getValue()
                elif app_info.getTAG() == 'A5':
                    policy_restricted_app_tlv_list = app_info.list_childs_tlv()
                    for policy_restricted_app_info in policy_restricted_app_tlv_list:
                        if policy_restricted_app_info.getTAG() == '4F': 
                            policy_restricted_app = policy_restricted_app_info.getValue()
                elif app_info.getTAG() == 'A6': app_discretionary_data = app_info.getValue()
                elif app_info.getTAG() == '87': app_family = app_info.getValue()
                elif app_info.getTAG() == '88': display_required_indicator = app_info.getValue()
                elif app_info.getTAG() == '8C': assinged_protocol = app_info.getValue()
                elif app_info.getTAG() == '8A': continuous_processing = app_info.getValue()
                elif app_info.getTAG() == '8B': recognition_algorithm = app_info.getValue()
            app_info_list.append({'aid':app_aid, 'lifecycle':app_lifecycle[:2], \
                    'app update counter':app_update_counter, 'selection priority':selection_priority, \
                    'app group head':app_group_head, 'app group members':app_group_members, \
                    'crel app list':crel_app_aid_list, 'policy restricted app':policy_restricted_app, \
                    'app discretionary data':app_discretionary_data, 'app family':app_family, \
                    'display required indicator':display_required_indicator, 'assinged protocol':assinged_protocol, \
                    'continuous processing':continuous_processing, 'recognition algorithm':recognition_algorithm})
    
    else:
        error_status = create_no_error_status(0x00)

    log_end("get_crs_status", error_status['errorStatus'])

    return error_status, app_info_list


def initialize_update(key_set_version , base_key, enc_key , mac_key , dek_key , scp, scp_implementation, sequence_counter = "000000" ):
        
    global last_apdu_response
    global last_apdu_status
    global payload_mode_activated

    log_start("initialize_update")
    # create a host challenge
    hostChallenge = crypto.RANDOM(8)
    
    log_debug("initialize_update: Host challenge Data: %s " % hostChallenge)
    # create the initialize update APDU command (with Le = Max data)
    initUpdateAPDU = '80' + '50' + key_set_version + '00 08' + hostChallenge + '00'
    error_status, rapdu = send_APDU(initUpdateAPDU)
    
    if error_status['errorStatus'] != 0x00:
        log_end("initialize_update", error_status['errorStatus'])
        return error_status, None
    
   
    # Set the security info structure needed for all GP operations
    security_info = securityInfo[securityInfo[4]]


    # checking payload mode
    if payload_mode_activated == True:
        # update the security information structure
        security_info['secureChannelProtocol'] = int(scp, 16)

        if security_info['secureChannelProtocol'] == GP_SCP02:
            # manage init update response
            # in SCP02 the card challenge is calculated using the session key. So we need to create session key before.
            sequenceCounter = toByteArray(sequence_counter)
            # just check the sequence counter length. In SCP02 sequence counter is expressedwith 2 bytes
            if len(sequenceCounter) != 2:
                error_status = create_error_status(ERROR_INCONSISTENT_SEQUENCE_COUNTER, runtimeErrorDict[ERROR_INCONSISTENT_SEQUENCE_COUNTER])
                return error_status, None
    
        elif security_info['secureChannelProtocol'] == GP_SCP03:
            # manage init update response
            sequenceCounter = increment(sequence_counter, 0x01)
            cardChallenge = calculate_card_challenge_SCP03(sequenceCounter + security_info['selectedAID'], enc_key)
            # type coherency
            cardChallenge = toByteArray(cardChallenge)
            sequenceCounter= toByteArray(sequenceCounter)
            log_debug("initialize_update: Card Challenge:  %s " % toHexString(cardChallenge))
            log_debug("initialize_update: Sequence Counter:  %s " % toHexString(sequenceCounter))

        else:
            error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
            return error_status, None
        

        
        security_info['secureChannelProtocolImpl'] = scp_implementation
        security_info['keySetVersion'] = key_set_version
        # we set it to a dummy value
        security_info['keyIndex'] = 0xFF
    

            
        

    else:

        # managing authentication data
        bytearray_initUpdateResponse = toByteArray(last_apdu_response)
        # check init_update_response length, it must be 28, 29 or 32 bytes
        # SCP01/SCP02 = 30 bytes, SCP03 31 or 34 bytes
        if len (bytearray_initUpdateResponse) != 28 and len (bytearray_initUpdateResponse) != 29 and len (bytearray_initUpdateResponse) != 32:
            error_status = create_error_status(ERROR_INVALID_RESPONSE_DATA, runtimeErrorDict[ERROR_INVALID_RESPONSE_DATA])
            return error_status, None
        
        # managing response of INITIALIZE UPDATE
        keyDiversificationData = bytearray_initUpdateResponse[:10]
        keyInformationData = bytearray_initUpdateResponse[10:12]
    
        # check if a scp has been set by the user, if not take the scp into the init update response
        if scp == None:
            scp = intToHexString(keyInformationData[1])
        
        # test if reported SCP is consistent with passed SCP
        if int(str(scp), 16) != keyInformationData[1]:
            error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
            return error_status, None
        
        # update the security information structure
        security_info['secureChannelProtocol'] = int(str(scp), 16)

    
        # in SCP03 the scp implementation value is returned by the init update response
        # in SCP02 this value is not present so this value should be set by the user.
        if security_info['secureChannelProtocol'] == GP_SCP02:
            if scp_implementation == None:
                scp_implementation = intToHexString(0x55)
                # error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
                # return error_status, None
        
        if security_info['secureChannelProtocol'] == GP_SCP03:
            # key information data on 3 bytes
            keyInformationData = bytearray_initUpdateResponse[10:13]
            scpi = keyInformationData[2]
            if scp_implementation == None:
                scp_implementation = intToHexString(scpi)
            else:
                #test if reported SCP implementation is consistent with passed SCP implementation
                if scp_implementation != intToHexString(scpi):
                    error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
                    return error_status, None
            
        security_info['secureChannelProtocolImpl'] = scp_implementation
        security_info['keySetVersion'] = keyInformationData[0]
        # we set it to a dummy value
        security_info['keyIndex'] = 0xFF

        if security_info['secureChannelProtocol'] == GP_SCP02:
            # manage init update response
            sequenceCounter = bytearray_initUpdateResponse[12:14] 
            cardChallenge= bytearray_initUpdateResponse[14:20] # 6 bytes
            cardCryptogram = bytearray_initUpdateResponse[20:28] # 8 bytes
        
        if security_info['secureChannelProtocol'] == GP_SCP03:
            # manage init update response
            cardChallenge= bytearray_initUpdateResponse[13:21] # 8 bytes
            cardCryptogram = bytearray_initUpdateResponse[21:29] # 8 bytes
            sequenceCounter = bytearray_initUpdateResponse[29:32] # 3 bytes
        

        log_debug("initialize_update: Key Diversification Data: %s " % toHexString(keyDiversificationData))

        log_debug("initialize_update: Key Information Data: %s " % toHexString(keyInformationData))

        log_debug("initialize_update: Card Challenge:  %s " % toHexString(cardChallenge))

        log_debug("initialize_update: Sequence Counter:  %s " % toHexString(sequenceCounter))

        log_debug("initialize_update: Card Cryptogram  %s " % toHexString(cardCryptogram))

    # create session key regarding the scp implementation 
    
    if security_info['secureChannelProtocol'] == GP_SCP02:
        ## Secure Channel base key
        if  (security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i04 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i14 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i44 or
            security_info['secureChannelProtocolImpl'] == SCP02_IMPL_i54):

            # calculation of encryption session key using on base key
            security_info['encryptionSessionKey'] = create_session_key_SCP02(base_key, KENC_TYPE, toHexString(sequenceCounter))
            # calculation of C-MAC session key
            security_info['C_MACSessionKey'] = create_session_key_SCP02(baseKey, KMAC_TYPE, toHexString(sequenceCounter))
            #calculation of R-MAC session key
            security_info['R_MACSessionKey'] = create_session_key_SCP02(baseKey, KRMAC_TYPE, toHexString(sequenceCounter))
            #calculation of data encryption session key
            security_info['dataEncryptionSessionKey'] = create_session_key_SCP02(baseKey, KDEK_TYPE, toHexString(sequenceCounter))
            
        ## 3 Secure Channel Keys */
        elif (security_info['secureChannelProtocolImpl']  == SCP02_IMPL_i05 or
            security_info['secureChannelProtocolImpl']   == SCP02_IMPL_i15 or
            security_info['secureChannelProtocolImpl']   == SCP02_IMPL_i55 or
            security_info['secureChannelProtocolImpl']   == SCP02_IMPL_i45):
                
            # calculation of encryption session key using on 3 static key
            security_info['encryptionSessionKey'] = create_session_key_SCP02(enc_key, KENC_TYPE, toHexString(sequenceCounter))
            # calculation of C-MAC session key
            security_info['C_MACSessionKey'] = create_session_key_SCP02(mac_key, KMAC_TYPE, toHexString(sequenceCounter))
            #calculation of R-MAC session key
            security_info['R_MACSessionKey'] = create_session_key_SCP02(dek_key, KRMAC_TYPE, toHexString(sequenceCounter))
            #calculation of data encryption session key
            security_info['dataEncryptionSessionKey'] = create_session_key_SCP02(dek_key, KDEK_TYPE, toHexString(sequenceCounter))

            if payload_mode_activated == True:
                cardChallenge  = self.calculate_card_challenge_SCP02(security_info['selectedAID'], security_info['C_MACSessionKey'])
                # type coherency
                cardChallenge = int(cardChallenge, 16)
            
        else:
            error_status = create_error_status(ERROR_INVALID_SCP_IMPL, runtimeErrorDict[ERROR_INVALID_SCP_IMPL])
            return error_status, None

    elif security_info['secureChannelProtocol'] == GP_SCP03:

        # calculation of encryption session key using on 3 static key
        session_key_value  = create_session_key_SCP03(enc_key, KENC_TYPE, toHexString(cardChallenge), hostChallenge)
        if session_key_value == None:
            error_status = create_error_status(ERROR_SESSION_KEY_CREATION, runtimeErrorDict[ERROR_SESSION_KEY_CREATION])
            return error_status, None
        else:
           security_info['encryptionSessionKey'] = session_key_value
        
        # calculation of C-MAC session key
        session_key_value  = create_session_key_SCP03(mac_key, KMAC_TYPE , toHexString(cardChallenge), hostChallenge)
        if session_key_value == None:
            error_status = create_error_status(ERROR_SESSION_KEY_CREATION, runtimeErrorDict[ERROR_SESSION_KEY_CREATION])
            return error_status, None
        else:
            security_info['C_MACSessionKey'] = session_key_value
        #calculation of R-MAC session key
        session_key_value  = create_session_key_SCP03(mac_key, KRMAC_TYPE, toHexString(cardChallenge), hostChallenge)
        if session_key_value == None:
            error_status = create_error_status(ERROR_SESSION_KEY_CREATION, runtimeErrorDict[ERROR_SESSION_KEY_CREATION])
            return error_status, None
        else:
            security_info['R_MACSessionKey'] = session_key_value
        # calculation of data encryption session key
        # warning: no session key for data encryption in SCP03
        # session_key_value  = create_session_key_SCP03(dek_key, KDEK_TYPE , toHexString(cardChallenge), hostChallenge)
        # if session_key_value == None:
        #     error_status = create_error_status(ERROR_SESSION_KEY_CREATION, runtimeErrorDict[ERROR_SESSION_KEY_CREATION])
        #     return error_status, None
        # else:
        security_info['dataEncryptionSessionKey'] = dek_key
    
    else:
        error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
        return error_status, None

    log_debug("initialize_update: S-ENC Session Key: %s" %security_info['encryptionSessionKey'])
    log_debug("initialize_update: S-MAC Session Key: %s" %security_info['C_MACSessionKey'])
    log_debug("initialize_update:   DEK Session Key: %s" %security_info['dataEncryptionSessionKey'])
    log_debug("initialize_update: R-MAC Session Key: %s" %security_info['R_MACSessionKey'])

    if security_info['secureChannelProtocol'] == GP_SCP02:
        offcardCryptogram = calculate_card_cryptogram_SCP02(toHexString(sequenceCounter), toHexString(cardChallenge), hostChallenge, security_info['encryptionSessionKey'])
    elif security_info['secureChannelProtocol'] == GP_SCP03:
        offcardCryptogram = calculate_card_cryptogram_SCP03(toHexString(cardChallenge), hostChallenge, security_info['C_MACSessionKey'])
    else:
        error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
        return error_status, None

    
    if payload_mode_activated == False:
        # compare cryptograms
        if toHexString(cardCryptogram) != offcardCryptogram:
            error_status = create_error_status(ERROR_CARD_CRYPTOGRAM_VERIFICATION, runtimeErrorDict[ERROR_CARD_CRYPTOGRAM_VERIFICATION])
            return error_status , None


    host_cryptogram = None
    if security_info['secureChannelProtocol'] == GP_SCP02:
        host_cryptogram = calculate_host_cryptogram_SCP02(toHexString(sequenceCounter), toHexString(cardChallenge), hostChallenge, security_info['encryptionSessionKey'])

    elif  security_info['secureChannelProtocol'] == GP_SCP03:
        host_cryptogram = calculate_host_cryptogram_SCP03(toHexString(cardChallenge), hostChallenge, security_info['C_MACSessionKey'])

    else:
        error_status = create_error_status(ERROR_INCONSISTENT_SCP, runtimeErrorDict[ERROR_INCONSISTENT_SCP])
        return error_status, None
    

    error_status = create_no_error_status(0x00)
    log_end("initialize_update", error_status['errorStatus'])
    return error_status, host_cryptogram

def internal_authenticate(key_version_number, key_identifier , crt_data , ePK_OCE ):
    
    log_start("internal_authenticate")
    

    
    # build the APDU
    data = "5F49" + lv(ePK_OCE)
    data_field = crt_data + data

    internal_authenticate_apdu = '80 88'  + key_version_number + key_identifier + lv(data_field)
    
    error_status, rapdu = send_APDU(internal_authenticate_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("internal_authenticate", error_status['errorStatus'])
        return error_status, None

        
    log_end("internal_authenticate", error_status['errorStatus'])
    return error_status, rapdu
    

def mutual_authenticate(key_version_number, key_identifier , crt_data , ePK_OCE ):
    
    log_start("mutual_authenticate")

    
    # build the APDU
    data = "5F49" + lv(ePK_OCE)
    data_field = crt_data + data

    mutual_authenticate_apdu = '80 82'  + key_version_number + key_identifier + lv(data_field)
    
    error_status, rapdu = send_APDU(mutual_authenticate_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("mutual_authenticate", error_status['errorStatus'])
        return error_status, None

        
    log_end("mutual_authenticate", error_status['errorStatus'])
    return error_status, rapdu

def external_authenticate(security_level, host_cryptogram):

    log_start("external_authenticate")

    # get security_info dictionary of working channel
    security_info = securityInfo[securityInfo[4]]
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

    error_status, rapdu = send_APDU(externalAuthAPDU)

    if error_status['errorStatus'] != 0x00:
        log_end("external_authenticate", error_status['errorStatus'])
        return error_status


    #update security info
    security_info['securityLevel'] = security_level
        
    log_end("external_authenticate", error_status['errorStatus'])
    return error_status

def get_certificate(key_version_number, key_identifier):
    log_start("get_certificate")
    
    error_status = __check_security_info__(securityInfo[securityInfo[4]])
    if error_status['errorStatus'] != 0x00:
        log_end("get_certificate", error_status['errorStatus'])
        return error_status
    
    # build the APDU


    get_certificate_apdu = '80 CA BF 21' + lv ('A6' + lv ( '83' + lv (key_version_number + key_identifier)))
    
    error_status, rapdu = send_APDU(get_certificate_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("get_certificate", error_status['errorStatus'])
        return error_status, None

        
    log_end("get_certificate", error_status['errorStatus'])
    return error_status, rapdu



def perform_security_operation(key_version_number, key_identifier , crt_data ):
    
    log_start("perform_security_operation")
    
    error_status = __check_security_info__(securityInfo[securityInfo[4]])
    if error_status['errorStatus'] != 0x00:
        log_end("perform_security_operation", error_status['errorStatus'])
        return error_status
    
    # build the APDU


    perform_security_operation_apdu = '80 2A' + key_version_number + key_identifier + lv(crt_data)
    
    error_status, rapdu = send_APDU(perform_security_operation_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("perform_security_operation", error_status['errorStatus'])
        return error_status

        
    log_end("perform_security_operation", error_status['errorStatus'])
    return error_status

def registry_update(security_domain_AID, application_aid, application_privileges = "00",  registry_parameter_field = None, install_token = None):
    log_start("registry_update")
    
    error_status = __check_security_info__(securityInfo[securityInfo[4]])
    if error_status['errorStatus'] != 0x00:
        log_end("registry_update", error_status['errorStatus'])
        return error_status
    
    # build the APDU
    # mandatory fields
    registry_update_apdu_data = lv(remove_space(security_domain_AID)) +  '00' + lv(remove_space(application_aid)) + lv(application_privileges)
    # optionnal fields
    parameter_field = ''
    if registry_parameter_field != None:
        parameter_field = parameter_field + 'EF' + lv(remove_space(registry_parameter_field))
    else:
        parameter_field =parameter_field + 'EF00'
    
    if install_token != None:
        install_token = lv(install_token)
    else:
        install_token =  '00' #no token

    registry_update_apdu = '80 E6 40 00'  + lv(registry_update_apdu_data + lv(parameter_field) + install_token)
    
    error_status, rapdu = send_APDU(registry_update_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("registry_update", error_status['errorStatus'])
        return error_status

        
    log_end("registry_update", error_status['errorStatus'])
    return error_status


def install_install(make_selectable, executable_LoadFile_AID, executable_Module_AID, application_AID, application_privileges = "00", application_specific_parameters = None, install_parameters = None, install_token = None):
    log_start("install_install")
    
    error_status = __check_security_info__(securityInfo[securityInfo[4]])
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
    
    error_status, rapdu = send_APDU(install_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("install_install", error_status['errorStatus'])
        return error_status

        
    log_end("install_install", error_status['errorStatus'])
    return error_status
        

def install_load(executable_load_file_aid, security_domain_aid, load_file_data_block_hash = None, load_parameters = None, load_token = None):
    log_start("install_load")
    
    error_status = __check_security_info__(securityInfo[securityInfo[4]])
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
    
    error_status, rapdu = send_APDU(install_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("install_load", error_status['errorStatus'])
        return error_status

        
    log_end("install_load", error_status['errorStatus'])
    return error_status


def load_blocks(load_file_path, block_size = 32):
    log_start("load_blocks")
    
    error_status = __check_security_info__(securityInfo[securityInfo[4]])
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

        error_status, rapdu = send_APDU(load_apdu)

        if error_status['errorStatus'] != 0x00:
            log_end("extradite", error_status['errorStatus'])
            return error_status
        
        block_number = block_number + 1
    
    log_end("load_blocks", error_status['errorStatus'])
    return error_status


def extradite(security_domain_AID, application_aid, identification_number = None,  image_Number = None, application_provider_identifier = None, token_identifier = None, extraditeToken = None):
    log_start("extradite")
    
    error_status = __check_security_info__(securityInfo[securityInfo[4]])
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
    
    error_status, rapdu = send_APDU(extradite_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("extradite", error_status['errorStatus'])
        return error_status

        
    log_end("extradite", error_status['errorStatus'])
    return error_status


def put_key(key_version_number, key_identifier, key_type, key_value, replace = False ):
    
    log_start("put_key")
    
    security_info = securityInfo[securityInfo[4]]

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
    
  
    error_status, rapdu = send_APDU(put_key_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("put_key", error_status['errorStatus'])
        return error_status

        
    log_end("put_key", error_status['errorStatus'])
    return error_status
    

def put_scp_key(key_version_number, key_list, replace = False ):

    log_start("put_scp_key")

    security_info = securityInfo[securityInfo[4]]
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
    error_status, rapdu = send_APDU(put_scp_key_apdu)

    if error_status['errorStatus'] != 0x00:
        log_end("put_scp_key", error_status['errorStatus'])
        return error_status
        
    log_end("put_scp_key", error_status['errorStatus'])
    return error_status   

def manage_channel(open_channel, logical_channel):
    global securityInfo

    log_start("manage_channel")

    if open_channel == True:
        capdu = '00 70 00 00 01'
    else:
        if logical_channel < 0x01 and logical_channel > 0x03:
            # channel number must be between 01 and 03
            error_status = create_error_status(ERROR_WRONG_DATA, runtimeErrorDict[ERROR_WRONG_DATA])
            return error_status
        capdu = '00 70 80 ' + intToHexString(logical_channel) + '00'

    error_status, rapdu = send_APDU(capdu, raw_mode = True)

    if error_status['errorStatus'] != 0x00:
        log_end("manage_channel", error_status['errorStatus'])
        return error_status, None

    if open_channel == True:
        byte_list_data = toByteArray(rapdu)
        channel_num = byte_list_data[0]
        sChannelInfo = securityInfo[channel_num]
        sChannelInfo['channelStatus'] = "ON"
    else:
        # Close working channel then set another chanenl as working channel
        if securityInfo[4] == logical_channel:
            securityInfo[4] = 0
        securityInfo[logical_channel] = {}

    log_end("manage_channel", error_status['errorStatus'])

    return error_status, rapdu