import pygp.logger as logger
import pygp.error as error
import pygp.gp.gp_functions as gp
import pygp.gp.gp_utils as gp_utils
import pygp.connection.connection as conn
import pygp.loadfile as loadfile

from pygp.crypto import *
from pygp.constants import *

# API version
__version__  = "1.0.0"

# all logging mode
NONE            = 0x00
CONSOLE_TRACE   = 0x01
FILE_TRACE      = 0x02
DEBUG_LEVEL     = 0x04
INFO_LEVEL      = 0x08
ERROR_LEVEL     = 0x10
APDU            = 0x20
APDU_MNGT       = 0x40
APDU_TIMING     = 0x80

# Global variables 
must_stop_on_error = False
current_protocol = conn.SCARD_PROTOCOL_Tx
context      = None
cardinfo     = None
readername   = None
securityInfo = None
key_list    = []



def __handle_error_status__(error_status, function_name = ''):
    global must_stop_on_error
    
    if error_status['errorStatus'] == error.ERROR_STATUS_FAILURE:
        if must_stop_on_error == False:
            # log the error with the message 
            logger.log_error("** " + function_name + error_status['errorMessage'] + " **")
        else:
            # stop execution by throwing an exception with the message 
            raise BaseException(error_status['errorMessage'])

    if error_status['errorStatus'] == error.ERROR_STATUS_CRITICAL:
        # Always raise exception with the message on critical error
        raise BaseException(error_status['errorMessage'])


def stop_on_error(value):
    """
        Allows to stop the execution if an error occured.

        :param bool value: True if execution should be stopped, False otherwise

    """
    global must_stop_on_error
    must_stop_on_error = value


def sleep(milliseconds):
    """
        Delay execution for a given amount of time in millisecond unit.

        :param int milliseconds: a number of milliseconds to delay execution process

    """
    import time
    time.sleep (milliseconds / 1000.0)


def get_version():
    """
        Returns current PyGP API version 
    """
    return __version__


def last_response():
    """
        Returns the last card response as a haxadecimal string.

        :returns: str response: the last APDU card response.

        .. note:: The response doesn't contain status word. Use :func:`last_status()` to get it.

    """
    return gp.last_response()


def last_status():
    """
    Returns the last card status word as a haxadecimal string.

    :returns: str response: the last APDU status word.

    """
    return gp.last_status()




def set_log_mode(loggingMode, file_path = None):
    """
        Manages the logging capabilities. 
        
        :param int loggingMode: a mask value to configure logging capabilities
            
            The logging mode could be: 
            
            * NONE          (0x00): No log 
            * CONSOLE_TRACE (0x01): Logging output is sent to sys.stdout, sys.stderr console.
            * FILE_TRACE    (0x02): Logging output is sent to a file specified by the file parameter.
            
            The logging level could be: 
            
            * DEBUG_LEVEL   (0x04): All logging messages are displayed
            * INFO_LEVEL    (0x08): Information and error logging messages are displayed
            * ERROR_LEVEL   (0x10): Error logging messages are displayed

            The logging option could be: 
            
            * APDU          (0x20): APDU exchanges are displayed
            * APDU_MNGT     (0x40): APDU exchanges due to the protocol (formelly T=0 protocol) are displayed
            * APDU_TIMING   (0x80): APDU exchanges timing are displayed
                    
        :param str file_path: the path of the logging file if the logging mode is set to FILE_TRACE

        ::

            # set the logging mode to a file with debug logging level
            set_log_mode(FILE_TRACE|DEBUG_LEVEL, "C:/log/myLoggingFile.txt")
            
            # set the logging mode to the console only with  information logging level and APDU exchanges
            set_log_mode(CONSOLE_TRACE|INFO_LEVEL|APDU)

    """
    global apdu_timer
    # first we remove all logging handler
    logger.remove_log_handlers()

    if (loggingMode & CONSOLE_TRACE) == CONSOLE_TRACE:
        # add a streamhandler to the system console
        logger.addStreamHandler()
    
    if (loggingMode & FILE_TRACE) == FILE_TRACE:
        # add a fileHandler to the system console
        logger.addFileHandler(file_path)
    
    if (loggingMode & DEBUG_LEVEL) == DEBUG_LEVEL:
        # set the logging level to debug
        logger.setDebugLevel()
    if (loggingMode & ERROR_LEVEL) == ERROR_LEVEL:
        # set the logging level to error
        logger.setErrorLevel()
    if (loggingMode & INFO_LEVEL) == INFO_LEVEL:
        # set the logging level to info
        logger.setInfoLevel()
    
    if (loggingMode & APDU) == APDU:
        # Display APDU exchanges
        logger.set_apdu_logging(True)   
    
    if (loggingMode & APDU_MNGT) == APDU_MNGT:
        # Display APDU exchanges
        logger.set_apdu_management_logging(True) 
    
    if (loggingMode & APDU_TIMING) == APDU_TIMING:
        # Display APDU timings
        gp.apdu_timing(True)
    else:     
        gp.apdu_timing(False)


def set_payload_mode(activate):
    """
        Allows to store all apdu to send into a list in place of sending them to the card.
        The list containing apdus could be retreive by using the :func get_payload_list

        :param bool activate: Activate the payload mode

    """
    gp.set_payload_mode(activate)


def get_payload_list():
    """
        Returns the list of payload apdu.

        :returns: list payload_list: the list of apdu


    """
    return gp.get_payload_list()


def echo(message, log_level=INFO_LEVEL):
    """
        Log the message argument depending on the logging level

         :param str message: the message to log.
         :param int log_level: the logging level of this message

            The logging level could be: 
            
            * DEBUG_LEVEL   (0x04): All logging messages are displayed
            * INFO_LEVEL    (0x08): Information and error logging messages are displayed
            * ERROR_LEVEL   (0x10): Error logging messages are displayed
        
        ::

            # echo the message only if the DEBUG_LEVEL is set
            echo("my message", DEBUG_LEVEL)

    """
    if log_level == ERROR_LEVEL:
        logger.log_error(message)
    elif log_level == INFO_LEVEL:
        logger.log_info(message)
    elif log_level == DEBUG_LEVEL:
        logger.log_debug(message)
    else:
        pass


def set_key(*args):
    """
    Put key definition into the off card key repository.

    :param str args: key defined using a specific format: "KEY_VERSION_NUMBER/KET_ID/KEY_TYPE/KEY_VALUE"
    
    .. note:: KEY_TYPE value could be: **DES-ECB**, **DES-CBC**, **AES**, **RSA-PRIV**, **RSA-PUB**

    .. note:: If a key defined by its key version number is already present into the off card key repository, the new value will replace the old one.

    """
    global key_list 

    import re
    r = re.compile('[0-9a-fA-F]*/[0-9a-fA-F]*/.*/[0-9a-fA-F]*')
    
    for arg in args:
        # remove space if any                    
        arg = arg.replace(' ', '')
        # verify arg format
        if r.match(arg) is None:
            logger.log_error(" %s argument has an invalid format. This key value is skipped" %arg)
            
            continue
        else:
            # ckeck if the version number is not already present...in this case we must replace the keys 
            key_def = arg.split("/")
            found_key_list = get_key_in_repository(key_def[0],key_def[1] )
            if len(found_key_list) == 0:
                # just add the key
                key_list.append(tuple (arg.split("/")))
            else:
                #remove the previous key
                key_list.remove(found_key_list[0])
                key_list.append(tuple (arg.split("/")))
            

def get_key_in_repository(key_version_number, key_identifier = None):
    """
        Returns the list of Tuple (key value/Key type) stored into the off card key repository regarding their key version number and eventually their key identifier.

        :param str keysetversion: the key set version.
        :param str key_identifier: the key identifier.

        :returns list key_list: A list of Tuple (key_version_number, key_id, key_type, key_value) matching the key version number

    """
    import re
    global key_list

    found_key_list = []    

    for key in key_list:

        if (key[0] == key_version_number):
            if key_identifier != None:
                if (key[1] == key_identifier):
                    found_key_vn = ''.join( re.split( '\W+', key[0].upper() ) )
                    found_key_id = ''.join( re.split( '\W+', key[1].upper() ) )
                    found_key_type = ''.join( re.split( '\W+', key[2].upper() ) )
                    found_key_value = ''.join( re.split( '\W+', key[3].upper() ) )
                    found_key_list.append( (found_key_vn, found_key_id, found_key_type, found_key_value) )
            else:
                found_key_vn = ''.join( re.split( '\W+', key[0].upper() ) )
                found_key_id = ''.join( re.split( '\W+', key[1].upper() ) )
                found_key_type = ''.join( re.split( '\W+', key[2].upper() ) )
                found_key_value = ''.join( re.split( '\W+', key[3].upper() ) )
                found_key_list.append( (found_key_vn, found_key_id, found_key_type, found_key_value) )
    
    return found_key_list
    
    # no key was found so raise exception
    raise BaseException ("No matching key found into the off card keys repository")


def terminal(readerName = None):
    """
        Open the terminal using its name. If no terminal name is entered, we use the first 'available' reader found in the registry

        :param str readerName: the name of the terminal to open.

        :returns: a dict mapping error codes with error status ERROR_STATUS_SUCCESS if no error occurs, error code and error message otherwise.
        
        ::

            # error_status dict
            {   error_status['errorStatus']  = ERROR_STATUS_FAILURE
                error_status['errorCode']    = 0x80301000
                error_status['errorMessage'] = "A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU"
            }
        
        :raises ValueError: if illegal parameter combination is supplied.

    """
    try:
        global context
        global readername     
        global cardInfo   
        global current_protocol

        # first establish context
        error_status, context = conn.establish_context()
        
        __handle_error_status__(error_status)
        
        if readerName == None:
        
            # take the first reader entry in the reader list
            error_status, list_readernames = conn.list_readers(context)
        
            __handle_error_status__(error_status)
        
            logger.log_debug('Found readers: ' + str(list_readernames))
        
            if len(list_readernames) > 0:
                for readers in list_readernames:
                    # then perform a card connect to verify the card connection
                    error_status,cardInfo = conn.card_connect(context, str(readers.decode()), current_protocol)
                    if error_status['errorStatus'] == error.ERROR_STATUS_SUCCESS:
                        readerName = readers.decode()

                if readerName == None:
                    raise BaseException("Failed to connect, please check the card.")

                logger.log_debug('Using first available reader in the list: %s' %readerName)
        
            else:
                logger.log_error('No reader found')
        
        readername = readerName
        
        return error_status
    
    except BaseException as e:
        logger.log_error(str(e))
        raise


def close():
    '''
        Close the current selected terminal.
   
        :returns: a dict mapping error codes with error status ERROR_STATUS_SUCCESS if no error occurs, error code and error message otherwise.
    
        ::

            # error_status dict
            {   error_status['errorStatus']  = ERROR_STATUS_FAILURE
                error_status['errorCode']    = 0x80301000
                error_status['errorMessage'] = "A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU"
            }
    '''
    try:
        global context
        
        # first establish context
        error_status = conn.release_context(context)
        
        __handle_error_status__(error_status)
        
        return error_status
    except BaseException as e:
        logger.log_error(str(e))
        raise

    # reset global variables after release context
    context      = None
    cardinfo     = None
    readername   = None
    securityInfo = None


def change_protocol(protocol):
    '''
        Set the protocol to select during the next card reset

        :param str protocol: The protocol to select. 

        The value could be **'T0'** (T=0), **'T1'** (T=1), **'RAW'** (Raw mode) or **'Tx'** (T=1 or T=0))

    '''
    global current_protocol
    if protocol != 'T0' and protocol != 'T1' and protocol != 'RAW' and protocol != 'Tx':
        raise BaseException(" %s argument is invalid." % protocol)
    else:
        if protocol ==  'T0':
            current_protocol = conn.SCARD_PROTOCOL_T0
        elif protocol ==  'T1':
            current_protocol = conn.SCARD_PROTOCOL_T1
        elif protocol ==  'RAW':
            current_protocol = conn.SCARD_PROTOCOL_RAW
        elif protocol ==  'Tx':
            current_protocol = conn.SCARD_PROTOCOL_Tx
        else:
            raise BaseException(" %s argument is invalid." % protocol)


def card():
    """
        Reset inserted card, get ATR and select the Issuer Security Domain

        :returns: str the card ATR

        .. note:: This command should be executed between opening a terminal and sending other card-related commands.

    """
    try:
        global context 
        global cardInfo   
        global readername
        global current_protocol

        # then perform a card connect
        error_status,cardInfo = conn.card_connect(context, str(readername), current_protocol)

        __handle_error_status__(error_status)
        
        # return ATR information
        atr = conn.getATR(context, cardInfo)
        logger.log_info("ATR : %s" %atr)

        # select ISD
        select_isd()

        return atr

    except BaseException as e:
        logger.log_error(str(e))
        raise


def atr():
    """
        Reset inserted card and get ATR.

        :returns: str the card ATR

        .. note:: This command should be executed between opening a terminal and sending other card-related commands.

    """
    try:
        global context 
        global cardInfo   
        global readername

        # then perform a card connect
        error_status,cardInfo = conn.card_connect(context, str(readername), conn.SCARD_PROTOCOL_Tx)

        __handle_error_status__(error_status)
        
        # return ATR information
        atr = conn.getATR(context, cardInfo)
        logger.log_info("ATR : %s" %atr)

        return atr

    except BaseException as e:
        logger.log_error(str(e))
        raise


def select_isd():
    """
        Select the Issuer Security Domain using select by default APDU command.
    """
    try:
        global context    
        global cardInfo    
        global readername    
        global securityInfo    

        error_status = gp.select_issuerSecurityDomain(context, cardInfo)

        __handle_error_status__(error_status, "select_isd: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def set_sd_state(lifeCycleState, aid):
    """
        Modifies the security domain Life Cycle State.
        
        :param str lifeCycleState: The new life cycle state.
        :param str aid: the AID of the target Application or Security Domain for which a Life Cycle change is requested.

    """
    try:
        global context    
        global cardInfo    
        global readername    
        global securityInfo    

        error_status = gp.set_status(context, cardInfo, securityInfo, CARD_ELEMENT_SD_AND_APPLICATIONS, lifeCycleState, aid)

        __handle_error_status__(error_status, "set_sd_state: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise

def set_app_state(lifeCycleState, aid):
    """
        Modifies the Application Life Cycle State.
        
        :param str lifeCycleState: The new life cycle state.
        :param str aid: the AID of the target Application or Security Domain for which a Life Cycle change is requested.

    """
    try:
        global context    
        global cardInfo    
        global readername    
        global securityInfo    

        error_status = gp.set_status(context, cardInfo, securityInfo, CARD_ELEMENT_APPLICATION_AND_SSD, lifeCycleState, aid)

        __handle_error_status__(error_status, "set_app_state: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def set_status(cardElement, lifeCycleState, aid):
    """
        Modifies the card Life Cycle State or the Application Life Cycle State.
        
        :param str cardElement: Identifier for Load Files, Applications or the Card Manager.See constants values in :ref:`set-status-card-element`.
        :param str lifeCycleState: The new life cycle state.
        :param str aid: the AID of the target Application or Security Domain for which a Life Cycle change is requested.

    """
    try:
        global context    
        global cardInfo    
        global readername    
        global securityInfo    

        error_status = gp.set_status(context, cardInfo, securityInfo, cardElement, lifeCycleState, aid)

        __handle_error_status__(error_status, "set_status: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def set_crs_status(status_type, status_value, aid):
    """
        Modifies the card Life Cycle State or the Application Life Cycle State.
        
        :param str status_type: Type of information shall be updated. (i.e. availability, priority order, etc.)
        :param str status_value: Updating value depends on the status type in 'status_type'
        :param str aid: the AID of the target CRS Application.

    """
    try:
        global context    
        global cardInfo    
        global readername    
        global securityInfo    

        error_status, app_info_list = gp.set_status(context, cardInfo, securityInfo, status_type, status_value, aid)

        __handle_error_status__(error_status, "set_crs_status: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def store_data(data):
    """
        Allows to transfer data to an Application or Security Domain processing the command.
        Depending of the data length, Multiple STORE DATA commands are used to send data to the Application or Security Domain
        by breaking the data into smaller components for transmission.

        :param str data: data in a format expected by the Security Domain or the Application.

    """
    try:
        global context    
        global cardInfo    
        global securityInfo  
        
        error_status = gp.store_data(context, cardInfo, securityInfo, data)

        __handle_error_status__(error_status, "store_data: ")  

    except BaseException as e:
        logger.log_error(str(e))
        raise


def get_data(identifier):
    """
        Retrieves a single card data object from the card identified by identifier.
        Some cards do not provide some data objects. Some possible identifiers are predefined.
        There is a convenience method :func:`get_key_information()` to get the key information
        containing key set version, key index, key type and key length of the keys.

        :param str identifier: the Two byte string with high and low order tag value for identifying card data object.

    """
    try:
        global context    
        global cardInfo    
        global securityInfo  
        
        error_status, rapdu = gp.get_data(context, cardInfo, securityInfo, identifier)

        __handle_error_status__(error_status, "get_data: ")  

        return rapdu

    except BaseException as e:
        logger.log_error(str(e))
        raise


def get_key_information():
    '''
        Get key information for the currently selected Application and log it through the logger.
    '''
    try:
        global context    
        global cardInfo    
        global securityInfo    

        error_status, key_information_templates = gp.get_key_information_template(context, cardInfo, securityInfo)

        __handle_error_status__(error_status, "get_key_information: ")  

        if key_information_templates != None:

            # build a description of the keyinformation
            # key_information_templates is list of Tuple : (Key id, Key version number,  KeyLength, KeyType)
            informationStr = ''
            for keyInfo in key_information_templates:
                informationStr = informationStr + 'Key identifier: ' + keyInfo[0]
                
                informationStr = informationStr + ',  Key version number: ' + keyInfo[1]
                informationStr = informationStr + ',  Key length: ' + str(int(keyInfo[2], 16)) + ' bytes'
                if len (keyInfo[3]) == 0x04: # 2 bytes
                    informationStr = informationStr + ',  Key type: ' + key_types_dict[getBytes(keyInfo[3], 1)]
                    informationStr = informationStr + ',  ' + key_types_dict[getBytes(keyInfo[3], 2)]
                else:
                    informationStr = informationStr + ',  KeyType: ' + key_types_dict[keyInfo[3]]
                informationStr = informationStr + '\n'
            
            logger.log_info(informationStr)
        

    except BaseException as e:
        logger.log_error(str(e))
        raise


def get_cplc():
    '''
        Get Card Production life cycle data and log it through the logger.
    '''
    try:
        global context    # Needed to modify global copy of context    
        global cardInfo    # Needed to modify global copy of context
        global readername    # Needed to modify global copy of context
        global key_list    # Needed to modify global copy of context
        global securityInfo    # Needed to modify global copy of context
        # Get data from card
        error_status, cplc_data = gp.get_cplc_data(context, cardInfo, securityInfo)
        
        __handle_error_status__(error_status, "get_cplc: ")
        
        if cplc_data != None:
            index = 0x00

            while index < len(cplc_data):

                logger.log_info('\tic fabricator:                              ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tic type:                                    ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tos id:                                      ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tos date:                                    ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tos level:                                   ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tfabrication date:                           ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tic serial:                                  ' +  cplc_data[index: index + 8])
                index = index + 8
                logger.log_info('\tic batch:                                   ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tmodule fabricator:                          ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tpacking date:                               ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\ticc manufacturer:                           ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tic embedding date:                          ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tpre - personalizer:                         ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tIC PrePersonalization Date:                 ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tIC PrePersonalization Equipment Identifier: ' +  cplc_data[index: index + 8])
                index = index + 4
                logger.log_info('\tIC Personalizer:                            ' +  cplc_data[index: index + 4])
                index = index + 8
                logger.log_info('\tIC Personalization Date:                    ' +  cplc_data[index: index + 4])
                index = index + 4
                logger.log_info('\tIC Personalization Equipment Identifier:    ' +  cplc_data[index: index + 8])
                index = index + 8
        else:
            pass
    except BaseException as e:
        logger.log_error(str(e))    
        raise      


def get_status_isd():
    """
        Get the AID, the life cycle state and the privileges of the Issuer Security Domain and log it through the logger.
    
    """

    try:
        global context       
        global cardInfo   
        global securityInfo

        # 1. perform the command 
        error_status, app_info_list =  gp.get_status(context, cardInfo, securityInfo, '80' )

        __handle_error_status__(error_status, "get_status_isd: ")

        if app_info_list != None:
            for app_info in app_info_list:
                logger.log_info("Card Manager AID : %s (%s) (%s)\n" % (app_info['aid'].upper(), SD_LifeCycleState[app_info['lifecycle']], gp_utils.bytesToPrivileges(app_info['privileges']) ))
            

    except BaseException as e:
        logger.log_error(str(e))
        raise


def get_status_applications():
    """
        Get the AID, the life cycle state and the privileges of all applications and log it through the logger.
    
    """
    try:
        global context       
        global cardInfo   
        global securityInfo

        # 1. perform the command 
        error_status, app_info_list =  gp.get_status(context, cardInfo, securityInfo, '40' )

        __handle_error_status__(error_status, "get_status_applications: ")

        if app_info_list != None:
            for app_info in app_info_list:
                logger.log_info("Application AID : %s (%s) (%s)" % (app_info['aid'].upper(), Application_LifeCycleState[app_info['lifecycle']], gp_utils.bytesToPrivileges(app_info['privileges']) ))
    
    except BaseException as e:
        logger.log_error(str(e))
        raise


def get_status_executable_load_files():
    """
        Get the AID and the life cycle state of all executable load files and log it through the logger.
    
    """
    try:
        global context       
        global cardInfo   
        global securityInfo

        # 1. perform the command 
        error_status, app_info_list =  gp.get_status(context, cardInfo, securityInfo, '20' )

        __handle_error_status__(error_status, "get_status_executable_load_file: ")

        if app_info_list != None:
            for app_info in app_info_list:
                logger.log_info("Load file AID : %s (%s)" % (app_info['aid'].upper(), ExecutableLoadFile_LifeCycleState[app_info['lifecycle']]))

    except BaseException as e:
        logger.log_error(str(e))
        raise


def get_status_executable_load_files_and_modules():
    """
        Get the AID, the life cycle state and the modules AID of all executable load file and modules and then log it through the logger.

    """
    try:
        global context       
        global cardInfo   
        global securityInfo

        # 1. perform the install command 
        error_status, app_info_list =  gp.get_status(context, cardInfo, securityInfo, '10' )

        __handle_error_status__(error_status, "get_status_executable_load_files_and_modules: ")
        if app_info_list != None:
            for app_info in app_info_list:
                logger.log_info("Load file AID : %s (%s)" % (app_info['aid'].upper(), ExecutableLoadFile_LifeCycleState[app_info['lifecycle']]))
                if app_info['module_aid'] != None:
                    logger.log_info("\tModule AID : %s " % (app_info['module_aid'].upper()))

    except BaseException as e:
        logger.log_error(str(e))
        raise


def ls():
    """
        Get the status of all executable load file, modules and applications and then log it through the logger.
    
    """
    try:
        global context       
        global cardInfo   
        global securityInfo

        # 1. perform the command
        error_status, isd_info_list =  gp.get_status(context, cardInfo, securityInfo, '80' )
        __handle_error_status__(error_status, "ls: ")
        error_status, app_info_list =  gp.get_status(context, cardInfo, securityInfo, '40' )
        __handle_error_status__(error_status, "ls: ")
        error_status, exefile_info_list =  gp.get_status(context, cardInfo, securityInfo, '10' )
        __handle_error_status__(error_status, "ls: ")

        if isd_info_list != None:
            for app_info in isd_info_list:
                logger.log_info("Card Manager AID : %s (%s) (%s)" % (app_info['aid'].upper(), SD_LifeCycleState[app_info['lifecycle']], gp_utils.bytesToPrivileges(app_info['privileges']) ))
        if app_info_list != None:
            for app_info in app_info_list:
                logger.log_info("Application AID : %s (%s) (%s)" % (app_info['aid'].upper(), Application_LifeCycleState[app_info['lifecycle']], gp_utils.bytesToPrivileges(app_info['privileges']) ))
        if exefile_info_list != None:        
            for app_info in exefile_info_list:
                logger.log_info("Load file AID : %s (%s)" % (app_info['aid'].upper(), ExecutableLoadFile_LifeCycleState[app_info['lifecycle']]))
                if app_info['module_aid'] != None:
                    logger.log_info("\tModule AID : %s " % (app_info['module_aid'].upper()))
    
    except BaseException as e:
        logger.log_error(str(e))
        raise


def get_crs_status(aid = None, tag_list = None):
    """
        Retrieves the CRS registered Contactless Applications display information, 
        the Lifecycle status and other information according to the given match/search criteria.

        :param str aid: search criterion AID, if empty it will search previously selected CRS Application recursively.
        :param str tag_list: Indicates to the CRS Application how to construct the response data for matching search criteria.

    """
    try:
        global context       
        global cardInfo   
        global securityInfo

        if aid == None: aid = '' 
        if tag_list == None: tag_list = '' 
            

        # 1. perform the command 
        error_status, app_info_list =  gp.get_crs_status(context, cardInfo, securityInfo, aid, tag_list)

        __handle_error_status__(error_status, "get_crs_status: ")
        if app_info_list != None:
            for app_info in app_info_list:
                logger.log_info("Application AID : %s (%s)" % (app_info['aid'].upper(), Application_LifeCycleState[app_info['lifecycle']]))
                if app_info['app update counter'] != '':
                    logger.log_info("\tApplication Update Counter : %s " % (app_info['app update counter'].upper()))
                if app_info['selection priority'] != '':
                    logger.log_info("\tSelection Priority : %s " % (app_info['selection priority'].upper()))
                if app_info['app group head'] != '':
                    logger.log_info("\tApplication Group Head : %s " % (app_info['app group head'].upper()))
                if app_info['app group members'] != '':
                    logger.log_info("\tApplication Group Member : %s " % (app_info['app group members'].upper()))
                if app_info['crel app list'] != '':
                    logger.log_info("\tCREL Application AID : %s " % (app_info['crel app list'].upper()))
                if app_info['policy restricted app'] != '':
                    logger.log_info("\tPolicy Restricted Application : %s " % (app_info['policy restricted app'].upper()))
                if app_info['app discretionary data'] != '':
                    logger.log_info("\tApplication discretionary data : %s " % (app_info['app discretionary data'].upper()))
                if app_info['app family'] != '':
                    logger.log_info("\tApplication Family : %s " % (app_info['app family'].upper()))
                if app_info['display required indicator'] != '':
                    logger.log_info("\tDisplay Required Indicator : %s " % (app_info['display required indicator'].upper()))
                if app_info['assinged protocol'] != '':
                    logger.log_info("\tAssigned Protocol for Implicit Selection : %s " % (app_info['assinged protocol'].upper()))
                if app_info['continuous processing'] != '':
                    logger.log_info("\tContinuous Processing : %s " % (app_info['continuous processing'].upper()))
                if app_info['recognition algorithm'] != '':
                    logger.log_info("\tRecognition Algorithm for Implicit Selection : %s " % (app_info['recognition algorithm'].upper()))

    except BaseException as e:
        logger.log_error(str(e))
        raise


def channel(logical_channel):
    """
        Selects the logical channel to use.

        :param int logical_channel: The Logical Channel number (0..3) to select.

        .. note:: You must track on your own, what channels are opened.

    """
    try:
        global context    
        global cardInfo    

        error_status = gp.select_channel(context, cardInfo, logical_channel)

        __handle_error_status__(error_status, "channel: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def manage_channel(open_channel, logical_channel = None):
    """
        Uses to open or close supplementaty logical channels.

        :param boolean open_channel: wether open/close the channel. True means to open and False to close the channel.
        :param int logical_channel: The Logical channel number (0..3) to open/close.

    """
    try:
        global context
        global cardInfo

        error_status, rapdu = gp.manage_channel(context, cardInfo, open_channel, logical_channel)

        __handle_error_status__(error_status, "manage_channel: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise

def get_certificate(key_version_number, key_identifier):    
    """
        Retrieves a CERT.SD.ECKA from the SD.
        
        :param str key_version_number: the key set version.
        :param str key_identifier: the key identifier.

        :returns str data_response: The response data containing the certificate.

    """
    try:
        global context       
        global cardInfo   
        global securityInfo

        # 1. perform the install command
        error_status, rapdu =  gp.get_certificate(context, cardInfo, securityInfo, key_version_number, key_identifier)

        __handle_error_status__(error_status, "get_certificate: ")  

        return rapdu

    except BaseException as e:
        logger.log_error(str(e))
        raise


def perform_security_operation(key_version_number, key_identifier,certificate):
    """
        The PERFORM SECURITY OPERATION command is used to send the OCE certificate to the SD. 
        This is required as a precondition to the initiation of an SCP11 secure channel.

        :param str key_version_number: the key set version.
        :param str key_identifier: the key identifier.
        :param str certificate: The certificate data.

    """
    try:
        global context       
        global cardInfo   
        global securityInfo

        # 1. perform the install command 
        error_status =  gp.perform_security_operation(context, cardInfo, securityInfo, key_version_number, key_identifier, certificate )

        __handle_error_status__(error_status, "perform_security_operation: ")  

    except BaseException as e:
        logger.log_error(str(e))
        raise


def internal_auth(key_version_number, key_identifier, crt_data , ePK_OCE_ECKA ):
    """
        Performs an internal authenticate command using the specified parameters. 

        :param str key_version_number: the key set version.
        :param str key_identifier: the key identifier.
        :param str crt_data: The data for key establishment.
        :param str ePK_OCE_ECKA: The Ephemeral public key of the OCE used for key agreement
       
        
        :returns str data_response: The response data containing the Ephemeral public key of the SD used for key agreement and the receipt.

    """
    try:
        global context       
        global cardInfo   
        global securityInfo

        # 1. perform the internal authenticate command 
        error_status, rapdu =  gp.internal_authenticate(context, cardInfo, key_version_number,  key_identifier, crt_data , ePK_OCE_ECKA )

        __handle_error_status__(error_status, "internal_auth: ")

        
        return rapdu
       
    except BaseException as e:
        logger.log_error(str(e))
        raise


def mutual_auth(key_version_number, key_identifier, crt_data, ePK_OCE_ECKA):
    """
		Performs an mutual authenticate command using the specified parameters. 

		:param str key_version_number: the key set version.
		:param str key_identifier: the key identifier.
		:param str crt_data: The data for key establishment.
		:param str ePK_OCE_ECKA: The Ephemeral public key of the OCE used for key agreement
		
		
		:returns str data_response: The response data containing the Ephemeral public key of the SD used for key agreement and the receipt.

    """
    try:
        global context       
        global cardInfo   
        global securityInfo

        # 1. perform the internal authenticate command 
        error_status, rapdu =  gp.mutual_authenticate(context, cardInfo, key_version_number,  key_identifier, crt_data , ePK_OCE_ECKA )

        __handle_error_status__(error_status, "mutual_auth: ")

        return rapdu
       
    except BaseException as e:
        logger.log_error(str(e))
        raise

        
def init_update(enc_key = None, mac_key = None, dek_key = None, scp = None, scpi = None, keysetversion = '21', sequence_counter = "000000"):
    """
        Performs an initializee update using specifiied key set and secure channel protocol.

        :param str enc_key: The Session Encryption Key. If None (default) the off card repository key with the specified keyset number is used.
        :param str mac_key: The Secure Channel Message Authentication Code Key. If None (default) the off card repository key with the specified keyset number is used.
        :param str dek_key: The Key Encryption Key. If None (default) the off card repository key with the specified keyset number is used.
        :param str scp: The Session Channel Protocol to used. If None (default) the SCP returned by the card is used.
        :param str scpi: The Secure Channel Protocol Implementation to used. If None (default) the SCP implementation returned by the card is used.
        :param str keysetversion: The Key Set version to used.
        :param str sequence_counter: The current sequence counter. Use only in case of payload mode.
        
        :returns str hostCryptogram: The off card host cryptogram to use into the :func:`ext_auth()` function.

    """
    try:
        global context       
        global cardInfo   
        global readername    
        global securityInfo   
    
        if enc_key == None:
            # get the key from the repository
            found_key_list = get_key_in_repository(keysetversion, "1")
            if len(found_key_list) > 0:
                (enc_key_vn, enc_key_id, enc_key_type, enc_key,) = found_key_list[0]
            else:
                raise BaseException("Could not find key with key version number %s and key id '1' into the off card key repository" %ketsetversion )
        
        if mac_key == None:
            # get the key from the repository
            found_key_list = get_key_in_repository(keysetversion, "2" )
            if len(found_key_list) > 0:
                (mac_key_vn, mac_key_id, mac_key_type, mac_key) = found_key_list[0]
            else:
                raise BaseException("Could not find key with key version number %s and key id '2' into the off card key repository" %ketsetversion )
        
        if dek_key == None:
            # get the key from the repository
            found_key_list = get_key_in_repository(keysetversion, "3")
            if len(found_key_list) > 0:
                (dek_key_vn, dek_key_id, dek_key_type, dek_key) = found_key_list[0]
            else:
                raise BaseException("Could not find key with key version number %s and key id '3' into the off card key repository" %ketsetversion )
        
        # TODO: manage this case ???
        base_key = None # ???

        # first init update:
        error_status, security_Info_template, hostCryptogram =  gp.initialize_update(context, cardInfo, ketsetversion, base_key, enc_key, mac_key, dek_key, scp, scpi, sequence_counter )
        __handle_error_status__(error_status, "init_update: ")
        securityInfo = security_Info_template

        return hostCryptogram

    except BaseException as e:
        logger.log_error(str(e))
        raise


def ext_auth(hostCryptogram, securitylevel = SECURITY_LEVEL_NO_SECURE_MESSAGING):
    """
        Performs an external authenticate using the specifiied cryptogram and security level to use during secure messaging.

        :param str hostCryptogram: The off card host cryptogram retreived during the :func:`init_update()` command.
        :param int securitylevel: The security level of the secure messaging. Could be:
        
            * SECURITY_LEVEL_NO_SECURE_MESSAGING          (0x00): No secure messaging expected.
            * SECURITY_LEVEL_C_MAC                        (0x01): C-MAC.
            * SECURITY_LEVEL_C_DEC_C_MAC                  (0x03): C-DECRYPTION and C-MAC.
            * SECURITY_LEVEL_R_MAC                        (0x10): R-MAC.
            * SECURITY_LEVEL_C_MAC_R_MAC                  (0x11): C-MAC and R-MAC.
            * SECURITY_LEVEL_C_DEC_C_MAC_R_MAC            (0x13): C-DECRYPTION, C-MAC and R-MAC.
            * SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC      (0x33): C-Decryption, C-MAC, R-Mac and R-Encryption.
        
        .. note:: Depending of SCP mode used during  the :func:`init_update()`, some security level will not be available.
    
    """
    try:
        global context       
        global cardInfo   
        global readername    
        global securityInfo   
    
        if securityInfo != None and hostCryptogram != None:
            error_status =  gp.external_authenticate(context, cardInfo, securityInfo, securitylevel, hostCryptogram )
            __handle_error_status__(error_status, "ext_auth: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise



def auth(enc_key = None, mac_key = None, dek_key = None, scp = None, scpi = None, ketsetversion = '21', sequence_counter = "000000", securitylevel = SECURITY_LEVEL_NO_SECURE_MESSAGING):
    """
        Performs a complete authentication with the card using the specifiied key set, secure channel protocol,and security level for secure messaging.

        :param str enc_key: The Session Encryption Key. If None (default) the off card repository key with the specified keyset number is used.
        :param str mac_key: The Secure Channel Message Authentication Code Key. If None (default) the off card repository key with the specified keyset number is used.
        :param str dek_key: The Key Encryption Key. If None (default) the off card repository key with the specified keyset number is used.
        :param str scp: The Session Channel Protocol to used. If None (default) the SCP returned by the card is used.
        :param str scpi: The Secure Channel Protocol Implementation to used. If None (default) the SCP implementation returned by the card is used.
        :param str ketsetversion: The Key Set version to used.
        :param str sequence_counter: The current sequence counter. Use only in case of payload mode.
        :param int securitylevel: The security level of the secure messaging. Could be:
        
            * SECURITY_LEVEL_NO_SECURE_MESSAGING          (0x00): No secure messaging expected.
            * SECURITY_LEVEL_C_MAC                        (0x01): C-MAC.
            * SECURITY_LEVEL_C_DEC_C_MAC                  (0x03): C-DECRYPTION and C-MAC.
            * SECURITY_LEVEL_R_MAC                        (0x10): R-MAC.
            * SECURITY_LEVEL_C_MAC_R_MAC                  (0x11): C-MAC and R-MAC.
            * SECURITY_LEVEL_C_DEC_C_MAC_R_MAC            (0x13): C-DECRYPTION, C-MAC and R-MAC.
            * SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC      (0x33): C-Decryption, C-MAC, R-Mac and R-Encryption.
        
        .. note:: Depending of SCP mode used, some security level will not be available.

    """
    try:
        global context       
        global cardInfo   
        global readername    
        global securityInfo   
    
        if enc_key == None:
            # get the key from the repository
            found_key_list = get_key_in_repository(ketsetversion, "1")
            if len(found_key_list) > 0:
                (enc_key_vn, enc_key_id, enc_key_type, enc_key,) = found_key_list[0]
            else:
                raise BaseException("Could not find key with key version number %s and key id '1' into the off card key repository" %ketsetversion )
        
        if mac_key == None:
            # get the key from the repository
            found_key_list = get_key_in_repository(ketsetversion, "2" )
            if len(found_key_list) > 0:
                (mac_key_vn, mac_key_id, mac_key_type, mac_key) = found_key_list[0]
            else:
                raise BaseException("Could not find key with key version number %s and key id '2' into the off card key repository" %ketsetversion )
        
        if dek_key == None:
            # get the key from the repository
            found_key_list = get_key_in_repository(ketsetversion, "3")
            if len(found_key_list) > 0:
                (dek_key_vn, dek_key_id, dek_key_type, dek_key) = found_key_list[0]
            else:
                raise BaseException("Could not find key with key version number %s and key id '3' into the off card key repository" %ketsetversion )
        
        # TODO: manage this case ???
        base_key = None # ???

        # first init update:
        error_status, security_Info_template, hostCryptogram =  gp.initialize_update(context, cardInfo, ketsetversion, base_key, enc_key, mac_key, dek_key, scp, scpi , sequence_counter)
        __handle_error_status__(error_status, "auth: ")
        securityInfo = security_Info_template

        if security_Info_template != None and hostCryptogram != None:
            error_status =  gp.external_authenticate(context, cardInfo, securityInfo, securitylevel, hostCryptogram )
            __handle_error_status__(error_status, "auth: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def extradite(security_domain_AID, application_aid, identification_number = None,  image_Number = None, application_provider_identifier = None, token_identifier = None, extraditeToken = None):
    '''
        Performs an application extradition into a Security Domain.

        :param str security_domain_AID: The AID of the Security domain.
        :param str application_aid: The AID of the application to extradite.
        :param str identification_number: The Identification Number of the Security Domain with the Token Verification privilege.
        :param str image_Number: The Image Number of the Security Domain with the Token Verification privilege.
        :param str application_provider_identifier: The Application Provider identifier.
        :param str token_identifier: The Token identifier/number (digital signature counter).
        :param str extraditeToken: The extradition token (None by default).
		
    '''
    try:
        global context       
        global cardInfo   
        global readername    
        global key_list    
        global securityInfo

        error_status =  gp.extradite(context, cardInfo, securityInfo, security_domain_AID, application_aid, identification_number,  image_Number, application_provider_identifier, token_identifier, extraditeToken )

        __handle_error_status__(error_status, "extradite: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def install_load(load_file_path, security_domain_aid ):
    '''
        Performs an install for load of a load file into a Security Domain.

        :param str load_file_path: The path of the load file to install.
        :param str security_domain_aid: The AID of the Security domain.

    '''
    try:
        global context    
        global cardInfo    
        global securityInfo    

        # Verify the load File
        load_file_obj = loadfile.Loadfile(load_file_path)

        error_status = gp.install_load(context, cardInfo, securityInfo, load_file_obj.get_aid(), security_domain_aid)

        __handle_error_status__(error_status, "install_load: ")


    except BaseException as e:
        logger.log_error(str(e))
        raise


def install(make_selectable, executable_LoadFile_AID, executable_Module_AID, application_AID, application_privileges = [], application_specific_parameters = None, install_parameters = None, install_token = None):
    '''
        Performs an install for install of an application into a Security Domain.

        :param boolean make_selectable: True if the application must be selectable.
        :param str executable_LoadFile_AID: The AID of the load file package.
        :param str executable_Module_AID: The AID of the load file module.
        :param str application_AID: The AID of the application instance.
        :param str application_privileges: A list of :ref:`privileges` for the Application ([] by default).
        :param str application_specific_parameters: The application parameters (under tag C9)
        :param str install_parameters: The installation parameter (under tag EF).
        :param str install_token: The install token (None by default).

        .. note:: example of application_privileges parameter : ["SD", "TP"] means privilege Security Domain with Trusted Path

    '''
    try:
        global context       
        global cardInfo   
        global readername    
        global securityInfo

        # 1. managing privieges
        b_string_privilege = gp_utils.privilegesToBytes(application_privileges)

        # 2. perform the install command 
        error_status =  gp.install_install(context, cardInfo, securityInfo, make_selectable, executable_LoadFile_AID, executable_Module_AID, application_AID, b_string_privilege, application_specific_parameters, install_parameters, install_token )

        __handle_error_status__(error_status, "install: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def registry_update(security_domain_AID, application_aid, application_privileges = [],  registry_parameter_field = None, install_token = None):
    '''
        Performs an install for registry update of an application into a Security Domain.

        :param str security_domain_AID: The AID of the security domain.
        :param str application_AID: The AID of the application instance.
        :param str application_privileges: A list of :ref:`privileges` for the Application ([] by default).
        :param str registry_parameter_field: The application parameters (under tag EF)
        :param str install_token: The install token (None by default).

        .. note:: example of application_privileges parameter : ["SD", "TP"] means privilege Security Domain with Trusted Path

    '''
    try:
        global context       
        global cardInfo   
        global readername    
        global key_list    
        global securityInfo

        # 1. managing privieges
        b_string_privilege = gp_utils.privilegesToBytes(application_privileges)

        error_status =  gp.registry_update(context, cardInfo, securityInfo, security_domain_AID, application_aid, b_string_privilege,  registry_parameter_field, install_token )

        __handle_error_status__(error_status, "registry_update: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def load_file(load_file_path, block_size = 32 ):
    '''
        Performs a set of load commands using the load file parameter.

        :param str load_file_path: The path of the load file to load.
        :param int block_size: The size of the data blocks.

    '''
    try:
        global context    
        global cardInfo    
        global securityInfo    

        # Verify the load File
        load_file_obj = loadfile.Loadfile(load_file_path)

        error_status = gp.load_blocks(context, cardInfo, securityInfo, load_file_path, block_size)

        __handle_error_status__(error_status, "load_file: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def put_key(key_version_number, key_identifier = None, replace = False):
    '''
        Add or replace a new key identified by its version number and key identifier.

        :param str key_version_number: The key version number.
        :param str key_identifier: The key identifier.
        :param bool replace: True if the key must be replaced, False otherwise.

        .. note:: The key must be presented in the the off card key repository before set it into the card. see :func:`set_key()`  

    '''
    try:
        global context       
        global cardInfo   
        global readername    
        global key_list    
        global securityInfo

        # 1. get the key from the off card key repository
        key_list = get_key_in_repository(key_version_number, key_identifier)
        ( key_vn, key_id, key_type, key_value ) = key_list[0] 
        # 2. perform the put_key command 
        error_status =  gp.put_key(context, cardInfo, securityInfo, key_version_number,key_identifier, key_type, key_value, replace )

        __handle_error_status__(error_status, "put_key: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def put_scp_key(key_version_number, replace = False):
    '''
        Add or replace scp keys identified by its version number.

        :param str key_version_number: The key version number.
        :param bool replace: True if the key must be replaced, False otherwise.

        .. note:: The key must be present in the the off card key repository before set it into the card. see :func:`set_key()`  

    '''
    try:
        global context       
        global cardInfo   
        global readername    
        global securityInfo

        # 1. get the keys from the off card key repository
        found_key_list = get_key_in_repository(key_version_number)
        # 2. perform the put_key command with the key_list 
        error_status =  gp.put_scp_key(context, cardInfo, securityInfo, key_version_number, found_key_list, replace )

        __handle_error_status__(error_status, "put_scp_key: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def select(aid):
    '''
        Performs an application selection by its AID.

        :param str aid: The AID of the application to select

    '''
    try:
        global context    
        global cardInfo    
        global readername    
        global key_list    
        global securityInfo    

        error_status = gp.select_application(context, cardInfo, aid)

        __handle_error_status__(error_status, "select: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def delete(aid):
    '''
        Performs an application deletion by its AID.

        :param str aid: The AID of the application to delete.

    '''
    try:
        global context    
        global cardInfo
        global securityInfo       

        error_status = gp.delete_application(context, cardInfo, securityInfo, aid)

        __handle_error_status__(error_status, "delete: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def delete_package(aid):
    '''
        Performs a package and related application deletion by its AID.

        :param str aid: The AID of the package to delete.

    '''
    try:
        global context    
        global cardInfo
        global securityInfo       

        error_status = gp.delete_package(context, cardInfo, securityInfo, aid)

        __handle_error_status__(error_status, "delete_package: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def delete_key(key_version_number, key_identifier):
    '''
        Performs a key deletion identifies by its version number and its key identifier.

        :param str key_version_number: The key version number.
        :param str key_identifier: The key identifier.

        .. note:: The key is not deleted into the the off card key repository.  

    '''
    try:
        global context    
        global cardInfo
        global securityInfo       

        error_status = gp.delete_key(context, cardInfo, securityInfo, key_version_number, key_identifier)

        __handle_error_status__(error_status)

    except BaseException as e:
        logger.log_error(str(e))
        raise


def send(apdu, raw_mode = False):
    '''
        Sends an APDU Command according to the security level of the selected Security Domain

        :param str apdu: The apdu command.
        :param bool raw_mode: If True apdu is sent without security level management.
    '''
    try:
        global context       
        global cardInfo   
        global readername    
        global key_list    
        global securityInfo    

        error_status, rapdu =  gp.send_APDU(context, cardInfo, securityInfo, apdu, raw_mode)

        __handle_error_status__(error_status, "send: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise


def upload_install(load_file_path, security_domain_aid, executable_module_aid, application_aid ):
    '''
        Performs a full load of an application under the selected Security Domain

        :param str load_file_path: The path of the load file to load.
        :param str executable_LoadFile_AID: The AID of the load file package.
        :param str executable_Module_AID: The AID of the load file module.
        :param str application_AID: The AID of the application instance.

    '''
    try:
        global context    
        global cardInfo    
        global securityInfo    

        # Verify the load File
        load_file_obj = loadfile.Loadfile(load_file_path)

        error_status = gp.install_load(context, cardInfo, securityInfo, load_file_obj.get_aid(), security_domain_aid)

        __handle_error_status__(error_status, "upload_install: ")

        error_status = gp.load_blocks(context, cardInfo, securityInfo, load_file_path, block_size = 192)

        __handle_error_status__(error_status, "upload_install: ")

        error_status = gp.install_install(context, cardInfo, securityInfo, True, load_file_obj.get_aid(), executable_module_aid, application_aid)

    except BaseException as e:
        logger.log_error(str(e))
        raise


def upload(load_file_path, security_domain_aid ):
    '''
        Performs a load of an application under the Security Domain

        :param str load_file_path: The path of the load file to load.
        :param str security_domain_aid: The AID of the Security Domain.

        .. note:: The install for install command is not send by this function.  
    '''
    try:
        global context    
        global cardInfo    
        global securityInfo    

        # Verify the load File
        load_file_obj = loadfile.Loadfile(load_file_path)

        error_status = gp.install_load(context, cardInfo, securityInfo, load_file_obj.get_aid(), security_domain_aid)

        __handle_error_status__(error_status, "upload: ")

        error_status = gp.load_blocks(context, cardInfo, securityInfo, load_file_path, block_size = 32)

        __handle_error_status__(error_status, "upload: ")

    except BaseException as e:
        logger.log_error(str(e))
        raise

