from pygp.utils import *

ERROR_STATUS_SUCCESS = 0x00
ERROR_STATUS_FAILURE = 0x01
ERROR_STATUS_CRITICAL= 0x02

ISO_SW_Dict = {
"6080":"Swallow or Eject correctly terminated",
"6081":"Following Request Status : no card",
"6082":"Following Request Status : card in correct position after having been inserted the first time",
"6084":"Following Request Status : card in right position",
"6085":"Following Request Status : powered up card remove and then re-inserted in correct position",
"6087":"Following Request Status : card still in right position",
"6282":"End of file reached before finding matching string",
"6283":"Application blocked",
"6300":"EXTERNAL AUTHENTICATE Failed",
"6400":"Execution error (Activatefile)",
"6490":"Data not found or AID not written during personalization",
"6491":"EEPROM integrity error or Incorrect optional code checksum or Bad DES Key or Data checksum error",
"6581":"EEPROM write error",
"6600":"Java unhandled Exception",
"6602":"Java unhandled ArithmeticException",
"6603":"Java unhandled ArrayIndexOutOfBoundsException",
"6604":"Java unhandled ArrayStoreException",
"6605":"Java unhandled ClassCastException",
"6606":"Java unhandled IndexOutOfBoundsException",
"6607":"Java unhandled NegativeArraySizeException",
"6608":"Java unhandled NullPointerException",
"6609":"Java unhandled RuntimeException",
"6610":"Java unhandled PINException",
"6611":"Java unhandled SystemException",
"6612":"Java unhandled TransactionException",
"6613":"Java unhandled CryptoException",
"6640":"Java StackOverflowError",
"6641":"Java OutOfMemoryError",
"6642":"Java IllegalArgumentException",
"6680":"DLRJC VM bad package file version",
"6681":"Java unhandled Throwable",
"6681":"DLRJC VM unsupported byte code",
"6682":"DLRJC VM feature not supported yet",
"6683":"DLRJC VM bad number of parameters",
"6684":"DLRJC VM bad data type",
"6685":"DLRJC VM class definition not found",
"6686":"DLRJC VM method not found",
"6687":"DLRJC VM native API entry not found",
"6688":"DLRJC VM field not found",
"6689":"DLRJCVM no access to field",
"6690":"DLRJCVM stack underflow",
"6691":"DLRJC VM stack not empty on method return",
"6692":"DLRJC VM invalid local variable access",
"6700":"Length error",
"6881":"Function not supported - Logical channel not supported/open",
"6981":"File condition not satisfied",
"6982":"Security Status not satisfied",
"6983":"File invalid",
"6984":"Data invalid",
"6985":"Conditions of use not satisfied (Sequence error)",
"6986":"Command not allowed (nocurrentEF)",
"6989":"Wrong MAC",
"6990":"Command forbidden in current life phase",
"6991":"No random generated before",
"6999":"Select Application failed",
"9000":"No Error",
"9484":"VOP wrong Algorithm in PUT KEY command",
"9485":"VOP bad check value in PUT KEY command",
"60C0":"Comman dunknown",
"60C1":"Illegal parameters in the command",
"60C2":"Illegal format in the command (<5bytes)",
"60C3":"The length byte & the number of data following do not match or are a read cmd consists of more than 5 bytes",
"60F0":"Answer error (INS not correct) or wrong TS byte during power on",
"60F1":"Three parity error in TS byte reception",
"60F2":"Card cannot be processed",
"60F3":"Card protocol not supported (T0 ! 0 in TD1 byte during power on)",
"60F4":"Framing error in reception mode",
"60F5":"XOR of T0 to TCK !: 0",
"60F6":"TA3 !: 20h or 3 parity errors in character received (T:0)",
"60F7":"No answer to a PTS reset",
"60F8":"Three parity errors in reception mode",
"60F9":"No answer from card before BWT timeout",
"60FC":"Three parity errors in transmission mode",
"60FE":"Data I/O line held at 0 volts or Power ON not executed",
"61LL":"Correctexecution,response is LL bytes long",
"6300":"Authentication Failed",
"660A":"Java unhandled SecurityException",
"660B":"Java unhandled CardException",
"660C":"Java unhandled UserException",
"660D":"Java unhandled CardRunTimeException",
"660E":"Java unhandled APDUException",
"660F":"Java unhandled TransactionException",
"668A":"DLRJC VM no access to method",
"66C0":"DLRJC VM bad link",
"66C1":"DLRJC VM not shared",
"66C2":"DLRJC VM Cross transient",
"66FF":"Java unhandled ISOException",
"6A80":"Incorrect parameter in data field",
"6A81":"Function not supported",
"6A82":"File not found",
"6A83":"Record not found",
"6A84":"Not enough memory space in the file",
"6A85":"Lc inconsistent with length recorded in TLV object",
"6A86":"Incorrect parameter (P1,P2)",
"6A87":"P1,P2 inconstant with Lc",
"6A88":"Referenced data not found",
"6A89":"File already exists",
"6A8A":"DF name already exists",
"6B00":"wrong P1,P2",
"6C00":"Correct Expected Length (Le)",
"6CLL":"Wrong length, good length : LL bytes",
"6D00":"INS value not supported",
"6E00":"CLA value not supported",
"6F00":"No precise diagnostic",
"6F01":"fatal error : EEPROM integrity error (IEP)",
"6F02":"fatal error : File system corrupted",
"6F03":"fatal error : Integrity error on data length",
"6F04":"fatal error : EEPROM security system error 1",
"6F05":"fatal error : EEPROM security system error 2",
"6F06":"fatal error : data integrity error",
"6F07":"fatal error : out of memory",
"6F08":"fatal error : invalid reference",
"6F09":"fatal error : transaction nested",
"6F0A":"fatal error : transaction buffer full",
"6F0B":"fatal error : transaction not started",
"6F0C":"fatal error : Not a GET RESPONSE command",
"90FF":"Card not in place or does not respond (mute)"
}

ERROR_UNRECOGNIZED_APDU_COMMAND             = '80301000' #!< A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU
ERROR_INVALID_RESPONSE_DATA                 = '80301001' #!< The response of the command was invalid.
ERROR_INCONSISTENT_SCP                      = '80301002' #!< The Secure Channel Protocol passed and reported do not match.
ERROR_INVALID_SCP_IMPL                      = '80301003' #!< The Secure Channel Protocol Implementation is invalid.
ERROR_CARD_CRYPTOGRAM_VERIFICATION          = '80301004' #!< The verification of the card cryptogram failed.
ERROR_SCP03_SECURITY_LEVEL_3_NOT_SUPPORTED  = '80301005' #!< SCP03 with security level 3 is not supported.
ERROR_WRONG_DATA                            = '80301006' #!< Wrong data.
ERROR_SESSION_KEY_CREATION                  = '80301007' #!< Error during session key creation.
ERROR_NO_CARD_CONTEXT_INITIALIZED           = '80301008' #!< A card context must be established first.
ERROR_NO_CARD_INFO_INITIALIZED              = '80301009' #!< A card connection must be established first.
ERROR_NO_SECURITY_INFO_INITIALIZED          = '8030100A' #!< A mutual authentication must be established first.
ERROR_VALIDATION_R_MAC                      = '8030100B' #!< The validation of the R-MAC has failed.
INVALID_LOGICAL_CHANNEL_NUMBER      = '80001000' #!< Invalid logical channel number.


runtimeErrorDict = {
    ERROR_UNRECOGNIZED_APDU_COMMAND: "A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU",
    ERROR_INVALID_RESPONSE_DATA: "The response of the command was invalid.",
    ERROR_INCONSISTENT_SCP: "The Secure Channel Protocol passed and reported do not match.",
    ERROR_INVALID_SCP_IMPL: "The Secure Channel Protocol Implementation is invalid.",
    ERROR_CARD_CRYPTOGRAM_VERIFICATION: "The verification of the card cryptogram failed.",
    ERROR_SCP03_SECURITY_LEVEL_3_NOT_SUPPORTED: "SCP03 with security level 3 is not supported.",
    ERROR_WRONG_DATA: "Wrong data.",
    ERROR_SESSION_KEY_CREATION: "Error during session key creation.",
    ERROR_NO_CARD_CONTEXT_INITIALIZED: "A card context must be established first.",
    ERROR_NO_CARD_INFO_INITIALIZED: "A card connection must be created first.",
    ERROR_NO_SECURITY_INFO_INITIALIZED: "A mutual authentication must be established first.",
    ERROR_VALIDATION_R_MAC: "The validation of the R-MAC has failed.",

    INVALID_LOGICAL_CHANNEL_NUMBER: "Invalid logical channel number"
}

def create_no_error_status(retCode):
    error_status = {}
    error_status['errorStatus'] = ERROR_STATUS_SUCCESS
    error_status['errorCode'] = retCode
    error_status['errorMessage'] = "Success"
    return error_status
    

def create_error_status(retCode, error_message):
    error_status = {}
    error_status['errorStatus'] = ERROR_STATUS_FAILURE
    error_status['errorCode'] = retCode
    error_status['errorMessage'] = error_message
    return error_status

def create_critical_error_status(retCode, error_message):
    error_status = {}
    error_status['errorStatus'] = ERROR_STATUS_CRITICAL
    error_status['errorCode'] = retCode
    error_status['errorMessage'] = error_message
    return error_status

def check_ISO7816_status_word(response):

    byte_list_data = toByteArray(response)
    statusWord = toHexString(byte_list_data[-2:])
    if (statusWord != '9000' and statusWord != '6310'):
        # create error with the status word
        return create_error_status(statusWord, ISO_SW_Dict[statusWord])
    else:
        return create_no_error_status(statusWord)


