# -*- coding: utf-8 -*-
import pygp.connection.pcsc as pcsc
import pygp.connection.connection

from pygp.utils import *
from pygp.error import *


def handle_retCode(retCode):
    if retCode != pcsc.SCARD_S_SUCCESS:
        error_status = create_critical_error_status(retCode, pcsc.SCardGetErrorMessage(retCode))
    else:
        error_status = create_no_error_status(retCode)
    return error_status


'''
TODO
Memory is allocated in this method for the card context. It must be freed with a call to ..release_context.
return OPGP_status struct with error status OPGP_status_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_status struct
'''
def establish_context(scope = pcsc.SCARD_SCOPE_USER):
    retCode, card_context = pcsc.SCardEstablishContext(scope)
    # create the status structure
    error_status =  handle_retCode(retCode)
    return error_status, card_context


def release_context(card_context):
    retCode = pcsc.SCardReleaseContext(card_context)
    # create the status structure
    error_status = handle_retCode(retCode)
    
    return error_status

def list_readers(card_context):

    retCode, readers = pcsc.SCardListReaders(card_context, [])
    # create the status structure
    error_status = handle_retCode(retCode)
    
    return error_status, readers

def card_connect(card_context, reader_name, protocol):
 
    retCode, hcard, active_protocol = pcsc.SCardConnect( card_context, reader_name, pcsc.SCARD_SHARE_SHARED, protocol)
    # create the status structure
    error_status = handle_retCode(retCode)
    if error_status['errorStatus'] == ERROR_STATUS_CRITICAL:
        return error_status, None

    #TODO: must check the error status here and send the result to the caller
    # create a cardInfo structure in order to store card information
    retCode, reader, state, protocol, atr = pcsc.SCardStatus(hcard)
    # create the status structure
    error_status = handle_retCode(retCode)
    
    card_info = pygp.connection.connection.create_card_info_dict(toHexString(atr), "", protocol, hcard)
    
    return error_status, card_info
    
def card_disconnect(card_info, disposition ):
    '''This function terminates a connection to the connection made through
        SCardConnect.  disposition can have the following values:

        Value of disposition    Meaning
        SCARD_LEAVE_CARD        Do nothing
        SCARD_RESET_CARD        Reset the card (warm reset)
        SCARD_UNPOWER_CARD      Unpower the card (cold reset)
        SCARD_EJECT_CARD        Eject the card

    '''

    retCode = pcsc.SCardDisconnect(card_info['cardHandle'], disposition)
    # create the status structure
    error_status = handle_retCode(retCode)
    
    return error_status

def send_apdu_T1(card_info, bytelist_capdu):
    retCode, bytelist_rapdu = pcsc.SCardTransmit(card_info['cardHandle'], pcsc.SCARD_PCI_T1, bytelist_capdu)
    
    # create the status structure
    error_status = handle_retCode(retCode)
    return error_status, bytelist_rapdu

def send_apdu_T0(card_info, bytelist_capdu):
    retCode, bytelist_rapdu = pcsc.SCardTransmit(card_info['cardHandle'], pcsc.SCARD_PCI_T0, bytelist_capdu)
    
    # create the status structure
    error_status = handle_retCode(retCode)
    return error_status, bytelist_rapdu


