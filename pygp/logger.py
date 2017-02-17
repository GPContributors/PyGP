from pygp import *
import logging





# create the global logger
logger = logging.getLogger()

# global variable for logging
apdu_logging = False
apdu_management_logging = False

def remove_log_handlers():
    global logger
    for handler in logger.handlers:
        if type(handler) == logging.FileHandler:
            handler.close()
        logger.removeHandler(handler)

def addStreamHandler():
    global logger
    logger.addHandler(logging.StreamHandler())

def addFileHandler(file_path):
    global logger
    logger.addHandler(logging.FileHandler(file_path, mode="w"))

def setInfoLevel():
    global logger
    logger.setLevel(logging.INFO)

def setDebugLevel():
    global logger
    logger.setLevel(logging.DEBUG)

def setErrorLevel():
    global logger
    logger.setLevel(logging.ERROR)


def apdu_logging_enable():
    global apdu_logging
    return apdu_logging

def set_apdu_logging(bool_value):
    global apdu_logging
    apdu_logging = bool_value

def apdu_management_logging_enable():
    global apdu_management_logging
    return apdu_management_logging

def set_apdu_management_logging(bool_value):
    global apdu_management_logging
    apdu_management_logging = bool_value


def log_info(message):
    ''' 
     '''
    global logger
    logger.info(message)

def log_debug(message):
    ''' 
     '''
    global logger
    logger.debug(message)

def log_error(message):
    ''' 
     '''
    global logger
    logger.error(message)

def log_start(message, *args):
    ''' 
     '''
    global logger
    logger.debug(message, *args)


def log_end(message, *args):
    ''' 
     '''
    global logger
    complete_message = message + ' '
    for arg in args:
        complete_message = complete_message + ' ' + str(arg)
    logger.debug(complete_message)


def log_apdu(direction, byte_list_apdu):
    ''' 
     '''
    if apdu_logging_enable() :
        global logger
        # format the capdu into 16 bytes long blocks
        j = 0
        if direction == 1:
            message = "==> "
        else:
            message = "<== "
        for i in range(0,len(byte_list_apdu)):
            message += ("%-0.2X " % byte_list_apdu[i])
            j = j + 1
            if j== 16:
                message+="\n    "
                j = 0

        logger.info(message)

def log_management_apdu(direction, byte_list_apdu):
    ''' log with info level
        TODO: put a var in order to display or not these management APDU...
     '''
    if apdu_management_logging_enable():
        global logger
        # format the capdu into 16 bytes long blocks
        j = 0
        if direction == 1:
            message = "\t\t--> "
        else:
            message = "\t\t<-- "
        for i in range(0,len(byte_list_apdu)):
            message += ("%-0.2X " % byte_list_apdu[i])
            j = j + 1
            if j== 16:
                message+="\n\t\t    "
                j = 0

        logger.info(message)

