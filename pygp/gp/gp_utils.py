import pygp.constants as constants
import pygp.utils as utils



def privilegesToBytes(privileges):
    """
        Function to retrieve the privileges bytes from a list of priviliges
        :param list privileges: A list of privilege described as a string

        :return: The bytes string corresponding to the privileges. 
                 The returning length can be 2 (for one byte privilege) to 6 (for three bytes privilege)
      
    """
    if privileges == [] or privileges == None:
        return "00"
    privilegeValue = 0
    for privilege in privileges:
        try:
            index = constants.privileges_def.index(privilege)
            privilegeValue = privilegeValue + (1 << index)
        except:
            pass
    if privilegeValue & 0x00FFFF:
        return '{:06X}'.format(privilegeValue) 
    privilegeValue = privilegeValue >> 16
    return '{:02X}'.format(privilegeValue) 


def bytesToPrivileges(bytes_string):
    """
        Function to retrieve the privileges from a list of bytes
        :param str bytes_string: A bytes string representing privileges

        :return: The humand readable string corresponding to the privileges bytes. 
                 
      
    """
    privileges_list = []
    privileges_bytearray = utils.toByteArray(bytes_string)

    if (len(privileges_bytearray) == 0x03):
        privileges_list.extend(getValueFromByte(privileges_bytearray[0],constants.privileges_byte1))
        privileges_list.extend(getValueFromByte(privileges_bytearray[1],constants.privileges_byte2))
        privileges_list.extend(getValueFromByte(privileges_bytearray[2],constants.privileges_byte3))
    elif (len(privileges_bytearray) == 0x02):
        privileges_list.extend(getValueFromByte(privileges_bytearray[0],constants.privileges_byte1))
        privileges_list.extend(getValueFromByte(privileges_bytearray[1],constants.privileges_byte2))
    
    elif(len(privileges_bytearray) == 0x01):
        privileges_list.extend(getValueFromByte(privileges_bytearray[0],constants.privileges_byte1))
    else:
        pass
        
    return ", ".join(privileges_list)


def getValueFromByte(aByte, aDict):
    ''' return the interpretation of a byte regarding the particular dictionary'''
    valueList = []
    for item in aDict.items():
        if ((item[0] & aByte) != 0x00):
            valueList.append(item[1])
    return valueList