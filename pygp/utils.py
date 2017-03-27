import collections

def remove_space(bytestring):
    """
        Removes all whitespace characters of a string.

        :param str bytestring: The string to manage

        :returns: str bytestr: the string without whitepace characters

    """
    import re
    bytestring = ''.join( re.split( '\W+', bytestring.upper() ) )
    return bytestring

def toByteArray(byteString):
    """
        Returns a list of bytes from a byte string
        
        :param str bytestring: a hexadecimal string

        :returns: list list_byte: the list of bytes

        ::

            # get the list of bytes from the hexadecimal string
            astr = "3B65000  09C11 0101 03"
            toByteArray( astr ) # returns  [ 0x3B, 0x65, 0x00, 0x00, 0x9C, 0x11, 0x01, 0x01, 0x03 ]

        
    """
    import re
    packedstring = ''.join( re.split( '\W+', byteString.upper() ) )
    aArray = bytearray.fromhex(packedstring.upper())
    value = list(aArray)
    return value

def toHexString(bytes=[]):
    """
        Returns a hexadecimal string from a list of bytes
        
        :param list bytes: a list of bytes

        :returns: str bytestr: the hexadecimal string 

        ::

            # get the string from the list of bytes
            a_list = [ 0x3B, 0x65, 0x00, 0x00, 0x9C, 0x11, 0x01, 0x01, 0x03 ]
            toHexString( a_list ) # returns  "3B6500009C11010103"
        
    """
    value = ""
    for i in range (0, len(bytes)):
        if (bytes[i] < 0x00):
            return None
        value += ("%-0.2X" % bytes[i])
    return value


def getBytes(data, byteNumber,length = 1):
    """
        Returns the part of data string from byte number to length bytes
        
        :param str data: a hexadecimal string
        :param int byteNumber: the start offset into the string
        :param int length: The bytes length to get

        :returns: str bytestr: the hexadecimal string 

        ::

            # get the string from byte 2 with a length of 3
            astr = "3B65000  09C11 0101 03"
            getBytes(astr, 2, 3) # returns  "650000"
        
    """

    import re
    bytestr = ''.join( re.split( '\W+', data.upper() ) )
    byteArray = toByteArray(bytestr)
    part = byteArray[byteNumber - 1:byteNumber - 1 + length]
    return toHexString(part)

def lv(bytestring):
    '''
        Returns a byte String representing the length content preceding by its length.

        :param str bytestring: a hexadecimal string

        :returns: str bytestr: the hexadecimal string preceded by its length 
        
        .. note:: for byte string up to FF bytes, the length is coded with 2 bytes.

        ::

            # get the string preceded by its length
            astr = "3B65000  09C11 0101 03"
            lv(astr) # returns  "093B65000 09C11010103"
        

    '''
    import re
    bytestr = ''.join( re.split( '\W+', bytestring.upper() ) )

    length = int(len(bytestr)/2)
    if (length > 0xFF):
        #length on 2 bytes
        return intToHexString(length,2) + bytestr
    else:
        return intToHexString(length,1) + bytestr


def intToHexString(intValue, len = 1):
    """
        Returns a hexadecimal string representing an integer
        
        :param int intValue: an integer value
        :param int len: the number of byte expected for the string

        :returns: str bytestr: the hexadecimal string 


        ::

            # get the string representation of the integer
            aInt = 10
            intToHexString ( aInt, 2 ) #returns  "000A"
            

    """
    stringValue = hex(intValue).lstrip('0x')
    stringValue = stringValue.rjust(len*2,'0')
    return stringValue.upper()


def getLength(bytestr, len = 1):
    '''
        Returns a string representing the length of the string as parameter on numberOfBytes bytes

        :param str bytestr: a hexadecimal string
        :param int len: the number of byte expected for the string
        
        ::

            getLength("A0A40002", 2) # returns "0004"
            getLength("A0A40002", 1) # returns "02"

            
    '''
    import re
    bytestr = ''.join( re.split( '\W+', bytestr.upper() ) )
    length = int(len(bytestr)/2)
    return intToHexString(length,len)



def increment(bytestr,value):
    '''
        This function increments an hexadecimal string with the integer value.
        The value could be an integer or a string.
    
        :param str bytestr: a hexadecimal string
        :param int value: the value to increment


        ::

            aStr = '01'
            aInt = 0x03
            newStr = increment ( aStr, aInt ) # returns  "04"
            aInt = '03'
            newStr = increment ( aStr, aInt ) # returns  "04"


    '''
    import re
    data = ''.join( re.split( '\W+', bytestr.upper() ) )
    # value is an integer
    if type(value) is int:
        # addition
        data_value = int(data, 16)
        data_value = data_value + value
        tmp_string = intToHexString(data_value)
        # return value on the same length
        while len(tmp_string) < len(data) :
            tmp_string = '00' + tmp_string

    # value is a string
    elif type(value) is str:
        #remove space
        value = ''.join( re.split( '\W+', value.upper() ) )
        # addition
        data_value = int(data, 16)
        value = int(value, 16)
        data_value = data_value + value
        tmp_string = intToHexString(data_value)
        # return value on the same length
        while len(tmp_string) < len(data) or len(tmp_string) < len(value) :
            tmp_string = '00' + tmp_string

    else:
        raise BaseException("Wrong parameter type")

    return tmp_string


def tlv_read(byteString):
    
    # remove space if any
    import re
    byteString = ''.join( re.split( '\W+', byteString.upper() ) )
    
    result = []
    
    tlv_tag = None
    tlv_type = None
    tlv_length = None
    tlv_value = None
    # create a byte array from the string
    bytearray_str = toByteArray(byteString)
    
    # 1. check the tag
    offset = 0x00 # used to manage offset into the array
    # check the ber tvl type
    if bytearray_str[offset] & 0x20  == 0x20 :
        tlv_type = 0x01 # BERTLV_CONSTRUCTED
    else:
        tlv_type = 0x00 # BERTLV_PRIMITIVE

    # first byte is a tag or part of a tag
    if  bytearray_str[offset] & 0x1F  == 0x1F :
        # bits b5 to b1 of first byte set to 1 indicate Tag coded over more than 1 byte
        if ( bytearray_str[offset + 1] & 0x80 ) == 0x80 :
            # bit b8 of second byte set to 1 indicates Tag coded over more than 2 bytes
            tlv_tag = toHexString(bytearray_str[:3])
            offset = offset + 3
        else:
            tlv_tag = toHexString(bytearray_str[:2])
            offset = offset + 2
    else:
        tlv_tag = toHexString(bytearray_str[:1])
        offset = offset + 1
    
    # 2. check the length
    if bytearray_str[offset] == 0x81 :
        tlv_length = toHexString(bytearray_str[offset+1:offset + 2])
        offset = offset + 2
    elif bytearray_str[offset] == 0x82:
        tlv_length = toHexString(bytearray_str[offset+1:offset + 3])
        offset = offset + 3
    elif bytearray_str[offset] == 0x83:
        tlv_length = toHexString(bytearray_str[offset+1:offset + 4])
        offset = offset + 4            
    else:
        tlv_length = intToHexString(bytearray_str[offset])
        offset = offset + 1            
    
    # 3. check the value
    length_as_int = int(tlv_length, 16)
    tlv_dict = {}#collections.OrderedDict()
    tlv_dict["T"] = tlv_tag
    tlv_dict["L"] = tlv_length
    
    if tlv_type == 0x00:
       
        #tlv_dict["V"] = toHexString(bytearray_str[offset:offset + length_as_int])
        #result.append(tlv_dict)
        #if offset + length_as_int < len (bytearray_str):
        #    result.append(tlv_read(toHexString(bytearray_str[offset + length_as_int:])))
        result.append(toHexString(bytearray_str[offset:offset + length_as_int]))
        tlv_dict["V"] = result
        
        

    else:
        #tlv_dict["V"] = tlv_read(toHexString(bytearray_str[offset:]))
        #result.append(tlv_dict)
        atlv_dict = tlv_read(toHexString(bytearray_str[offset:]))
        result.append(atlv_dict)
        dict_len = int(atlv_dict["L"], 16) + int(len(atlv_dict["T"])/2) + 1 # len(tag) + len(L) + len
        if offset + dict_len < len (bytearray_str):
            result.append(tlv_read(toHexString(bytearray_str[offset + dict_len:])))

        tlv_dict["V"] = result
    return tlv_dict



    
 