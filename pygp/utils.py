import collections

def remove_space(bytestring):
    # remove space if any
    import re
    bytestring = ''.join( re.split( '\W+', bytestring.upper() ) )
    return bytestring

def toByteArray(byteString):
    import re
    packedstring = ''.join( re.split( '\W+', byteString.upper() ) )
    aArray = bytearray.fromhex(packedstring.upper())
    value = list(aArray)
    return value

def toHexString(bytes=[]):

    value = ""
    for i in range (0, len(bytes)):
        if (bytes[i] < 0x00):
            return None
        value += ("%-0.2X" % bytes[i])
    return value


def getBytes(data, byteNumber,length = 1):
    ''' return the part of data string from byte number to length bytes '''
    import re
    bytestr = ''.join( re.split( '\W+', data.upper() ) )
    byteArray = toByteArray(bytestr)
    part = byteArray[byteNumber - 1:byteNumber - 1 + length]
    return toHexString(part)

def lv(bytestring):
    '''
    Return a byte String representing the length content preceding by its length

    for byte string up to FF bytes, the length is coded with 2 bytes

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
    """Returns an hex string representing an integer """
    stringValue = hex(intValue).lstrip('0x')
    stringValue = stringValue.rjust(len*2,'0')
    return stringValue.upper()


def getLength(bytestr, numberOfBytes = 1):
    '''
        return a string representing the length of the string as parameter on numberOfBytes bytes
        
        ::
            getLengthOfHexaString("A0A40002", 2) -> "0004"
            getLengthOfHexaString("A0A40002", 1) -> "02"
    '''
    import re
    bytestr = ''.join( re.split( '\W+', bytestr.upper() ) )
    length = int(len(bytestr)/2)
    return intToHexString(length,numberOfBytes)

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



    
 