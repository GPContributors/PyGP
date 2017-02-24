import zipfile
import os
import array
import collections
from struct import unpack
from ctypes import c_ubyte
import pygp.utils as utils
import pygp.constants as constants
import pygp.crypto as crypto



class Loadfile(object):
    '''
    This class builds a LoadFile object from a disk-based file.
    and provides basic getters.
    '''
    def __init__(self, filename):
        '''
        Builds a Loadfile Object with the filename as parameter

        :param str filename : An absolute or relative path to a load File

        '''
        self.is_capfile = False
        # dict of all components of a cap file
        self.components = collections.OrderedDict()
        # check if the filename is a relative path
        if os.path.isabs(filename) == False:
            # make it absolute starting from the current working directory
            retval = os.path.join(os.curdir,filename)
            self.loadfile_path = os.path.abspath(retval)
        else:
            # already absolute path, do nothing
            self.loadfile_path = filename
        
        # # analyze the loadfile
        if zipfile.is_zipfile(self.loadfile_path):
             # it is a CAP file
             self.is_capfile = self.read_cap_format()
        else:
            # it is a ijc file
            pass
            self.is_capfile = self.read_ijc_format()
        
        # check if it is a cap file
        if self.is_capfile == False:
            raise BaseException("The file %s is not a valid CAP File" %self.loadfile_path)
    

    def get_load_blocks(self, blockSize, addHeader = True):
        ''' return a list of blockSize long data blocks '''
        allBlocks = []
        # build the complete datablock string
        if addHeader== True:
            completeCode = self.__createHeaderSize__() + self.get_raw_code()
        else:
            completeCode = self.get_raw_code()
        # cut the string into blocksize long blocks
        for index in range(0, len(completeCode), blockSize*2):
            allBlocks.append(completeCode[index:index + blockSize*2] )
        return allBlocks


    def __createHeaderSize__(self):
        ''' Returns the BERTLV string representing the CAP File length'''
        headerSize = 'C4'
        length = int(float(self.get_code_size()))
        if length < 128:
            return headerSize + utils.intToHexString(length)
        elif (length < 256 ):
            return headerSize + '81' + utils.intToHexString(length)
        else:
            return  headerSize + '82' + utils.intToHexString(length, 2)

    def get_raw_code(self):
        ''' Returns the raw code of the load file as string (ie. All components excluding Descriptor and Debug Component)'''
        rawCodeAsString = ''
        #for component_name in self.components:
        #    if component_name != 'Descriptor' or  component_name != 'Debug':
        #        rawCodeAsString = rawCodeAsString + self.components[component_name]

        # Sometimes suncap file does not have correct component order and it will return 6985, 
        # so generate raw string one by one to prevent it.
        if "Header" in self.components.keys():
            rawCodeAsString += self.components["Header"]

        if "Directory" in self.components.keys():
            rawCodeAsString += self.components["Directory"]

        if "Import" in self.components.keys():
            rawCodeAsString += self.components["Import"]

        if "Applet" in self.components.keys():
            rawCodeAsString += self.components["Applet"]

        if "Class" in self.components.keys():
            rawCodeAsString += self.components["Class"]

        if "Method" in self.components.keys():
            rawCodeAsString += self.components["Method"]

        if "Staticfield" in self.components.keys():
            rawCodeAsString += self.components["Staticfield"]

        if "Export" in self.components.keys():
            rawCodeAsString += self.components["Export"]

        if "ConstantPool" in self.components.keys():
            rawCodeAsString += self.components["ConstantPool"]

        if "RefLocation" in self.components.keys():
            rawCodeAsString += self.components["RefLocation"]

        # Add this even optional component
        if "Descriptor" in self.components.keys():
            rawCodeAsString += self.components["Descriptor"]

        return rawCodeAsString
    
    def get_code_size(self):
        ''' returns the code size of the package '''
        size = int(len(self.get_raw_code())/2)
        
        return size
    def get_estimate_size(self):
        ''' returns the estimate size of the package on card '''
        size = 0x00
        if "Applet" in self.components.keys():
            applet_component_str = self.components["Applet"]
            applet_comp_size = utils.getBytes(applet_component_str,2, 2)
            size = size + int(applet_comp_size, 16)
        
        size = size + int(len(self.get_aid())/2)

        # class component
        class_comp_size = utils.getBytes(self.components["Class"],2, 2)
        size = size + int(class_comp_size, 16)
        # method component
        method_comp_size = utils.getBytes(self.components["Method"],2, 2)
        size = size + int(method_comp_size, 16)
        
        if "Export" in self.components.keys():
            export_component_str = self.components["Applet"]
            export_comp_size = utils.getBytes(export_component_str,2, 2)
            size = size + int(export_comp_size, 16)
        
        # static component
        static_comp_size = utils.getBytes(self.components["Staticfield"],2, 2)
        size = size + int(static_comp_size, 16)
        
        return size
    
    def get_name(self):
        ''' returns the load file name '''
        return os.path.basename(self.loadfile_path)


    def get_int_support(self):
        ''' returns True if the load file use integer '''
        # look into the header component
        header_component_str = self.components["Header"]
        flag = utils.getBytes(header_component_str,10)
        return (int(flag, 16) & 0x01) == 0x01

    def get_jc_version(self):
        ''' returns the load file javacard version '''
        # look into the header component
        header_component_str = self.components["Header"]
        # the minor and major version are byte 8 and 9 of the header component
        minor_version = utils.getBytes(header_component_str,8)
        major_version = utils.getBytes(header_component_str,9)
        return  major_version + "." + minor_version

    def get_aid(self):
        ''' returns the load file AID '''
        # look into the header component
        header_component_str = self.components["Header"]
        # the package AIDlength is byte 13 of the header component
        aid_len = utils.getBytes(header_component_str,13)
        aid = utils.getBytes(header_component_str,14, int(aid_len, 16))
        return aid
    
    def isAppletPresent(self):
        ''' Returns True if an application is present into load file '''
        return "Applet" in self.components.keys()

    def get_applet_aid(self):
        ''' returns the aid of tha application if any '''
        # look into the applet component
        applets_aid = []
        if "Applet" in self.components.keys():
            applet_component_str = self.components["Applet"]
            applet_count = utils.getBytes(applet_component_str,4)
            offset = 5
            for i in range(0, int(applet_count, 16)):
                aid_len = utils.getBytes(applet_component_str,offset)
                offset = offset + 1
                aid = utils.getBytes(applet_component_str,offset, int(aid_len, 16))
                offset = offset + int(aid_len, 16)
                applets_aid.append(aid)
                # by pass install method offset
                offset = offset + 2
        return applets_aid

    
    def get_version(self):
        ''' returns the load file  version '''
        # look into the header component
        header_component_str = self.components["Header"]
        # the minor and major version are byte 11 and 12 of the header component
        minor_version = utils.getBytes(header_component_str,11)
        major_version = utils.getBytes(header_component_str,12)
        return  major_version + "." + minor_version

    def get_pkg_name(self):
        ''' returns the load file package name '''
        # look into the header component
        header_component_str = self.components["Header"]
        # the package name is after the package aid in  the header component
        aid_len = utils.getBytes(header_component_str,13)
        name_len_offset = 14 + int(aid_len, 16) + 1
        name_len = utils.getBytes(header_component_str, name_len_offset)
        #package name is not always set (ie JC version 2.1)
        if name_len != '':
            name = utils.getBytes(header_component_str,name_len_offset + 1, int(name_len, 16))
        else:
            name = "not set"
        return name
    
    def get_import_pkg_aid(self):
        ''' return a list of tuple containing pkg_aid, version and eventually the name'''
        # look into the import component
        imported_pkg_aid = []
        if "Import" in self.components.keys():
            import_component_str = self.components["Import"]
            import_count = utils.getBytes(import_component_str,4)
            offset = 5
            for i in range(0, int(import_count, 16)):
                minor_version = utils.getBytes(import_component_str,offset)
                offset = offset + 1
                major_version = utils.getBytes(import_component_str,offset)
                offset = offset + 1
                aid_len = utils.getBytes(import_component_str,offset)
                offset = offset + 1
                aid = utils.getBytes(import_component_str,offset, int(aid_len, 16))
                offset = offset + int(aid_len, 16)
                imported_pkg_aid.append((aid, major_version + "." + minor_version, constants.aid_dict.get(aid, "")))
        return imported_pkg_aid


    def get_load_file_data_hash(self, hashAlgorithm = 'SHA1'):
        ''' Returns the Hash of this load file '''
        if (hashAlgorithm == 'SHA1'):
            # we perform a SHA-1 of the raw code
            return crypto.SHA1(self.get_raw_code())
        elif (hashAlgorithm == 'SHA256'):
            # we perform a SHA-1 of the raw code
            return crypto.SHA256(self.get_raw_code())
        elif (hashAlgorithm == 'SHA384'):
            # we perform a SHA-1 of the raw code
            return crypto.SHA384(self.get_raw_code())
        elif (hashAlgorithm == 'SHA512'):
            # we perform a SHA-1 of the raw code
            return crypto.SHA512(self.get_raw_code())


        else:
            pass

    def __str__(self):
        ''' return a string representation of this load file '''
        str_val = ''
        str_val = str_val  + "CAP file name         : %s\n" %self.get_name()
        str_val = str_val  + "CAP file version      : %s\n" %self.get_version()
        str_val = str_val  + "Package name          : %s\n" %self.get_pkg_name()
        str_val = str_val  + "Package AID           : %s\n" %self.get_aid()
        str_val = str_val  + "Java Card version     : %s\n" %self.get_jc_version()
        str_val = str_val  + "Integer support       : %s\n" %str(self.get_int_support())
        str_val = str_val  + "Import AIDs           : \n"
        for (aid, version, name) in self.get_import_pkg_aid():
            str_val = str_val  + "      %s (%s) version %s\n" %(aid, name, version)
        if self.isAppletPresent():
            for aid in self.get_applet_aid():
                str_val = str_val  + "Applet AID            : %s\n" %aid
        str_val = str_val  + "CAP file components   : \n"
        for component in self.components:
            str_val = str_val  + "     %s.cap (%d  bytes)\n" %(component, int(len(self.components[component])/2))
        
        return str_val
        



    
    def __handle_file__(self):

        data = []
        length = 0
        isExist = os.path.exists(self.loadfile_path)
        if (isExist == True):
            data = array.array('B')
            with open(self.loadfile_path, 'rb') as f:
                while True:
                    try: data.fromfile(f, 1024 * 1024)
                    except EOFError: break

            return data.tolist()
        else:
            raise BaseException("File Not found Error", "The File %s doesn't exist)" %self.loadfile_path)

    def read_ijc_format(self):
    
        data = self.__handle_file__()
        length = len(data)
        offset = 0
        while offset < length:
            aComponent = ''
            #read TAG
            tag = data[offset]
            offset = offset + 1
            #read length
            lHigh = data[offset]
            offset = offset + 1
            lLow = data[offset]
            offset = offset + 1
            componentLength = lHigh<<8
            componentLength = componentLength + lLow
            aComponent = aComponent  + "%02X" % tag
            aComponent = aComponent  + "%02X" % lHigh
            aComponent = aComponent  + "%02X" % lLow 
            for i in range(0, componentLength):
                aComponent = aComponent  + "%02X" % data[offset]
                offset = offset + 1
            
            if (aComponent.startswith('01')):
                self.components["Header"] = aComponent
                magic_number_pos = aComponent.find("DECAFFED")
                if magic_number_pos == -1:
                    return False
            elif (aComponent.startswith('02')):
                # add to the dict
                self.components["Directory"] = aComponent
            elif (aComponent.startswith('03')):
                # add to the dict
                self.components["Applet"] = aComponent
            elif (aComponent.startswith('04')):
                # add to the dict
                self.components["Import"] = aComponent
            elif (aComponent.startswith('05')):
                # add to the dict
                self.components["ConstantPool"] = aComponent
            elif (aComponent.startswith('06')):
                # add to the dict
                self.components["Class"] = aComponent
                
            elif (aComponent.startswith('07')):
                # add to the dict
                self.components["Method"] = aComponent
                
            elif (aComponent.startswith('08')):
                # add to the dict
                self.components["Staticfield"] = aComponent
                
            elif (aComponent.startswith('09')):
                # add to the dict
                self.components["RefLocation"] = aComponent
                
            elif (aComponent.startswith('0A')):
                # add to the dict
                self.components["Export"] = aComponent
            elif (aComponent.startswith('0B')):
                # add to the dict
                self.components["Descriptor"] = aComponent
            elif (aComponent.startswith('0C')):
                # add to the dict
                self.components["Debug"] = aComponent
            else:
                # add to the dict with the tag as entry
                self.components[aComponent[0:2]] = aComponent
        return True

    def read_cap_format(self):
        jarFile = zipfile.ZipFile(self.loadfile_path)
        allcomponents = jarFile.infolist() 
        for comp in allcomponents:
            bytes_data = jarFile.read(comp.filename)
            tmp_data = (c_ubyte*(len(bytes_data)))(*bytes_data)
            temp_data_as_str = utils.toHexString(tmp_data[:len(bytes_data)])
            # check if it a valid cap file
            if (temp_data_as_str.startswith('01')):
                magic_number_pos = temp_data_as_str.find("DECAFFED")
                if magic_number_pos == -1:
                    return False
                # add to the dict
                self.components["Header"] = temp_data_as_str
            elif (temp_data_as_str.startswith('02')):
                # add to the dict
                self.components["Directory"] = temp_data_as_str
            elif (temp_data_as_str.startswith('03')):
                # add to the dict
                self.components["Applet"] = temp_data_as_str
            elif (temp_data_as_str.startswith('04')):
                # add to the dict
                self.components["Import"] = temp_data_as_str
            elif (temp_data_as_str.startswith('05')):
                # add to the dict
                self.components["ConstantPool"] = temp_data_as_str
            elif (temp_data_as_str.startswith('06')):
                # add to the dict
                self.components["Class"] = temp_data_as_str
                
            elif (temp_data_as_str.startswith('07')):
                # add to the dict
                self.components["Method"] = temp_data_as_str
                
            elif (temp_data_as_str.startswith('08')):
                # add to the dict
                self.components["Staticfield"] = temp_data_as_str
                
            elif (temp_data_as_str.startswith('09')):
                # add to the dict
                self.components["RefLocation"] = temp_data_as_str
                
            elif (temp_data_as_str.startswith('0A')):
                # add to the dict
                self.components["Export"] = temp_data_as_str
            elif (temp_data_as_str.startswith('0B')):
                # add to the dict
                self.components["Descriptor"] = temp_data_as_str
            elif (temp_data_as_str.startswith('0C')):
                # add to the dict
                self.components["Debug"] = temp_data_as_str
            else:
                # add to the dict with the tag as entry
                self.components[temp_data_as_str[0:2]] = temp_data_as_str
        return True
    
 
  
    
    def isCapfile(self):
        return self.is_capfile
                    




