import unittest
from pygp import *


class Test_Utils_Module(unittest.TestCase):


    def test_expected_data(self):
        ''' Test the check_expected_data function'''
        status = '9001'
        expected_status = '9000, 6x01, 6Cxx '
        self.assertEqual(False, check_expected_data(status, expected_status))
        status = '9000'
        self.assertEqual(True, check_expected_data(status, expected_status))
        status = '6D01'
        self.assertEqual(True, check_expected_data(status, expected_status))
        status = '906C'
        self.assertEqual(False, check_expected_data(status, expected_status))
        data = '0102030405060708090102030405060708090102030405060708090102030405060708090102030405060708090102030405060708090102030405060708090A'
        expected_data = '010203040506070809010203040506070809010203040506070809010203040506070809010203040506070809010203040506070809010203040506070809'
        self.assertEqual(False, check_expected_data(data, expected_data))
        data = '0102030405060708090102030405060708090102030405060708090102030405060708090102030405060708090102030405060708090102030405060708090A'
        expected_data = '010203040506070809010203040506070809010203040506070809010203040506070809010203040506070809010203040506070809010203040506070809, 010203040506070809010203040506070809010    2030405060708090102030405060708090102030405060708090102030405060708090102030405060708090A'
        self.assertEqual(True, check_expected_data(data, expected_data))
        data = '0102030405060708090102030405060708090102030405060708090102030405060708090102030405060708090102030405060708090102030405060708090A'
        expected_data = '010203040506070809010203040506070809010203040506070809010203040506070809010203040506070809010203040506070809010203040506070809, xXxX03040506070809010203040506070809010    2030405060708090102030405060708090102030405060708090102030405060708090102030405060708090A'
        self.assertEqual(True, check_expected_data(data, expected_data))

    def test_LV(self):
        ''' Test the lv function'''
        astr = ""
        bytestring = lv(astr)
        self.assertEqual(bytestring, "00")
        for i in range(0, 300):
            astr = astr + "01"
        bytestring = lv(astr)
        self.assertEqual(bytestring, "012C" + astr)
        astr = "3B65000  09C11 0101 03"
        bytestring = lv(astr)
        self.assertEqual(bytestring, "093B6500009C11010103") 

    def test_ber_lv(self):
        ''' Test the ber_lv function'''
        astr = ""
        bytestring = ber_lv(astr)
        self.assertEqual(bytestring, "00")

        astr = ""
        for i in range(0, 128):
            astr = astr + "01"
        bytestring = ber_lv(astr)
        self.assertEqual(bytestring, "8180" + astr)

        astr = ""
        for i in range(0, 300):
            astr = astr + "01"
        bytestring = ber_lv(astr)
        self.assertEqual(bytestring, "82012C" + astr)
        astr = "3B65000  09C11 0101 03"
        bytestring = ber_lv(astr)
        self.assertEqual(bytestring, "093B6500009C11010103") 


    def test_der_lv(self):
        ''' Test the der_lv function'''
        astr = ""
        bytestring = der_lv(astr)
        self.assertEqual(bytestring, "00")
        for i in range(0, 300):
            astr = astr + "01"
        bytestring = der_lv(astr)
        self.assertEqual(bytestring, "FF012C" + astr)
        astr = "3B65000  09C11 0101 03"
        bytestring = der_lv(astr)
        self.assertEqual(bytestring, "093B6500009C11010103") 


    def test_getLength(self):
        ''' Test the getLength function'''
        bytestring = getLength("A0A40002", 2)
        self.assertEqual(bytestring, "0004")
        bytestring = getLength("A0A40002", 1)
        self.assertEqual(bytestring, "04") 
        bytestring = getLength("", 1)
        self.assertEqual(bytestring, "00") 
 
    def test_tlv_read(self):
        ''' Test the tlv_read function'''
        # response data for GET DATA KEY INFO
        keyinfo = 'E042C00401228010C00402228010C00403228010C0060174A180A003C00C0274A840A740A640A540A440C00C0374A840A740A640A540A440C0040474B120C0047474B120'
        dic_keyinfo = tlv_read(keyinfo)
        bytestring = dic_keyinfo['E0']['C0'][0]
        self.assertEqual(bytestring, "01228010")
        bytestring = dic_keyinfo['E0']['C0'][3]
        self.assertEqual(bytestring, "0174A180A003")
      

if __name__ == "__main__":

     unittest.main()
