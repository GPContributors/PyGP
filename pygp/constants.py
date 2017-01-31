'''
.. _set-status-card-element:

Set_Status Reference Control Parameter P1
-----------------------------------------

The following constants valurs could be used with the :func:`set_status()` function for the parameter cardElement.

**CARD_ELEMENT_ISD ('80')**  to indicate Issuer Security Domain.

**CARD_ELEMENT_APPLICATION_AND_SSD ('40')** to indicate Application or Supplementary Security Domain.

**CARD_ELEMENT_SD_AND_APPLICATIONS ('60')** to indicate Application or Supplementary Security Domain.


.. _privileges:
		
Security Domain privileges
--------------------------
		
			+----------+---------------------------------+
			| Value    |  Description                    |
			+==========+=================================+
			| "CSA"    |  Contactless Self Activation    |
			+----------+---------------------------------+
			| "CA"     |  Contactless Activation         |
			+----------+---------------------------------+
			| "CLFDB"  |  Ciphered Load File Block       |
			+----------+---------------------------------+
			| "RG"     |  Receipt Generation             |
			+----------+---------------------------------+
			| "GS"     |  Global Service                 |
			+----------+---------------------------------+
			| "FA"     |  Final Application              |
			+----------+---------------------------------+
			| "GR"     |  Global Registry                |
			+----------+---------------------------------+
			| "GL"     |  Global Lock                    |
			+----------+---------------------------------+
			| "GD"     |  Global Delete                  |
			+----------+---------------------------------+
			| "TM"     | Token Management                |
			+----------+---------------------------------+
			| "AM"     | Authorized Management           |
			+----------+---------------------------------+
			| "TP"     | Trusted Path                    |
			+----------+---------------------------------+
			| "MDAPV"  | Mandated DAP Verification       |
			+----------+---------------------------------+
			| "CVMM"   | CVM management                  |
			+----------+---------------------------------+
			| "CR"     | Card Reset                      |
			+----------+---------------------------------+
			| "CT"     | Card Terminated                 |
			+----------+---------------------------------+
			| "CL"     | Card Lock                       |
			+----------+---------------------------------+
			| "DM"     | Delegated Management            |
			+----------+---------------------------------+
			| "DAPV"   | DAP Verification                |
			+----------+---------------------------------+
			| "SD"     | Security Domain                 |
			+----------+---------------------------------+

'''
ISD_PACKAGE_AID = "A0000001515350"
ISD_MODULE_AID  = "A000000151535041"


GP_SCP02 = 0x02
GP_SCP03 = 0x03


KENC_TYPE = 0x01
KMAC_TYPE = 0x02
KDEK_TYPE  = 0x03
KRMAC_TYPE = 0x04

SECURITY_LEVEL_NO_SECURE_MESSAGING      =  0x00 #!< Secure Channel Protocol '03': No secure messaging expected.
SECURITY_LEVEL_C_MAC                    =  0x01 #!< Secure Channel Protocol '02': C-MAC
SECURITY_LEVEL_C_DEC_C_MAC              =  0x03 #!< Secure Channel Protocol '02': C-DECRYPTION and C-MAC
SECURITY_LEVEL_R_MAC                    =  0x10 #!< Secure Channel Protocol '02': R-MAC
SECURITY_LEVEL_C_MAC_R_MAC              =  0x11 #!< Secure Channel Protocol '03': C-MAC and R-Mac
SECURITY_LEVEL_C_DEC_C_MAC_R_MAC        =  0x13 #!< Secure Channel Protocol '02': C-DECRYPTION, C-MAC and R-MAC
SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC  =  0x33 #!< Secure Channel Protocol '03': C-Decryption, C-MAC, R-Mac and R-Encryption


CARD_ELEMENT_ISD                        = '80'   #!< Indicate Issuer Security Domain.
CARD_ELEMENT_APPLICATION_AND_SSD        = '40'   #!< Indicate Application or Supplementary Security Domain.
CARD_ELEMENT_SD_AND_APPLICATIONS        = '60'   #!< Indicate Application or Supplementary Security Domain.


LIFE_CYCLE_LOAD_FILE_LOADED             = '01'   #!< Executable Load File is loaded.
LIFE_CYCLE_CARD_OP_READY                = '01'   #!< Card is OP ready.
LIFE_CYCLE_CARD_INITIALIZED             = '07'   #!< Card is initialized.
LIFE_CYCLE_CARD_SECURED                 = '0F'   #!< Card is in secured state.
LIFE_CYCLE_CARD_LOCKED                  = '7F'   #!< Card is locked.
LIFE_CYCLE_CARD_TERMINATED              = 'FF'   #!< Card is terminated.
LIFE_CYCLE_APPLICATION_INSTALLED        = '03'   #!< Application is installed
LIFE_CYCLE_APPLICATION_SELECTABLE       = '07'   #!< Application is selectable.
LIFE_CYCLE_APPLICATION_LOCKED           = 'FF'   #!< Application is locked.
LIFE_CYCLE_SECURITY_DOMAIN_INSTALLED    = '03'   #!< Application is installed
LIFE_CYCLE_SECURITY_DOMAIN_SELECTABLE   = '07'   #!< Application is selectable.
LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED = 'FF'   #!< Application is personalized.
LIFE_CYCLE_SECURITY_DOMAIN_LOCKED       = 'FF'   #!< Application is locked.


# Secure Channel Protocol '02': "i" = '44': Initiation mode explicit, C-MAC on modified APDU,
# ICV set to zero, no ICV encryption, 1 Secure Channel base key,
# well-known pseudo-random algorithm (card challenge),

SCP02_IMPL_i44  = '44'
# Secure Channel Protocol '02': "i" = '45': Initiation mode explicit, C-MAC on modified APDU,
# ICV set to zero, no ICV encryption, 3 Secure Channel Keys,
# well-known pseudo-random algorithm (card challenge),


SCP02_IMPL_i45  = '45'
# Secure Channel Protocol '02': "i" = '54': Initiation mode explicit, C-MAC on modified APDU,
# ICV set to zero, ICV encryption for C-MAC session, 1 Secure Channel base key,
# well-known pseudo-random algorithm (card challenge),

SCP02_IMPL_i54  = '54'
# Secure Channel Protocol '02': "i" = '55': Initiation mode explicit, C-MAC on modified APDU,
# ICV set to zero, ICV encryption for C-MAC session, 3 Secure Channel Keys,
# well-known pseudo-random algorithm (card challenge).

SCP02_IMPL_i55  = '55'
# Secure Channel Protocol '02': "i" '04': Initiation mode explicit, C-MAC on modified APDU,
# ICV set to zero, no ICV encryption, 1 Secure Channel base key, unspecified card challenge generation method

SCP02_IMPL_i04  = '04'
# Secure Channel Protocol '02': "i" '05': Initiation mode explicit, C-MAC on modified APDU,
# ICV set to zero, no ICV encryption, 3 Secure Channel Keys, unspecified card challenge generation method

SCP02_IMPL_i05  = '05'
# Secure Channel Protocol '02': "i" '0A': Initiation mode implicit, C-MAC on unmodified APDU,
# ICV set to MAC over AID, no ICV encryption, 1 Secure Channel base key

SCP02_IMPL_i0A  = '0A'
# Secure Channel Protocol '02': "i" '0B': Initiation mode implicit, C-MAC on unmodified APDU,
# ICV set to MAC over AID, no ICV encryption, 3 Secure Channel Keys

SCP02_IMPL_i0B  = '0B'
# Secure Channel Protocol '02': "i" '14': Initiation mode explicit, C-MAC on modified APDU,
# ICV set to zero, ICV encryption for CMAC session, 1 Secure Channel base key,
# unspecified card challenge generation method

SCP02_IMPL_i14  = '14'
# Secure Channel Protocol '02': "i" '15': Initiation mode explicit, C-MAC on modified APDU,
# ICV set to zero, ICV encryption for CMAC session, 3 Secure Channel Keys,
# unspecified card challenge generation method

SCP02_IMPL_i15  = '15'
# Secure Channel Protocol '02': "i" '1A': Initiation mode implicit, C-MAC on unmodified APDU,
# ICV set to MAC over AID, ICV encryption for C-MAC session, 1 Secure Channel base key

SCP02_IMPL_i1A  = '1A'
# Secure Channel Protocol '02': "i" '1B': Initiation mode implicit, C-MAC on unmodified APDU,
# ICV set to MAC over AID, ICV encryption for C-MAC session, 3 Secure Channel Keys

SCP02_IMPL_i1B  = '1B'

# Secure Channel Protocol '03': "i" '00': No R-MAC, no R-ENCRYPTION, no Pseudo-random cryptogram

SCP03_IMPL_i00  = '00'
# 
# Secure Channel Protocol '03': "i" '10': Pseudo-random card challenge, no R-MAC support, no R-ENCRYPTION support.

SCP03_IMPL_i10  = '10'

# 
# Secure Channel Protocol '03': "i" '30': Pseudo-random card challenge, R-MAC support, no R-ENCRYPTION support.

SCP03_IMPL_i30  = '30'

# 
# Secure Channel Protocol '03': "i" '20': Random card challenge, R-MAC support, no R-ENCRYPTION support.

SCP03_IMPL_i20  = '20'

# 
# Secure Channel Protocol '03': "i" '60': Random card challenge, R-MAC support, R-ENCRYPTION support.

SCP03_IMPL_i60  = '60'

# 
# Secure Channel Protocol '03': "i" '70': Pseudo-random card challenge, R_MAC, support, R-ENCRYPTION support.

SCP03_IMPL_i70  = '70'


key_type_coding_dict = {
    
    "DES": '80',
    "DES-ECB": '83',
    "DES-CBC": '84',
    "AES": '88',
    "RSA-PRIV": 'A2',
    "RSA-PUB": 'A0'

}

key_types_dict = {
                "80":"DES mode (ECB/CBC) implicitly known",
                "81" :"Reserved (Triple DES)",
                "82" :"Triple DES in CBC mode",
                "83" :"DES in ECB mode",
                "84" :"DES in CBC mode",
                "85" :"Pre Shared Key for Transport Layer Security",
                "86" :"RFU (symmetric algorithms)",
                "87" :"RFU (symmetric algorithms)",
                "88" :"AES (16, 24, or 32 long keys)",
                "89" :"RFU (symmetric algorithms)",
                "8A" :"RFU (symmetric algorithms)",
                "8B" :"RFU (symmetric algorithms)",
                "8C" :"RFU (symmetric algorithms)",
                "8D" :"RFU (symmetric algorithms)",
                "8E" :"RFU (symmetric algorithms)",
                "8F" :"RFU (symmetric algorithms)",
                "90" :"HMAC SHA1 length of HMAC is implicitly known",
                "91" :"HMAC SHA1 160 length of HMAC is 160 bits",
                "92" :"RFU (symmetric algorithms)",
                "93" :"RFU (symmetric algorithms)",
                "94" :"RFU (symmetric algorithms)",
                "95" :"RFU (symmetric algorithms)",
                "96" :"RFU (symmetric algorithms)",
                "97" :"RFU (symmetric algorithms)",
                "98" :"RFU (symmetric algorithms)",
                "99" :"RFU (symmetric algorithms)",
                "9A" :"RFU (symmetric algorithms)",
                "9B" :"RFU (symmetric algorithms)",
                "9C" :"RFU (symmetric algorithms)",
                "9D" :"RFU (symmetric algorithms)",
                "9E" :"RFU (symmetric algorithms)",
                "9F" :"RFU (symmetric algorithms)",
                "A0" :"RSA Public Key  public exponent e component (clear text)",
                "A1" :"RSA Public Key  modulus N component (clear text)",
                "A2" :"RSA Private Key  modulus N component",
                "A3" :"RSA Private Key  private exponent d component",
                "A4" :"RSA Private Key  Chinese Remainder P component",
                "A5" :"RSA Private Key  Chinese Remainder Q component",
                "A6" :"RSA Private Key  Chinese Remainder PQ component",
                "A7" :"RSA Private Key  Chinese Remainder DP1 component  )",
                "A8" :"RSA Private Key  Chinese Remainder DQ1 component )",
                "A9" :"RFU (asymmetric algorithms)",
                "FF" :"Extended format"
               
               }


privileges_def = (
    "RFU-b1",
    "RFU-b2",
    "RFU-b3",
    "RFU-b4",
    "CSA",
    "CA",
    "CLFDB",
    "RG",
    "GS",
    "FA",
    "GR",
    "GL",
    "GD",
    "TM",
    "AM",
    "TP",
    "MDAPV",
    "CVMM",
    "CR",
    "CT",
    "CL",
    "DM",
    "DAPV",
    "SD"
)

privileges_byte1 = ({0x80:"SD",\
                    0x40:"DAPV",\
                    0x20:"DM",\
                    0x10:"CL",\
                    0x08:"CT",\
                    0x04:"CR",\
                    0x02:"CVMM",\
                    0x01:"MDAPV"})

privileges_byte2 = ({0x80:"TP",\
                    0x40:"AM",\
                    0x20:"TM",\
                    0x10:"GD",\
                    0x08:"GL",\
                    0x04:"GR",\
                    0x02:"FA",\
                    0x01:"GS"})

privileges_byte3 = ({0x80:"RG",\
                    0x40:"CLFDB",\
                    0x20:"CA",\
                    0x10:"CSA"})


SD_LifeCycleState = ({'01':"OP READY",\
                      '07':"INITIALIZED",\
                      '0F':"SECURED",\
                      '7F':"CARD_LOCKED",\
                      'FF':"TERMINATED"})
Application_LifeCycleState= ({'03':"INSTALLED",\
                      '07':"SELECTABLE",\
                      '0F':"PERSONALIZED",\
                      '80':"LOCKED"})

ExecutableLoadFile_LifeCycleState = ({'01':"LOADED"})


# The AID dictionary allows to define a package name regarding its AID
aid_dict = {
"A0000000030000":   "visa.openplatform",
"A00000015100":     "org.globalplatform",
"A0000000620001":   "java.lang",
"A0000000620002":   "java.io",
"A0000000620003":   "java.rmi",
"A0000000620101":   "javacard.framework",
"A000000062010101": "javacard.framework.service",
"A0000000620102":   "javacard.security",
"A0000000620201":   "javacardx.crypto",
"A000000227011000": "koreanpackage.crypto",
"A00000000310":     "VSDC",
"A0000000036010":   "VisaCash",
"A000000063":       "PKCS15",
"315041592E":       "PSE",
"A0000000046010":   "CashCard",
"A0000000035350":   "Security Domain",
"A000000167413000": "nJCOP System",
"A000000167413001": "FIPS 140-2",
"A0000001320001":   "org.javacardforum.javacard.biometry"

}