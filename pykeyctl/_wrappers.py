#!/usr/bin/env python

from __future__ import absolute_import, unicode_literals

#from . import exceptions
import exceptions
import ctypes

###############################################################################
# Defines
###############################################################################
keyutils = ctypes.cdll.LoadLibrary(ctypes.util.find_library('keyutils'))

KEYCTL_GET_KEYRING_ID = 0
KEYCTL_UPDATE = 2
KEYCTL_REVOKE = 3
KEYCTL_CHOWN = 4
KEYCTL_SETPERM = 5
KEYCTL_DESCRIBE = 6
KEYCTL_CLEAR = 7
KEYCTL_LINK = 8
KEYCTL_UNLINK = 9
KEYCTL_SEARCH = 10
KEYCTL_READ = 11
KEYCTL_INSTANTIATE = 12
KEYCTL_NEGATE=13
KEYCTL_SET_REQKEY_KEYRING = 14
KEYCTL_SET_TIMEOUT = 15
KEYCTL_ASSUME_AUTHORITY = 16

KEYRING = {"Thread": -1,
           "Process": -2,
           "Session": -3,
           "User": -4,
           "User_session": -5,
           "group": -6,
           "reqkey_auth_key": -7} #	assumed request_key() authorisation key

KEY_REQKEY_DEFL_NO_CHANGE = -1#	No change
KEY_REQKEY_DEFL_DEFAULT = 0 #	Default[1]

KEY_REQKEY_DEFL_THREAD_KEYRING = -1#	Thread keyring
KEY_REQKEY_DEFL_PROCESS_KEYRING = -2 # Process keyring
KEY_REQKEY_DEFL_SESSION_KEYRING = -3 # Session keyring
KEY_REQKEY_DEFL_USER_KEYRING = -4 # User keyring
KEY_REQKEY_DEFL_USER_SESSION_KEYRING = -5 # User session keyring
KEY_REQKEY_DEFL_GROUP_KEYRING = -6 # Group keyring

# typedef

#from include/linux/key.h
key_serial_t = ctypes.c_int32

###############################################################################
# Type checks and conversions
###############################################################################

def get_string_types(*objs):
    return (i for i in objs if type(i) in (str))


###############################################################################
# Exported functions
###############################################################################

keyutils.add_key.argtypes = [ctypes.c_char_p,
                             ctypes.c_char_p,
                             ctypes.c_char_p,
                             ctypes.c_size_t,
                             key_serial_t] 
keyutils.add_key.restype = key_serial_t

def add_key(descrip, payload, key_type="user", keyring="User"):
    """Add a key to a keyring. This is a wrapper for the following function:

    key_serial_t add_key(const char *type, const char *desc,
                         const void *payload, size_t plen,
			 key_serial_t keyring);
    """
    #keyutils.add_key
    #keyutils.add_key(b"user", b"test", b"testpayload", len("testpayload")+1, -4)
    
