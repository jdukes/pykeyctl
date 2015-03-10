#!/usr/bin/env python

from __future__ import unicode_literals
from inspect import getcallargs

#from .. import exceptions
from sys import path
path.insert(0, '..')
from exceptions import ArgumentTypeException
#from .defines import *
from defines import *
import ctypes
from ctypes.util import find_library

from decorator import decorator #dependancy

keyutils = ctypes.cdll.LoadLibrary(find_library('keyutils'))


###############################################################################
# Type checks, return values, and conversions
###############################################################################

keyutils.add_key.argtypes = [ctypes.c_char_p,
                             ctypes.c_char_p,
                             ctypes.c_char_p,
                             ctypes.c_size_t,
                             key_serial_t] 
keyutils.add_key.restype = key_serial_t

keyutils.request_key.argtypes = [ctypes.c_char_p,
                                 ctypes.c_char_p,
                                 ctypes.c_char_p,
                                 key_serial_t]
keyutils.request_key.restype = key_serial_t

# extern ctypes.c_long keyctl(int cmd, ...);

keyutils.keyctl_get_keyring_ID.restype = key_serial_t
keyutils.keyctl_get_keyring_ID.argtypes = [key_serial_t, ctypes.c_int]

keyutils.keyctl_join_session_keyring.restype = key_serial_t
keyutils.keyctl_join_session_keyring.argtypes = [ctypes.c_char_p]

keyutils.keyctl_update.restype = ctypes.c_long
keyutils.keyctl_update.argtypes = [key_serial_t,
                                   ctypes.c_void_p,
                                   ctypes.c_size_t]

keyutils.keyctl_revoke.restype = ctypes.c_long
keyutils.keyctl_revoke.argtypes = [key_serial_t]

keyutils.keyctl_chown.restype = ctypes.c_long
keyutils.keyctl_chown.argtypes = [key_serial_t, uid_t, gid_t]

keyutils.keyctl_setperm.restype = ctypes.c_long
keyutils.keyctl_setperm.argtypes = [key_serial_t, key_perm_t]

keyutils.keyctl_describe.restype = ctypes.c_long
keyutils.keyctl_describe.argtypes = [key_serial_t,
                                     ctypes.c_char_p,
                                     ctypes.c_size_t]

keyutils.keyctl_clear.restype = ctypes.c_long
keyutils.keyctl_clear.argtypes = [key_serial_t]

keyutils.keyctl_link.restype = ctypes.c_long
keyutils.keyctl_link.argtypes = [key_serial_t, key_serial_t]

keyutils.keyctl_unlink.restype = ctypes.c_long
keyutils.keyctl_unlink.argtypes = [key_serial_t, key_serial_t]

keyutils.keyctl_search.restype =  ctypes.c_long
keyutils.keyctl_search.argtypes = [key_serial_t,
                                   ctypes.c_char_p,
                                   ctypes.c_char_p,
                                   key_serial_t]

keyutils.keyctl_read.restype = ctypes.c_long
keyutils.keyctl_read.argtypes = [key_serial_t, ctypes.c_char_p, ctypes.c_size_t]

keyutils.keyctl_instantiate.restype = ctypes.c_long
keyutils.keyctl_instantiate.argtypes = [key_serial_t,
                                        ctypes.c_void_p,
                                        ctypes.c_size_t,
                                        key_serial_t]

keyutils.keyctl_negate.restype = ctypes.c_long
keyutils.keyctl_negate.argtypes = [key_serial_t, ctypes.c_uint, key_serial_t]
keyutils.keyctl_set_reqkey_keyring.restype = ctypes.c_long
keyutils.keyctl_set_reqkey_keyring.argtypes = [ctypes.c_int]

keyutils.keyctl_set_timeout.restype = ctypes.c_long
keyutils.keyctl_set_timeout.argtypes = [key_serial_t, ctypes.c_uint]

keyutils.keyctl_assume_authority.restype = ctypes.c_long
keyutils.keyctl_assume_authority.argtypes = [key_serial_t]

keyutils.keyctl_get_security.restype = ctypes.c_long
keyutils.keyctl_get_security.argtypes = [key_serial_t,
                                         ctypes.c_char_p,
                                         ctypes.c_size_t]

keyutils.keyctl_session_to_parent.restype = ctypes.c_long
keyutils.keyctl_session_to_parent.argtypes = []

keyutils.keyctl_reject.restype = ctypes.c_long
keyutils.keyctl_reject.argtypes = [key_serial_t,
                                   ctypes.c_uint,
                                   ctypes.c_uint,
                                   key_serial_t]

# struct iovec;
# keyutils.keyctl_instantiate_iov.restype = ctypes.c_long
# keyutils.keyctl_instantiate_iov.argtypes = [key_serial_t,
#                                             const struct iovec *payload_iov, #fix
#                                             ctypes.c_uint,
#                                             key_serial_t]
keyutils.keyctl_invalidate.restype = ctypes.c_long
keyutils.keyctl_invalidate.argtypes = [key_serial_t]

keyutils.keyctl_get_persistent.restype = ctypes.c_long
keyutils.keyctl_get_persistent.argtypes = [uid_t, key_serial_t]

keyutils.keyctl_describe_alloc.restype = ctypes.c_int
keyutils.keyctl_describe_alloc.argtypes = [key_serial_t, c_char_p_p ] 

keyutils.keyctl_read_alloc.restype = ctypes.c_int
keyutils.keyctl_read_alloc.argtypes = [key_serial_t, c_void_p_p ] 

keyutils.keyctl_get_security_alloc.restype = ctypes.c_int
keyutils.keyctl_get_security_alloc.argtypes = [key_serial_t, c_char_p_p ] 

# keyutils.recursive_key_scan.restype = ctypes.c_int
# keyutils.recursive_key_scan.argtypes = [key_serial_t, recursive_key_scanner_t func, void *data ]

# keyutils.recursive_session_key_scan.restype = ctypes.c_int
# keyutils.recursive_session_key_scan.argtypes = [recursive_key_scanner_t func, void *data ]

keyutils.find_key_by_type_and_desc.restype = key_serial_t
keyutils.find_key_by_type_and_desc.argtypes = [ctypes.c_char_p,
                                               ctypes.c_char_p,
                                               key_serial_t]


def validate_args(locals, annotation):
    errors = ["%s is '%s' but should be '%s'" % (k,
                                                 type(v).__name__,
                                                 annotation[k].__name__)
              for k,v in locals.items()
              if not type(v) in annotation[k]]
    if errors:
        raise ArgumentTypeException(errors)

    
@decorator    
def validated(fn, *args, **kwargs):
    validate_args(getcallargs(fn, *args, **kwargs), fn.__annotations__)
    return fn(*args, **kwargs)


###############################################################################
# Exported functions
###############################################################################

@validated
def add_key(descrip: [bytes],
            payload: [bytes],
            key_type: [bytes] = b"user",
            keyring: [int] = -4) -> 'int':
    """Add a key to a keyring. This is a wrapper for the following function:

    key_serial_t add_key(const char *type, const char *desc,
                         ctypes.c_void_p, size_t plen,
			 key_serial_t keyring);
    """
    return keyutils.add_key(key_type, descrip, payload, len(payload)+1, keyring)

# def request_key(descrip: 'bytes',
#                 key_type: 'bytes' = b"user",
#                 callout_info: 'bytes', 
#                 keyring: 'int' = -4) -> 'int':

# 	key_serial_t request_key(const char *type, const char *description,
# 				 const char *callout_info,
# 				 key_serial_t dest_keyring);
