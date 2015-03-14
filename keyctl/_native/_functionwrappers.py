#!/usr/bin/env python
from __future__ import unicode_literals

import errno
import ctypes
from ctypes.util import find_library
from inspect import getcallargs


from .._exceptions import *

from .defines import *

from decorator import decorator 


keyutils = ctypes.CDLL(find_library('keyutils'), use_errno=True)

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

# keyutils.keyctl_get_persistent.restype = ctypes.c_long
# keyutils.keyctl_get_persistent.argtypes = [uid_t, key_serial_t]

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

# keyutils.find_key_by_type_and_desc.restype = key_serial_t
# keyutils.find_key_by_type_and_desc.argtypes = [ctypes.c_char_p,
#                                                ctypes.c_char_p,
#                                                key_serial_t]

def validate_args(callargs, annotation):
    errors = ["%s is '%s' but should be one of '%s'" % (k,
                                                        type(v).__name__,
                                                        [a.__name__ for a in
                                                         annotation[k]])
              for k,v in callargs.items()
              if not type(v) in annotation[k]]
    if errors:
        raise ArgumentTypeException(errors)


###############################################################################
# Return checks
###############################################################################


def error_check(ret, fn):
    if ret == -1:
        raise KeyCtlError(ctypes.get_errno(), fn)


@decorator
def error_checked(fn, *args, **kwargs):
    ret = fn(*args, **kwargs)
    error_check(ret, fn)
    return ret


###############################################################################
# Helpers
###############################################################################

def wrapped_string_reader(fn, key):
    buf_len = fn(key, ctypes.c_char_p(), 0)
    error_check(buf_len, fn)
    buf = bytes(buf_len)
    ret = fn(key, buf, buf_len)
    error_check(ret, fn)
    if ret < buf_len:
        raise UnderflowError(buf_len, ret)
    return buf
    

###############################################################################
# Exported functions
###############################################################################

@error_checked
def add_key(descrip,
             payload,
             key_type = b"user",
             keyring = -4) -> key_serial_t:
    """Add a key to a keyring. 

    This is a wrapper for the following function:

        key_serial_t add_key(const char *type, const char *desc,
                             ctypes.c_void_p, size_t plen,
                             key_serial_t keyring);
    """
    return keyutils.add_key(key_type, descrip,
                            payload, len(payload)+1, keyring)
    

@error_checked
def request_key(descrip,
                 callout_info = None,
                 key_type = b"user",
                 dest_keyring = -4) -> key_serial_t:
    """Find or generate a key and add it to the dest_keyring.

    This is a wrapper for the following function:

    	key_serial_t request_key(const char *type, const char *description,
				 const char *callout_info,
				 key_serial_t dest_keyring);
    """
    return keyutils.request_key(key_type, descrip, callout_info, dest_keyring)

#------------------------------------------------------------------------------
# keyctl function wrappers
#------------------------------------------------------------------------------

@error_checked
def keyctl_get_keyring(key, create=False):
    """Get keyring by ID.
    
    This is a wrapper for the following function:

        extern key_serial_t keyctl_get_keyring_ID(key_serial_t id, int create);
    """
    return keyutils.keyctl_get_keyring_ID(key, create)


@error_checked
def keyctl_join_session_keyring(name = None) -> key_serial_t:

    """Join a session keyring by name, or make an anonymous one.

    If no args are passed in or name is None, an anonymous keyring is
    created attached to the process as its session keyring,
    displacing the old session keyring.

    This is a wrapper for the following function:

        extern key_serial_t keyctl_join_session_keyring(const char *name);
    """
    return keyutils.keyctl_join_session_keyring(name)


@error_checked
def keyctl_update(key, payload):
    """Updated the payload for a key by ID.
    
    This is a wrapper for the following function:

        extern long keyctl_update(key_serial_t id, const void *payload, size_t plen);
    """
    return keyutils.keyctl_update(key, payload, len(payload))


@error_checked
def keyctl_revoke(key):
    """Make the key unavailable for further operations.

    This is a wrapper for the following function:

        extern long keyctl_revoke(key_serial_t id);
    """
    return keyutils.keyctl_revoke(key)


@error_checked
def keyctl_chown(key, uid, gid) -> ctypes.c_long:
    """Change ownership of a key. 

    Either one of uid or gid can be set to -1 to suppress that change.
    
    This is a wrapper for the following function:

        extern long keyctl_chown(key_serial_t id, uid_t uid, gid_t gid);
    """
    return keyutils.keyctl_chown(key, uid, gid)


@error_checked
def keyctl_chmod(key, perm) -> ctypes.c_long:
    """Change the permissions of a key.
    
    This is a wrapper for the following function:

        extern long keyctl_setperm(key_serial_t id, key_perm_t perm);
    """
    return keyutils.keyctl_setperm(key, perm)


@error_checked
def keyctl_describe(key) -> bytes:
    """Get a summary of key attributes.

    A successful call will return a bytes of the following format:
    b"<type>;<uid>;<gid>;<perm>;<description>"

    This is a wrapper for the following function:

        extern long keyctl_describe(key_serial_t id, char *buffer, size_t buflen);
    """
    return wrapped_string_reader(keyutils.keyctl_describe, key)


@error_checked
def keyctl_clear_keyring(ringid) -> ctypes.c_long:
    """Clear a keyring by id.

    This is a wrapper for the following function:

        extern long keyctl_clear(key_serial_t ringid);
    """
    return keyutils.keyctl_clear(ringid)


@error_checked
def keyctl_link(key,
                ringid) -> ctypes.c_long:

    """Link a key to a keyring.

    This is a wrapper for the following function:

        extern long keyctl_link(key_serial_t id, key_serial_t ringid);
    """
    return keyutils.keyctl_link(key, ringid)


@error_checked
def keyctl_unlink(key,
                  ringid) -> ctypes.c_long:
    """Remove a key from a keyring given permission to modify the keyring.

    This is a wrapper for the following function:

        extern long keyctl_unlink(key_serial_t id, key_serial_t ringid);
    """
    return keyutils.keyctl_unlink(key, ringid)


@error_checked
def keyctl_search_keytree(ringid,
                          key_type,
                          description,
                          destringid) -> key_serial_t:
    """Search src_keyring tree for a key and add it to the dest_keyring:

    This is a wrapper for the following function:

        extern long keyctl_search(key_serial_t ringid, const char *type, const char *description, key_serial_t destringid);
    """
    return keyutils.keyctl_search(ringid, key_type, description, destringid)


@error_checked
def keyctl_read(key) -> bytes:
    """Return the payload for a key. 

    Get the key payload for a given key id. In Python this is
    impossible to securely erase. Do not read highly sensitive keys
    using this method.

    This is a wrapper for the following function:

        extern long keyctl_read(key_serial_t id, char *buffer, size_t buflen);
    """
    return wrapped_string_reader(keyutils.keyctl_read, key)

@error_checked
def keyctl_session_to_parent():
    """Install the calling process's session keyring on its parent.

    This is a wrapper for the following function:

        extern long keyctl_session_to_parent(void);
    """
    return keyutils.keyctl_session_to_parent(void)


@error_checked
def keyctl_instantiate(key,
                       payload,
                       ringid) -> ctypes.c_long:
    """Instantiate a partially constructed key.

    Assign the value payload to the key in keyring.
    
    This is a wrapper for the following function:

        extern long keyctl_instantiate(key_serial_t id, const void *payload, size_t plen, key_serial_t ringid);
    """
    return keyutils.keyctl_instantiate(key, payload, len(payload), ringid)

# @error_checked
# def keyctl_instantiate_iov(*args, **kwargs):
#     """NOT IMPLEMENTED.

#     Instantiate a partially constructed key. Assign the value payload
#     to the key in keyring.
    
#     This is a wrapper for the following function:

#         extern long keyctl_negate(key_serial_t id, unsigned timeout, key_serial_t ringid);
#     """
#     

@error_checked
def keyctl_negate(key,
                  timeout,
                  ringid = None ) -> ctypes.c_long:
    """Negate the initialization of a key.

    If a keyring is specified and not None the key will also be linked
    into that keyring given proper permissions. Searches for this key
    will return "No such key" (ENOKEY) until the timeout expires.

    This is a wrapper for the following function:

      extern long keyctl_negate(key_serial_t id, unsigned timeout, key_serial_t ringid);
    """
    return keyutils.keyctl_negate(key, timeout, ringid)


@error_checked
def keyctl_reject(key,
                  timeout,
                  error,
                  ringid = None ) -> ctypes.c_long:
    """Reject the initialization of a key.

    If a keyring is specified and not None the key will also be linked
    into that keyring given proper permissions. Searches for this key
    will return the error specified by "error" until the timeout expires.

    This is a wrapper for the following function:

       extern long keyctl_reject(key_serial_t id, unsigned timeout, 
                                 unsigned error, key_serial_t ringid);
    """
    return keyutils.keyctl_reject(key, timeout, error, ringid);
                                  

@error_checked
def keyctl_set_req_keyring(reqkey_defl) -> ctypes.c_long:
    """Set the default request-key destination keyring.

    The following constants define which keyring to assign as default:

	CONSTANT				VALUE	NEW DEFAULT KEYRING
	======================================	======	=======================
	KEY_REQKEY_DEFL_NO_CHANGE		-1	No change
	KEY_REQKEY_DEFL_DEFAULT			0	Default[1]
	KEY_REQKEY_DEFL_THREAD_KEYRING		1	Thread keyring
	KEY_REQKEY_DEFL_PROCESS_KEYRING		2	Process keyring
	KEY_REQKEY_DEFL_SESSION_KEYRING		3	Session keyring
	KEY_REQKEY_DEFL_USER_KEYRING		4	User keyring
	KEY_REQKEY_DEFL_USER_SESSION_KEYRING	5	User session keyring
	KEY_REQKEY_DEFL_GROUP_KEYRING		6	Group keyring


    This is a wrapper for the following function:

        extern long keyctl_set_reqkey_keyring(int reqkey_defl);
    """
    if type(reqkey_defl) == 'str':
        reqkey_defl = -KEYRING[reqkey_defl]
    return keyutils.keyctl_set_reqkey_keyring(reqkey_defl)

@error_checked
def keyctl_get_default_req_keyring(): 
    return KEYRING[-keyctl_set_req_keyring(-1)]


@error_checked
@input_validated
def keyctl_set_timeout(key,
                       timeout) -> ctypes.c_long:
    """Set the timeout on a key.
                 
    This is a wrapper for the following function:

        extern long keyctl_set_timeout(key_serial_t key, unsigned timeout);
    """
    return keyutils.keyctl_set_timeout(key, timeout)


@error_checked
def keyctl_assume_authority(key) -> ctypes.c_long:
    """Assume the authority granted to instantiate a key.

    This is a wrapper for the following function:

        extern long keyctl_assume_authority(key_serial_t key);

    """
    return keyutils.keyctl_assume_authority(key)

@error_checked
def keyctl_get_security_context(key) -> bytes:
    """Get the LSM security context attached to a key.
    
    Get a string represenatiation of the LSM security context.

    This is a wrapper for the following function:

        extern long keyctl_get_security(key_serial_t key, char *buffer, size_t buflen);
    """
    return wrapped_string_reader(keyutils.keyctl_get_security, key)

# struct iovec;
# extern long keyctl_instantiate_iov(key_serial_t id,
# 				   const struct iovec *payload_iov,
# 				   unsigned ioc,

@error_checked
def keyctl_invaldate(key) -> ctypes.c_long:
    """Invalidate this key.

    This is a wrapper for the following function:

        extern long keyctl_invalidate(key_serial_t id);
    """
    return keyutils.keyctl_invalidate(key)

#extern long keyctl_get_persistent(uid_t uid, key_serial_t id);



