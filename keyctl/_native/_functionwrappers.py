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

@decorator
def input_validated(fn, *args, **kwargs):
    validate_args(getcallargs(fn, *args, **kwargs), fn.__annotations__)
    return fn(*args, **kwargs)


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

def keyctl_string_reader(op, key):
    buf_len = keyutils.keyctl(op,
                              key,
                              ctypes.c_char_p(),
                              0)
    error_check(buf_len, )
    ret = keyutils.keyctl(op, key, buf, buf_len)
    buf = bytes(buf_len)
    error_check(ret, _get_security_context)
    if ret < buf_len:
        raise UnderflowError(buf_len, ret)
    return buf


#merge these two
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

#@type_convert
@error_checked
def add_key(descrip: [bytes],
             payload: [bytes],
             key_type: [bytes] = b"user",
             keyring: [key_serial_t, int] = -4) -> key_serial_t:
    """Add a key to a keyring. 

    This is a wrapper for the following function:

        key_serial_t add_key(const char *type, const char *desc,
                             ctypes.c_void_p, size_t plen,
                             key_serial_t keyring);
    """
    return keyutils.add_key(key_type, descrip,
                            payload, len(payload)+1, keyring)
    

@error_checked
def request_key(descrip: [bytes],
                 callout_info: [bytes, None] = None,
                 key_type: [bytes] = b"user",
                 dest_keyring: [key_serial_t, int] = -4) -> key_serial_t:
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
def keyctl_get_keyring(key: [key_serial_t, int], create: [bool, int]=False):
    """Get keyring by ID.
    
    This is a wrapper for the following function:

        extern key_serial_t keyctl_get_keyring_ID(key_serial_t id, int create);
    """
    return keyutils.keyctl_get_keyring_ID(key, create)


@error_checked
def keyctl_join_session_keyring(name: [bytes, None] = None) -> key_serial_t:

    """Join a session keyring by name, or make an anonymous one.

    If no args are passed in or name is None, an anonymous keyring is
    created attached to the process as its session keyring,
    displacing the old session keyring.

    This is a wrapper for the following function:

        extern key_serial_t keyctl_join_session_keyring(const char *name);
    """
    return keyutils.keyctl_join_session_keyring(name)


@error_checked
def keyctl_update(key: [key_serial_t, int], payload: [bytes]):
    """Updated the payload for a key by ID.
    
    This is a wrapper for the following function:

        extern long keyctl_update(key_serial_t id, const void *payload, size_t plen);
    """
    return keyutils.keyctl_update(key, payload, len(payload))


@error_checked
def keyctl_revoke(key: [key_serial_t, int]):
    """Make the key unavailable for further operations.

    This is a wrapper for the following function:

        extern long keyctl_revoke(key_serial_t id);
    """
    return keyutils.keyctl_revoke(key)


@error_checked
def keyctl_chown(key: [key_serial_t, int], uid: [uid_t], gid: [gid_t]) -> ctypes.c_long:
    """Change ownership of a key. 

    Either one of uid or gid can be set to -1 to suppress that change.
    
    This is a wrapper for the following function:

        extern long keyctl_chown(key_serial_t id, uid_t uid, gid_t gid);
    """
    return keyutils.keyctl_chown(key, uid, gid)


@error_checked
def keyctl_chmod(key: [key_serial_t, int], perm: [key_perm_t]) -> ctypes.c_long:
    """Change the permissions of a key.
    
    This is a wrapper for the following function:

        extern long keyctl_setperm(key_serial_t id, key_perm_t perm);
    """
    return keyutils.keyctl_setperm(key, perm)


@error_checked
def keyctl_describe(key: [key_serial_t, int]) -> bytes:
    """Get a summary of key attributes.

    A successful call will return a bytes of the following format:
    b"<type>;<uid>;<gid>;<perm>;<description>"

    This is a wrapper for the following function:

        extern long keyctl_describe(key_serial_t id, char *buffer, size_t buflen);
    """
    return wrapped_string_reader(keyutils.keyctl_describe, key)


@error_checked
def keyctl_clear_keyring(ringid: [key_serial_t, int]) -> ctypes.c_long:
    """Clear a keyring by id.

    This is a wrapper for the following function:

        extern long keyctl_clear(key_serial_t ringid);
    """
    return keyutils.keyctl_clear(ringid)


@error_checked
def keyctl_link(key: [key_serial_t, int],
                ringid: [key_serial_t, int]) -> ctypes.c_long:

    """Link a key to a keyring.

    This is a wrapper for the following function:

        extern long keyctl_link(key_serial_t id, key_serial_t ringid);
    """
    return keyutils.keyctl_link(key, ringid)


@error_checked
def keyctl_unlink(key: [key_serial_t, int],
                  ringid: [key_serial_t, int]) -> ctypes.c_long:
    """Remove a key from a keyring given permission to modify the keyring.

    This is a wrapper for the following function:

        extern long keyctl_unlink(key_serial_t id, key_serial_t ringid);
    """
    return keyutils.keyctl_unlink(key, ringid)


@error_checked
def keyctl_search_keytree(ringid: [key_serial_t, int],
                          key_type: [bytes],
                          description: [bytes],
                          destringid: [key_serial_t, int]) -> key_serial_t:
    """Search src_keyring tree for a key and add it to the dest_keyring:

    This is a wrapper for the following function:

        extern long keyctl_search(key_serial_t ringid, const char *type, const char *description, key_serial_t destringid);
    """
    return keyutils.keyctl_search(ringid, key_type, description, destringid)


@error_checked
def keyctl_read(key: [key_serial_t, int]) -> bytes:
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
def keyctl_instantiate(key: [key_serial_t, int],
                       payload: [bytes],
                       ringid: [key_serial_t, int]) -> ctypes.c_long:
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
def keyctl_negate(key: [key_serial_t, int],
                  timeout: [ctypes.c_uint],
                  ringid: [key_serial_t, int, None] = None ) -> ctypes.c_long:
    """Negate the initialization of a key.

    If a keyring is specified and not None the key will also be linked
    into that keyring given proper permissions. Searches for this key
    will return "No such key" (ENOKEY) until the timeout expires.

    This is a wrapper for the following function:

      extern long keyctl_negate(key_serial_t id, unsigned timeout, key_serial_t ringid);
    """
    return keyutils.keyctl_negate(key, timeout, ringid)


@error_checked
def keyctl_reject(key: [key_serial_t, int],
                  timeout: [ctypes.c_uint],
                  error: [ctypes.c_uint],
                  ringid: [key_serial_t, int, None] = None ) -> ctypes.c_long:
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
def keyctl_set_req_keyring(reqkey_defl: [ctypes.c_int, int, str]) -> ctypes.c_long:
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
def keyctl_set_timeout(key: [key_serial_t, int],
                       timeout: [ctypes.c_uint, int]) -> ctypes.c_long:
    """Set the timeout on a key.
                 
    This is a wrapper for the following function:

        extern long keyctl_set_timeout(key_serial_t key, unsigned timeout);
    """
    return keyutils.keyctl_set_timeout(key, timeout)


@error_checked
def keyctl_assume_authority(key: [key_serial_t, int]) -> ctypes.c_long:
    """Assume the authority granted to instantiate a key.

    This is a wrapper for the following function:

        extern long keyctl_assume_authority(key_serial_t key);

    """
    return keyutils.keyctl_assume_authority(key)

@error_checked
def keyctl_get_security_context(key: [key_serial_t, int]) -> bytes:
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
def keyctl_invaldate(key: [key_serial_t, int]) -> ctypes.c_long:
    """Invalidate this key.

    This is a wrapper for the following function:

        extern long keyctl_invalidate(key_serial_t id);
    """
    return keyutils.keyctl_invalidate(key)

#extern long keyctl_get_persistent(uid_t uid, key_serial_t id);


#------------------------------------------------------------------------------
# keyctl calls
#------------------------------------------------------------------------------

@error_checked
@input_validated
def get_keyring(key: [key_serial_t, int],
                 create: [bool, int] = False) -> key_serial_t:
    """Get keyring by ID.
    
    This is a wrapper for the following function:
       
	key_serial_t keyctl(KEYCTL_GET_KEYRING_ID, key_serial_t id,
			    int create);
    """
    return keyutils.keyctl(KEYCTL_GET_KEYRING_ID, key, create)


@error_checked
@input_validated
def join_session_keyring(name: [bytes, None] = None) -> key_serial_t:
    """Join a session keyring by name, or make an anonymous one.

    If no args are passed in or name is None, an anonymous keyring is
    created attached to the process as its session keyring,
    displacing the old session keyring.

    This is a wrapper for the following function:

	key_serial_t keyctl(KEYCTL_JOIN_SESSION_KEYRING, const char *name);

    """
    return keyutils.keyctl(KEYCTL_JOIN_SESSION_KEYRING, name)


@error_checked
@input_validated
def update(key: [key_serial_t, int], payload: [bytes]):
    """Updated the payload for a key by ID.
    
    This is a wrapper for the following function:

    	long keyctl(KEYCTL_UPDATE, key_serial_t key, const void *payload,
		    size_t plen);
    """
    return keyutils.keyctl(KEYCTL_UPDATE, key, payload,
		           len(payload));

@error_checked
@input_validated
def revoke(key: [key_serial_t, int]):
    """Make the key unavailable for further operations.

    This is a wrapper for the following function:

	long keyctl(KEYCTL_REVOKE, key_serial_t key);
    """
    return keyutils.keyctl(KEYCTL_REVOKE, key)


@error_checked
@input_validated
def chown(key: [key_serial_t, int], uid: [uid_t], gid: [gid_t]) -> ctypes.c_long:
    """Change ownership of a key. 

    Either one of uid or gid can be set to -1 to suppress that change.
    
    This is a wrapper for the following function:
        
        long keyctl(KEYCTL_CHOWN, key_serial_t key, uid_t uid, gid_t gid);
    """
    return keyutils.keyctl(KEYCTL_CHOWN, key, uid, gid)


@error_checked
@input_validated
def chmod(key: [key_serial_t, int], perm: [key_perm_t]) -> ctypes.c_long:
    """Change the permissions of a key.
    
    This is a wrapper for the following function:

	long keyctl(KEYCTL_SETPERM, key_serial_t key, key_perm_t perm);
    """
    return keyutils.keyctl(KEYCTL_SETPERM, key, perm)



@input_validated
def describe(key: [key_serial_t, int]) -> bytes:
    """Get a summary of key attributes.

    A successful call will return a bytes of the following format:
    b"<type>;<uid>;<gid>;<perm>;<description>"

    This is a wrapper for the following function:

	long keyctl(KEYCTL_DESCRIBE, key_serial_t key, char *buffer,
		    size_t buflen);
    """
    return keyctl_string_reader(KEYCTL_DESCRIBE, key)


@error_checked
@input_validated
def clear_keyring(keyring: [key_serial_t, int]) -> ctypes.c_long:
    """Clear a keyring by id.

    This is a wrapper for the following function:

    	long keyctl(KEYCTL_CLEAR, key_serial_t keyring);
    """
    return keyutils.keyctl(KEYCTL_CLEAR, keyring)


@error_checked
@input_validated
def link(key: [key_serial_t, int],
          keyring: [key_serial_t, int]) -> ctypes.c_long:

    """Link a key to a keyring.

    This is a wrapper for the following function:

	long keyctl(KEYCTL_LINK, key_serial_t keyring, key_serial_t key);
    """
    return keyutils.keyctl(KEYCTL_LINK, keyring, key)


@error_checked
@input_validated
def unlink(key: [key_serial_t, int],
          keyring: [key_serial_t, int]) -> ctypes.c_long:
    """Remove a key from a keyring given permission to modify the keyring.

    This is a wrapper for the following function:

	long keyctl(KEYCTL_UNLINK, key_serial_t keyring, key_serial_t key);
    """
    return keyutils.keyctl(KEYCTL_UNLINK, keyring, key);


@error_checked
@input_validated
def search_keytree(src_keyring: [key_serial_t, int],
                    key_type: [bytes],
                    description: [bytes],
                    dest_keyring: [key_serial_t, int]) -> key_serial_t:
    """Search src_keyring tree for a key and add it to the dest_keyring:

    This is a wrapper for the following function:

	key_serial_t keyctl(KEYCTL_SEARCH, key_serial_t keyring,
			    const char *type, const char *description,
			    key_serial_t dest_keyring);
    """
    return keyutils.keyctl(KEYCTL_SEARCH,
                           src_keyring,
                           key_type,
                           description,
                           dest_keyring)


@input_validated
def read(key: [key_serial_t, int]) -> bytes:
    """Return the payload for a key. 

    Get the key payload for a given key id. In Python this is
    impossible to securely erase. Do not read highly sensitive keys
    using this method.

    This is a wrapper for the following function:

	long keyctl(KEYCTL_READ, key_serial_t keyring, char *buffer,
		    size_t buflen);
    """
    return keyctl_string_reader(KEYCTL_READ, key)


@error_checked
@input_validated
def instantiate(key: [key_serial_t, int],
                 payload: [bytes],
                 keyring: [key_serial_t, int]) -> ctypes.c_long:
    """Instantiate a partially constructed key.

    Assign the value payload to the key in keyring.
    
    This is a wrapper for the following function:

	long keyctl(KEYCTL_INSTANTIATE, key_serial_t key,
		    const void *payload, size_t plen,
		    key_serial_t keyring);
    """
    return keyutils.keyctl(KEYCTL_INSTANTIATE,
                           key, payload, len(payload), keyring)

#@error_checked
#@input_validated
def instantiate_iov(*args, **kwargs):
    """NOT IMPLEMENTED.

    Instantiate a partially constructed key. Assign the value payload
    to the key in keyring.
    
    This is a wrapper for the following function:
    
	long keyctl(KEYCTL_INSTANTIATE_IOV, key_serial_t key,
		    const struct iovec *payload_iov, unsigned ioc,
		    key_serial_t keyring);
    """
    raise NotImplemented()


@error_checked
@input_validated
def negate(key: [key_serial_t, int],
            timeout: [ctypes.c_uint, int],
            keyring: [key_serial_t, int, None] = None ) -> ctypes.c_long:
    """Negate the initialization of a key.

    If a keyring is specified and not None the key will also be linked
    into that keyring given proper permissions. Searches for this key
    will return "No such key" (ENOKEY) until the timeout expires.

    This is a wrapper for the following function:
    
	long keyctl(KEYCTL_NEGATE, key_serial_t key,
		    unsigned timeout, key_serial_t keyring);

    """
    return keyutils.keyctl(KEYCTL_NEGATE, key, timeout, keyring)


def reject(key: [key_serial_t, int],
            timeout: [ctypes.c_uint, int],
            error: [ctypes.c_uint, int],
            keyring: [key_serial_t, int, None] = None ) -> ctypes.c_long:
    """Reject the initialization of a key.

    If a keyring is specified and not None the key will also be linked
    into that keyring given proper permissions. Searches for this key
    will return the error specified by "error" until the timeout expires.

    This is a wrapper for the following function:
    
	long keyctl(KEYCTL_REJECT, key_serial_t key,
		    unsigned timeout, unsigned error, key_serial_t keyring);

    """
    return keyutils.keyctl(KEYCTL_REJECT, key, timeout, error, keyring)

    
        
@error_checked
@input_validated
def set_req_keyring(reqkey_defl: [ctypes.c_int, int]) -> ctypes.c_long:
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
       
                     
	long keyctl(KEYCTL_SET_REQKEY_KEYRING, int reqkey_defl);
    """
    return keyutils.keyctl(KEYCTL_SET_REQKEY_KEYRING, reqkey_defl)


def get_default_req_keyring(): #!!fix!! this should resolve the
                                #keyring from the def list above
    return set_req_keyring(-1)


@error_checked
@input_validated
def set_timeout(key: [key_serial_t, int],
                 timeout: [ctypes.c_uint, int]) -> ctypes.c_long:
    """Set the timeout on a key.
                 
    This is a wrapper for the following function:

	long keyctl(KEYCTL_SET_TIMEOUT, key_serial_t key, unsigned timeout);
    """
    return keyutils.keyctl(KEYCTL_SET_TIMEOUT, key, timeout);


@error_checked
@input_validated
def assume_authority(key: [key_serial_t, int]) -> ctypes.c_long:
    """Assume the authority granted to instantiate a key.

    This is a wrapper for the following function:

	long keyctl(KEYCTL_ASSUME_AUTHORITY, key_serial_t key);
    """
    return keyutils.keyctl(KEYCTL_ASSUME_AUTHORITY, key)


@input_validated
def get_security_context(key: [key_serial_t, int]) -> bytes:
    """Get the LSM security context attached to a key.
    
    Get a string represenatiation of the LSM security context.

    This is a wrapper for the following function:

	long keyctl(KEYCTL_GET_SECURITY, key_serial_t key, char *buffer,
		    size_t buflen)
    """
    return keyctl_string_reader(KEYCTL_GET_SECURITY, key)


@error_checked
@input_validated
def session_to_parent():
    """Install the calling process's session keyring on its parent.

    This is a wrapper for the following function:

	long keyctl(KEYCTL_SESSION_TO_PARENT);
    """
    return keyutils.keyctl(KEYCTL_SESSION_TO_PARENT)

@error_checked
@input_validated
def invaldate(key: [key_serial_t, int]) -> ctypes.c_long:
    """Invalidate this key.

    This is a wrapper for the following function:

	long keyctl(KEYCTL_INVALIDATE, key_serial_t key);
    """
    return keyutils.keyctl(KEYCTL_INVALIDATE, key)


