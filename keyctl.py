#!/usr/bin/env python

import ctypes

###############################################################################
# Defines
###############################################################################
keyutils = ctypes.cdll.LoadLibrary('libkeyutils.so.1') #need to check for
                                                #this or find it
#libc = ctypes.cdll.LoadLibrary("libc.so.6")

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

KEYRING = {"Default": 0,
           "Thread": -1,
           "Process": -2,
           "Session": -3,
           "User": -4,
           "User_session": -5,
           "Group": -6,
           "reqkey_auth_key": -7} #	assumed request_key() authorisation key

KEY_REQKEY_DEFL_NO_CHANGE = -1#	No change
KEY_REQKEY_DEFL_DEFAULT = 0 #	Default[1]
KEY_REQKEY_DEFL_THREAD_KEYRING = 1#	Thread keyring
KEY_REQKEY_DEFL_PROCESS_KEYRING = 2 # Process keyring
KEY_REQKEY_DEFL_SESSION_KEYRING = 3 # Session keyring
KEY_REQKEY_DEFL_USER_KEYRING = 4 # User keyring
KEY_REQKEY_DEFL_USER_SESSION_KEYRING = 5 # User session keyring
KEY_REQKEY_DEFL_GROUP_KEYRING = 6 # Group keyring


###############################################################################
# Classes
###############################################################################


class Key(object):

    def __init__(self, k_id):
        assert type(k_id) == int, "argument must be an integer"
        self.k_id = k_id
        keyutils.keyctl_describe_alloc(self.k_id, );
        self._buf_len = keyutils.keyctl(KEYCTL_DESCRIBE,
                                        self.k_id,
                                        ctypes.c_char_p(),
                                        0)
        assert self._buf_len > 0, "key not found"
        self._get_descrip()

    def __getattr__(self, name): #beware of toctou
        if name in self.__dict__:
            return self.__dict__[name]
        elif name in ["type", "uid", "gid", "perm", "description"]:
            self._get_descrip()
        elif name == "value":
            return self.read() 
        elif name == "keyring":
            self._get_keyring()
        return self.__getattribute__(name)

    def __setattr__(self, name, value):
        if name == "value":
            return self.update(value)
        elif name in ["description", "type"] and name in self.__dict__:
            #this is immutable
            raise Exception("you fucked up")
        elif name in ["uid", "gid"] and name in self.__dict__:
            return self.chown(**{name:value})
        object.__setattr__(self, name, value)

    def _get_descrip(self):
        #user properties
        buf = ctypes.create_string_buffer(self._buf_len) 
        keyutils.keyctl(KEYCTL_DESCRIBE, self.k_id, buf, self._buf_len)
        (self.type, self.uid,
         self.gid, self.perm, self.description) = buf.value.decode().split(';')
        del(buf)

    def _get_keyring(self):
        self.keyring = keyutils.keyctl(KEYCTL_GET_KEYRING_ID, self.k_id, 0)

    def get_keyring(self):
        return Key(self.keyring)
        
    def __repr__(self):
        return "<Key %s: '%s'>" % (self.k_id, self.description)

    def __delete__(self):
        #cleanup allocs
        pass

    def update(self, payload):
        #because payloads can't be safely cleared this library isn't
        #safe to use. Secrets will stay in memory
        plen = len(payload) #this can't be cleared without doing
                            #*really* bad things.
        keyutils.keyctl(KEYCTL_UPDATE, self.k_id, payload, plen)
        ## however this fucking voodoo would work
        p = ctypes.cast(id(payload)+20, ctypes.c_char_p)
        ctypes.memset(p, 0, plen)
        
    def revoke(self):
        keyutils.keyctl(KEYCTL_REVOKE, self.k_id)
        for k in self.__dict__.iterkeys():
            self.__dict__[k] = "[deleted]"

    def chown(self, uid=-1, gid=-1):
        #should only be possible by root
        keyutils.keyctl(KEYCTL_CHOWN, self.k_id, uid, gid)
        #i can haz error handling?
        if uid > 0:
            assert uid == self.uid, \
                   "this is why we can't have nice things"
        if gid > 0:
            assert gid == self.gid, \
                   "now look what you've done"

    def chmod(self, mode):
        #keyctl(KEYCTL_SETPERM, key_serial_t key, key_perm_t perm);
        pass

    def clear(self):
        #might split Key and Keyring out....
        assert self.type == "keyring", "is not of type 'keyring'"
        #clears a keyring of keys
        keyutils.keyctl(KEYCTL_CLEAR, self.k_id);
    
    def link(self, keyring):
        if type(keyring) == type(self):
            kr_id = keyring.kr_id
        else:
            kr_id = keyring
        keyutils.keyctl(KEYCTL_LINK, kr_id, self.k_id)

    def unlink(self, keyring=None):
        keyring = keyring or self.keyring
        keyutils.keyctl(KEYCTL_UNLINK, keyring, self.k_id);

    def read(self):
        #make sure this works with keyrings
        _buf_len = keyutils.keyctl(KEYCTL_READ, self.k_id, None, 0);
        buf = ctypes.create_string_buffer(_buf_len)
        keyutils.keyctl(KEYCTL_READ, self.k_id, buf, _buf_len);
        value = buf.raw
        buf.value = '\0' * len(buf)
        return value

    def set_timeout(self, timout=0):
        keyutils.keyctl(KEYCTL_SET_TIMEOUT, self.k_id, timeout)

    def clear_timout(self):
        self.set_timeout()



###############################################################################
# Helper functions
###############################################################################

def get_key(k_id):
    return Key(k_id)


def find_key(descrip, k_type="user", keyring='User'):
    k_id = keyutils.keyctl(KEYCTL_SEARCH, KEYRING[keyring],
                           k_type, descrip, KEYRING[keyring])
    if k_id > 0:
        return Key(k_id)
    else:
        raise Exception("shit broke") #need a good exception here


def add_key(descrip, payload, type="user", keyring="User"):
    plen = len(payload) #need to figure out how to clear this since
                        #strings are immutable...
    k_id = keyutils.add_key(type, descrip, payload, plen, KEYRING[keyring])
    p = ctypes.cast(id(payload)+20, ctypes.c_char_p)
    ctypes.memset(p, 0, plen)
    return k_id
    #return Key(k_id)


def add_keyring(descrip, keyring="User"):
    return add_key(type="keyring", descrip=descrip, payload=None,
                   plen=0, keyring=KEYRING[keyring])


def get_keyring(k_id, create = 0):
    k_id = keyutils.keyctl(KEYCTL_GET_KEYRING_ID, k_id, create)
    if k_id > 0:
        return Key(k_id)
    else:
        raise Exception("shit broke") #need a good exception here


def request_key(descrip, type="user",
                callout_info=None,
                keyring=KEYRING["User"]):
    k_id = keyutils.request_key(type, descrip, callout_info, keyring);
    if k_id > 0:
        return Key(k_id)
    else:
        raise Exception("shit broke") #need a good exception here
