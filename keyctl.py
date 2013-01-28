#!/usr/bin/env python

from ctypes import cdll, create_string_buffer

###############################################################################
# Defines
###############################################################################
keyutils = cdll.LoadLibrary('libkeyutils.so.1') #need to check for
                                                #this or find it

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
        self._buf_len = keyutils.keyctl(KEYCTL_DESCRIBE, self.k_id, None, 0)
        assert self._buf_len > 0, "key not found"

    def __getattr__(self, key):
        if key in self.__dict__:
            return self.__dict__[key]
        elif key in ["type", "uid", "gid", "perm", "description"]:
            self._get_descrip()
        elif key == "value":
            return self.read()
        elif key == "keyring":
            self._get_keyring()
        return self.__getattribute__(key)

    def _get_descrip(self):
        buf = create_string_buffer(self._buf_len)
        keyutils.keyctl(KEYCTL_DESCRIBE, self.k_id, buf, self._buf_len)
        (self.type, self.uid,
         self.gid, self.perm, self.description) = buf.value.split(';')
        del(buf)

    def _get_keyring(self):
        self.keyring = keyutils.keyctl(KEYCTL_GET_KEYRING_ID, self.k_id, 0)

    def get_keyring(self):
        return Key(self.keyring)
        
    def __repr__(self):
        return "<Key %s: '%s'>" % (self.k_id, self.description)

    def update(self, payload):
        plen = len(payload)
        keyutils.keyctl(KEYCTL_UPDATE, self.k_id, payload, plen)
        self._get_value()
        del(payload)

    def revoke(self):
        keyutils.keyctl(KEYCTL_REVOKE, self.k_id)
        for k in self.__dict__.iterkeys():
            self.__dict__[k] = "[deleted]"


    def chown(self, user=-1, group=-1):
        #should only be possible by root
        #keyctl(KEYCTL_CHOWN, key_serial_t key, uid_t uid, gid_t gid)
        pass

    def chmod(self, mode):
        #keyctl(KEYCTL_SETPERM, key_serial_t key, key_perm_t perm);
        pass

    def describ(self):
        # print out <type>;<uid>;<gid>;<perm>;<description>
        # or dump a dict...
        pass
    
    # def clear(self):
    #     #clears a keyring of keys
    #     keyutils.keyctl(KEYCTL_CLEAR, key_serial_t keyring);
    # not sure if this shoule be in the key object....
    
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
        buf = create_string_buffer(_buf_len)
        keyutils.keyctl(KEYCTL_READ, self.k_id, buf, _buf_len);
        value = buf.value
        del(buf) # make sure this is actually freed
        return value

    def set_timeout(self, timout=0):
        keyutils.keyctl(KEYCTL_SET_TIMEOUT, self.k_id, unsigned timeout)

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
    return Key(k_id)


def get_keyring(k_id, create = 0):
    k_id = keyutils.keyctl(KEYCTL_GET_KEYRING_ID, k_id, create)
    if k_id > 0:
        return Key(k_id)
    else:
        raise Exception("shit broke") #need a good exception here

