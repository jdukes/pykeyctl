#!/usr/bin/env python

from .helpers import chunk
from ._exceptions import *
from ._native import *

# Each key has a number of attributes:
# 	- A serial number.
# 	- A type.
# 	- A description (for matching a key in a search).
# 	- Access control information.
# 	- An expiry time.
# 	- A payload.
# 	- State.

class Key(object):
    """This is used to interact with keys in keyctl.
    
    Each key has a number of attributes:
     	- A serial number.
 	- A type.
 	- A description (for matching a key in a search).
 	- Access control information.
 	- An expiry time.
 	- A payload.
 	- State.

    """
    def __init__(self, id):
        #create metaclass that determines if key or keyring and inits
        #correctly
        self.id = id

    def __repr__(self):
        return "<%s(%d)>" % (self.__class__.__name__, self.id)

    @classmethod
    def request(cls, descrip, callout_info, key_type=b"user", dest_keyring=-4):
        #this sucks, do this in a better way
        if type(descrip) == "str":
            descrip = descrip.encode('utf8')
        if type(callout_info) == "str":
            callout_info = callout_info.encode('utf8')
        if type(key_type) == "str":
            key_type = key_type.encode('utf8')
        key = request_key(descrip, callout_info, key_type, dest_keyring)
        return cls(key)

    @classmethod
    def add(cls, descrip, payload, key_type="user", keyring=-4):
        if type(descrip) == str:
            descrip = descrip.encode('utf8')
        if type(payload) == str:
             payload = payload.encode('utf8')
        if type(key_type) == str:
             key_type = key_type.encode('utf8')
        key = add_key(descrip, payload, key_type, keyring)
        return cls(key)

    @property
    def descrip(self):
        if self.id:
            descrip = keyctl_describe(self.id).decode('utf8')
            return { k:v for k,v in zip(("type",
                                         "uid",
                                         "gid",
                                         "perm",
                                         "description"),
                                        descrip.split(";"))}
        else:
            return None

    @property
    def type(self):
        return self.descrip["type"]
    
    @property
    def uid(self):
        return int(self.descrip["uid"])

    @uid.setter
    def uid(self, val):
        keyctl_chown(self.id, val, 0)
        #there's a better way to do this... 

    @property
    def gid(self):
        return int(self.descrip["gid"])

    @gid.setter
    def gid(self, val):
        keyctl_chown(self.id, 0, val)

    @property
    def perm(self):
        return self.descrip["perm"]

    #add perm setter

    def read(self):
        self._keybytes = keyctl_read(self.id)
        return self._keybytes

    @property
    def keyring(self):
        self.ringid = keyutils.keyctl(KEYCTL_GET_KEYRING_ID, self.id, 0)
        return Keyring(self.ringid)
    
    def instantiate(self, payload, ringid):
        keyctl_assume_authority(self.id)
        keyctl_instantiate(self.id, payload, ringid)

    
class Keyring(Key):

    @classmethod
    def show_tree(cls, start_keyring=-3):
        for k in Keyring(start_keyring).children:
            yield k
            if k.type == "keyring":
                yield [i for i in cls.show_tree(k.id)]

    @property
    def children(self):
        ch = []
        for c in chunk(self.read(), 4):
            key = int.from_bytes(c, byteorder="little")
            #fix this stupid
            k = Key(key)
            if Key(key).type == "keyring":
                ch.append(Keyring(key))
            else:
                ch.append(k)
        return ch

    def clear(self):
        keyctl_clear_keyring(self.id)

                     
#list keyrings
#instantiate keyring
# self._as_parameter_ = kid <- allows to be passed in to ctypes
#instantiate key

#__all__ = [Key, Keyring, create_key, get_key, get_keyrings]
__all__ = [Key, Keyring]
