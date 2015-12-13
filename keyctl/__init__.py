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
        self._as_parameter_ = self.id  # this defines how it's passed
                                       # to ctypes functions

    def __repr__(self):
        return "<%s(%d)>" % (self.__class__.__name__, self.id)

    def __del__(self):
        keyctl_unlink(self.id)

    @classmethod
    def request(cls, descrip, callout_info, key_type=b"user", dest_keyring=-4):
        #this sucks, do this in a better way
        if type(descrip) != bytes:
            descrip = descrip.encode('utf8')
        if type(callout_info) != bytes:
            callout_info = callout_info.encode('utf8')
        if type(key_type) != bytes:
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
    def props(self):
        if self.id:
            descrip = keyctl_describe(self.id).decode('utf8')
            return { k:v for k,v in zip(("type",
                                         "uid",
                                         "gid",
                                         "perm",
                                         "description"),
                                        descrip.split(";"))}
        else:
            return None  # we should raise an exception here

    @property
    def descrip(self):
        return self.props["description"]

    @property
    def type(self):
        return self.props["type"]
    
    @property
    def uid(self):
        return int(self.props["uid"])

    @uid.setter
    def uid(self, val):
        keyctl_chown(self.id, val, 0)
        #there's a better way to do this... 

    @property
    def gid(self):
        return int(self.props["gid"])

    @gid.setter
    def gid(self, val):
        keyctl_chown(self.id, 0, val)

    @property
    def perm(self):
        return self.props["perm"]

    #add perm setter

    def read(self):
        self._keybytes = keyctl_read(self.id)
        return self._keybytes

    @property
    def keyring(self):
        self.ringid = keyctl_get_keyring(self.id)
        return Keyring(self.ringid)
    
    def instantiate(self, payload, ringid):
        keyctl_assume_authority(self.id)
        keyctl_instantiate(self.id, payload, ringid)

    
class Keyring(Key):

    def add_key(self, descrip, payload, key_type="user"):
        if type(descrip) == str:
            descrip = descrip.encode('utf8')
        if type(payload) == str:
             payload = payload.encode('utf8')
        if type(key_type) == str:
             key_type = key_type.encode('utf8')
        key = add_key(descrip, payload, key_type, self.id)
        return cls(key)
    
    
    @classmethod
    def tree(cls, start_keyring=-3):
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

                     

__all__ = [Key, Keyring]
