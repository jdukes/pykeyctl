#!/usr/bin/env python

from exceptions import *
from _native.functionwrappers import *

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
    def __init__(self, key):
        
        self.id = key

class KeyRing(Key):
    pass

#list keyrings
#instantiate keyring
# self._as_parameter_ = kid <- allows to be passed in to ctypes
#instantiate key

#__all__ = [Key, Keyring, get_key, get_keyrings]
