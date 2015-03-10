#!/usr/bin/env python

class ArgumentTypeException(Exception):
    def __init__(self, bad_args):
        self.bad_args = bad_args

    def __str__(self):
        return "Incorrect argument types: %s" % ', '.join(self.bad_args)

    def __repr__(self):
        return str(self)
    
        
    
class KeyExists(Exception):

    def __init__(self, kid):
        self.kid = kid

    def __str__(self):
        return "Key %d exists and cannot be updated with this call" % self.kid


