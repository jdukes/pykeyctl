#!/usr/bin/env python

class KeyExists(Exception):

    def __init__(self, kid):
        self.kid = kid

    def __str__(self):
        return "Key %d exists and cannot be updated with this call" % self.kid

    
