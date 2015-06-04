#!/usr/bin/env python

def chunk(data, size):
    assert (len(data) % size) == 0, \
        "Cannot divide into blocks of size %s" % size
    for i in range(0, len(data), size):
        yield data[i:i + size]

        
