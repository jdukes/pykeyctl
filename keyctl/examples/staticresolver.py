#!/usr/bin/env python
from sys import argv
from keyctl import Key

payload = b"static"

def main():
    uid = int(argv[1])
    gid = int(argv[2])
    key = int(argv[3])
    ringid = int(argv[4])
    size = int(argv[5])
    if size > 1024:
        exit(1)
    p = (payload * ((size // len(payload)) + 1))[:size]
    k = Key(key)
    k.instantiate(p, ringid)

if __name__ == "__main__":
    main()
    
