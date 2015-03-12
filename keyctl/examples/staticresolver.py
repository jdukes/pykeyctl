#!/usr/bin/env python
from keyctl import Key

payload = b"static"

def main(uid, gid, key, ringid, size):
    p = (payload * ((size // len(payload)) + 1))[:size]
    k = Key(key)
    k.instantiate(p, ringid)

if __name__ == "__main__":
    uid = int(argv[1])
    gid = int(argv[2])
    key = int(argv[3])
    ringid = int(argv[4])
    size = int(argv[5])
    main(uid, gid, key, ringid, size)
    
