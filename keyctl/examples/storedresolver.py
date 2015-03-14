#!/usr/bin/env python

import fcntl
from sys import argv
from os import getuid, setuid, setgid, chown, chmod, fstat, path
from datetime import datetime
from binascii import unhexlify, hexlify

from keyctl import Key


KEYSTOREFILE = "/etc/keystore"
MAX_KEYSIZE = 1024*1024 


###############################################################################


class KeyStoreEntry:

    def __init__(self, uid, key, timestamp):
        self.uid = int(uid)
        self.key = unhexlify(key)
        self.time = datetime.fromtimestamp(int(timestamp))

    def __repr__(self):
        return "<KeyStoreEntry '%s'>" % self

    def __str__(self):
        return "%s %s %s" % (self.uid,
                             hexlify(self.key).decode('ascii'),
                             int(self.time.timestamp()))


class KeyStore:

    def __init__(self, keystore, key_size):
        self.fd = None
        self.entries = []
        self.key_size = int(key_size)
        assert self.key_size <= MAX_KEYSIZE, "Key size too big"
        if not path.exists(keystore):
            with open(keystore,'x') as touch:
                touch.write('')
            chown(keystore, 0, 0)
            chmod(keystore, 0o600)
        self.fd = open(keystore, 'r+')
        s = fstat(self.fd.fileno())
        fcntl.lockf(self.fd, fcntl.LOCK_EX)
        assert (s.st_uid == 0 and
                s.st_gid == 0 and
                not ((s.st_mode & 0o7777) ^ 0o0600)),\
            "Invalid permissions on %s" % keystore
        for line in self.fd:
            uid, key, timestamp = line.split(' ')
            self.entries.append(KeyStoreEntry(uid, key, timestamp))

    def add_key_for(self, uid):
        with open('/dev/urandom','rb') as r:
            key = r.read(16)
        self.entries.append(KeyStoreEntry(uid,
                                          hexlify(key),
                                          datetime.now().timestamp())) #ick
        return key

    def __getitem__(self, uid):
        try:
            return next(e.key for e in self.entries if e.uid == uid
                        and len(e.key) == self.key_size)
        except StopIteration:
            key = self.add_key_for(uid)
            self.write()
            return key

    def write(self):
        self.fd.seek(0)
        self.fd.write("\n".join("%s" % k for k in self.entries)) #writelines?

    def __del__(self):
        if self.fd:
            fcntl.lockf(self.fd, fcntl.LOCK_UN)
            self.fd.close()

        
###############################################################################

def usage():
    print("This program should never be run on it's own and will only work if "
          "run as root. It is intended to be run by the request-key process." )
    print("it's correct usage is:")
    print("%s <key> <uid> <gid>" % argv[0])
    exit(1)


def find_or_make_key(uid, key_size):
    keystore = KeyStore(KEYSTOREFILE, key_size)
    payload = keystore[uid]
    del(keystore)
    return payload
    
    
def main():
    if (getuid() != 0) or (len(argv) < 4):
        usage()
    keyid = argv[1]
    uid = int(argv[2])
    gid = int(argv[3])
    keyring = argv[4]
    key_size = argv[5]

    payload = find_or_make_key(uid, key_size)
    setgid(gid)
    setuid(uid)
    k = Key(keyid)
    k.instantiate(payload, ringid)

if __name__ == "__main__":
    main()
    
