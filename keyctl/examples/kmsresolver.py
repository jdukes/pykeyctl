#!/usr/bin/env python
# Copyright 2016 Josh Dukes
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function
from sys import argv
from os import setuid, setgid, getuid

def usage():
    print("This program should never be run on it's own and will only work if "
          "run as root. It is intended to be run by the request-key process." )
    print("it's correct usage is:")
    print("%s <key> <uid> <gid> <keyring> <base64_encoded_encrypted_key>" % argv[0])
    exit(1)

def decrypt_key(b64_key):
    from base64 import b64decode
    import boto
    key_data = b64decode(b64_key)
    print("key data type %s, data: %s" % (type(key_data), key_data))
    kms = boto.connect_kms()
    decrypted_blob = kms.decrypt(key_data)
    return bytes(decrypted_blob["Plaintext"])

def main():
    if (getuid() != 0) or (len(argv) < 5):
        usage()
    uid = int(argv[2])
    gid = int(argv[3])
    setgid(gid)
    setuid(uid)
    keyid = int(argv[1])
    keyring = int(argv[4])

    from keyctl import Key #only import other deps after we've dropped privs
    b64_key = argv[5]
    print(type(b64_key))
    payload = decrypt_key(b64_key)
    k = Key(keyid)
    k.instantiate(payload, keyring)

    
if __name__ == "__main__":
    main()
