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

import errno

class ArgumentTypeException(Exception):
    def __init__(self, bad_args_msgs):
        self.bad_args_msgs = bad_args_msgs

    def __str__(self):
        return "Incorrect argument types: %s" % ', '.join(self.bad_args_msgs)

    def __repr__(self):
        return str(self)


class NotImplemented(Exception):

    def __str__(self):
        return "This functionality does not yet exist"

class UnderflowError(Exception):
    def __init__(self, read, available):
        self.read = read
        self.available = available

    def __str__(self):
        return "%s bytes available for read, only got %s" % (self.read,
                                                             self.available)
        
    def __repr__(self):
        return str(self)    
    

class KeyCtlError(Exception):
    messages = {"EEXISTS":"Key exists and cannot be updated with this call",
                "ENOTDIR": "Specified keyring is not a keyring",
                "EACCES": "Invalid permissions",
                "ENOKEY": "No such key",
                "EKEYREVOKED": "Key has been revoked",
                "EKEYEXPIRED": "Key has expired",
                "EOPNOTSUPP": "Operation not supported for this key",
                "ENOMEM": "Insufficient memory to perform this operation",
                "EINVAL": "Invalid value"}

    def __init__(self, err, fn):
        self.err = err
        self.fn = fn

    def __str__(self):
        if self.err in errno.errorcode:
            if errno.errorcode[self.err] in self.messages:
                msg = self.messages[errno.errorcode[self.err]]
            else:
                msg = errno.errorcode[self.err]
        else:
            msg = "Unknown error %d from %s" % (self.err, self.fn.__name__)
        return msg


