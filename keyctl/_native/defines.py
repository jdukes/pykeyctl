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

from ctypes import c_int32, c_char_p, c_void_p, POINTER, c_uint32

###############################################################################
# defines
###############################################################################

# keyctl commands 
KEYCTL_GET_KEYRING_ID = 0 # ask for a keyring's ID
KEYCTL_JOIN_SESSION_KEYRING = 1 # join or start named session keyring
KEYCTL_UPDATE = 2 # update a key
KEYCTL_REVOKE = 3 # revoke a key
KEYCTL_CHOWN = 4 # set ownership of a key
KEYCTL_SETPERM = 5 # set perms on a key
KEYCTL_DESCRIBE = 6 # describe a key
KEYCTL_CLEAR = 7 # clear contents of a keyring
KEYCTL_LINK = 8 # link a key into a keyring
KEYCTL_UNLINK = 9 # unlink a key from a keyring
KEYCTL_SEARCH = 10 # search for a key in a keyring
KEYCTL_READ = 11 # read a key or keyring's contents
KEYCTL_INSTANTIATE = 12 # instantiate a partially constructed key
KEYCTL_NEGATE = 13 # negate a partially constructed key
KEYCTL_SET_REQKEY_KEYRING = 14 # set default request-key keyring
KEYCTL_SET_TIMEOUT = 15 # set timeout on a key
KEYCTL_ASSUME_AUTHORITY = 16 # assume authority to instantiate key
KEYCTL_GET_SECURITY = 17 # get key security label
KEYCTL_SESSION_TO_PARENT = 18 # set my session keyring on my parent process
KEYCTL_REJECT = 19 # reject a partially constructed key
KEYCTL_INSTANTIATE_IOV = 20 # instantiate a partially constructed key
KEYCTL_INVALIDATE = 21 # invalidate a key
KEYCTL_GET_PERSISTENT = 22 # get a user's persistent keyring

KEYRING = {"Thread": -1,
           "Process": -2,
           "Session": -3,
           "User": -4,
           "User_session": -5,
           "group": -6,
           "reqkey_auth_key": -7} #	assumed request_key() authorisation key

#reqkey 
KEY_REQKEY_DEFL_NO_CHANGE = -1#	No change
KEY_REQKEY_DEFL_DEFAULT = 0 #	Default[1]
KEY_REQKEY_DEFL_THREAD_KEYRING = 1
KEY_REQKEY_DEFL_PROCESS_KEYRING = 2
KEY_REQKEY_DEFL_SESSION_KEYRING = 3
KEY_REQKEY_DEFL_USER_KEYRING = 4
KEY_REQKEY_DEFL_USER_SESSION_KEYRING = 5
KEY_REQKEY_DEFL_GROUP_KEYRING = 6

# permissions
KEY_POS_VIEW = 0x01000000 #	/* possessor can view a key's attributes */
KEY_POS_READ = 0x02000000 #	/* possessor can read key payload / view keyring */
KEY_POS_WRITE = 0x04000000 #	/* possessor can update key payload / add link to keyring */
KEY_POS_SEARCH = 0x08000000 #	/* possessor can find a key in search / search a keyring */
KEY_POS_LINK = 0x10000000 #	/* possessor can create a link to a key/keyring */
KEY_POS_SETATTR = 0x20000000 #	/* possessor can set key attributes */
KEY_POS_ALL = 0x3f000000 #

KEY_USR_VIEW = 0x00010000 #	/* user permissions... */
KEY_USR_READ = 0x00020000
KEY_USR_WRITE = 0x00040000
KEY_USR_SEARCH = 0x00080000
KEY_USR_LINK = 0x00100000
KEY_USR_SETATTR = 0x00200000
KEY_USR_ALL = 0x003f0000

KEY_GRP_VIEW = 0x00000100 #	/* group permissions... */
KEY_GRP_READ = 0x00000200
KEY_GRP_WRITE = 0x00000400
KEY_GRP_SEARCH = 0x00000800
KEY_GRP_LINK = 0x00001000
KEY_GRP_SETATTR = 0x00002000
KEY_GRP_ALL = 0x00003f00

KEY_OTH_VIEW = 0x00000001 #	/* third party permissions... */
KEY_OTH_READ = 0x00000002
KEY_OTH_WRITE = 0x00000004
KEY_OTH_SEARCH = 0x00000008
KEY_OTH_LINK = 0x00000010
KEY_OTH_SETATTR = 0x00000020
KEY_OTH_ALL = 0x0000003f


###############################################################################
# typedefs
###############################################################################

key_serial_t = c_int32
key_perm_t = c_uint32
gid_t = c_uint32
uid_t = c_uint32
c_char_p_p = POINTER(c_char_p)
c_void_p_p = POINTER(c_void_p)
