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
    
