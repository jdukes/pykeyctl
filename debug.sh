#!/bin/bash -vxxx
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

exec 2>&1 > $(dirname $0)/output

DIR=$1
PROG=$2
shift 2

echo `pwd` 
echo $PROG $@

$PROG $@  >> $DIR/output 2>&1
