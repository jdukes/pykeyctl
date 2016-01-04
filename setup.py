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

from setuptools import setup, find_packages
from datetime import datetime #for version string
import os
import sys
try:
    import keyctl
except ImportError:
    keyctl = type('placeholder',
                  (object,),
                  dict(__doc__="IMPORT FAILED PLACEHOLDER"))


now = datetime.now()
version="%s.%s.0a1" % (now.year, now.month) # PEP440 compliant

setup(name="keyctl",
      version=version,
      description="A python wrapper around keyctl. This is currently alpha",
      url="https://github.com/jdukes/pykeyctl",
      author="Josh Dukes",
      author_email="hex@neg9.org",
      license="Apache-2.0",
      install_requires=["decorator"],
      entry_points = {
          'console_scripts':[
              'staticresolver=keyctl.examples.staticresolver:main',
              'storedresolver=keyctl.examples.storedresolver:main',
              'kmsresolver=keyctl.examples.kmsresolver:main',
          ]
      },
      keywords = "key management, keyctl",
      long_description=keyctl.__doc__,
      packages=find_packages())

