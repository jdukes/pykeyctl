#!/usr/bin/env python
from setuptools import setup, find_packages
from datetime import datetime #for version string
import os
import sys
# sys.path.insert(0,os.path.join(os.path.dirname(__file__),'keyctl'))
# import keyctl

now = datetime.now()


version="%s.%s.0a0" % (now.year, now.month) # PEP440 compliant

setup(name="keyctl",
      version=version,
      description="A python wrapper around keyctl. This is currently alpha",
      url="https://github.com/jdukes/pykeyctl",
      author="Josh Dukes",
      author_email="hex@neg9.org",
      license="GPL",
      install_requires=["decorator"],
      entry_points = {
          'console_scripts':[
              'staticresolver=keyctl.examples.staticresolver:main',
          ]
      },
      keywords = "key management, keyctl",
      #long_description=keyctl.__doc__,
      packages=find_packages())

