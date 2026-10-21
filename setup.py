#!/usr/bin/env python3

# Metadata lives in pyproject.toml. This shim stays for stdeb:
#   python3 setup.py --command-packages=stdeb.command bdist_deb
# stdeb can't find the Debian Maintainer or Homepage in pyproject metadata,
# so give it both here.

import setuptools

setuptools.setup(
    url = 'https://shaw.cx/updatedns',
    options = {
        'sdist_dsc' : {'maintainer' : 'Matthew Shaw <mshaw.cx@gmail.com>'},
        },
    )
