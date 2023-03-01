#!/usr/bin/env python3

from setuptools import setup

exec(compile(open('updatedns/version.py').read(),'version.py','exec'))

setup(
    name                 = 'updatedns',
    author               = __author__,
    author_email         = __email__,
    version              = __version__,
    license              = __license__,
    url                  = 'https://shaw.cx/updatedns',
    description          = 'Command-Line GIT Server',
    long_description     = open('README.md').read(),
    packages             = setuptools.find_packages(),
    include_package_data = True,
    zip_safe             = False,
    install_requires = [
        'apache-libcloud',
        ],
    entry_points = {
        'console_scripts' : [
            'updatedns = updatedns.updatedns:main',
            ]
        },
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        ]
    )
