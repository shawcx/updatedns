#!/usr/bin/env python3

import setuptools

exec(compile(open('updatedns/version.py').read(),'version.py','exec'))

setuptools.setup(
    name = 'updatedns',
    author       = __author__,
    author_email = __email__,
    version      = __version__,
    license      = __license__,
    url = 'https://shaw.cx/updatedns',
    description = 'Command-Line Cloud DNS utility',
    long_description = open('README.md').read(),
    long_description_content_type = 'text/markdown',
    packages = setuptools.find_packages(),
    include_package_data = True,
    zip_safe = False,
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
