# -*- coding: UTF-8 -*-
'''
Prerequisits:
Windows: scapy and its dependencies:
@todo: scapy: setup.py install
@todo: pywin32: http://stackoverflow.com/a/2500528/47407 easy_install pysvn.exe
@todo: winpcap: http://www.winpcap.org/ not a Python package, comes with Wireshark
@todo: pypcap: win32 installer
@todo: libdnet: win32 installer


@since: 12.05.2014
@author: nuabaranda@web.de
'''


from setuptools import setup
import codecs
import os
import re


here = os.path.abspath(os.path.dirname(__file__))

# Read the version number from a source file.
# Why read it, and not import?
# see https://groups.google.com/d/topic/pypa-dev/0PkjVpcxTzQ/discussion
def find_version(*file_paths):
    # Open in Latin-1 so that we avoid encoding errors.
    # Use codecs.open for Python 2 compatibility
    with codecs.open(os.path.join(here, *file_paths), 'r', 'latin1') as f:
        version_file = f.read()

    # The version line must have the form
    # __version__ = 'ver'
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


setup(
  name='scapy_bacnet',
  packages=['scapy_bacnet'],
  version=find_version('scapy_bacnet', '__init__.py'),
  description='A BACnet layer for Scapy',
  author='desolat',
  author_email='nuabaranda@web.de',
  license='',
  url='https://github.com/desolat/scapy-bacnet',
  download_url='https://github.com/desolat/scapy-bacnet/archive/master.zip',
  keywords=['scapy', 'bacnet'],
  classifiers=[],
  # @todo: how to distiquish between Linux and Win installation?
  install_requires=[
                   # @todo: not maintained on pypi, how can I provide references to (Windows) installers?
#                    'scapy',
#                    'pywin32',
#                    'pcap',
#                    'dnet',
                    'pyreadline'
                   ],

)

