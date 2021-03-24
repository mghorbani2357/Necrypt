"""Encryption method which contains both RSA and AES encryption using random iv"""
__author__ = 'Mohsen Ghorbani'

from .necrypt import Necrypt
from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
