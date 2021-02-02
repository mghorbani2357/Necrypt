# import pytest

from necrypt.necrypt import Necrypt

n = Necrypt(1024)

plain = 'سasdasdasdلام'

print(n.encrypt(plain))
print(n.encrypt(plain))
c = n.encrypt(plain)

print(n.decrypt(c))
