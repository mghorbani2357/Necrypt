from unittest import TestCase
from necrypt.necrypt import Necrypt


class TestNecrypt(TestCase):
    def test_unique_encryption(self):
        n = Necrypt(1024)
        plain = 'Text'
        self.assertNotEqual(n.encrypt(plain), n.encrypt(plain))

    def test_encrypt_decrypt(self):
        n = Necrypt(1024)
        plain = 'Text'
        self.assertEqual(plain, n.decrypt(n.encrypt(plain)))

    def test_sign_verify(self):
        n = Necrypt(1024)
        plain = 'Text'

        signature = n.sign(plain + 's')

        with self.assertRaises(ValueError) as context:
            n.verify(plain, signature)

        self.assertEqual('Invalid signature', str(context.exception))

