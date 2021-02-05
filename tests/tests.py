from unittest import TestCase
from necrypt.necrypt import Necrypt
import os


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

    def test_file_encryption_decryption(self):
        plain_file_data = b'plain'
        with open('plain_file', 'wb') as plain_file:
            plain_file.write(plain_file_data)

        n = Necrypt(1024)

        n.encrypt_file('plain_file', 'cipher_file')

        n.decrypt_file('cipher_file', 'decrypted_file')

        with open('decrypted_file') as decrypted_file:
            decrypted_file_data = decrypted_file.read()

        files_to_remove = ['plain_file', 'cipher_file', 'decrypted_file']
        for filename in files_to_remove:
            if os.path.isfile(filename):
                os.remove(filename)

        self.assertEquals(plain_file_data, decrypted_file_data.encode())

    def test_import_export_key(self):
        n = Necrypt(1024)

        n.export_key('key_file')

        n.import_key('key_file')

        print(n.decrypt(n.encrypt('s')))
