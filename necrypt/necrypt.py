from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import hashlib
from Crypto import Random
from Crypto.Signature import pkcs1_15

BLOCK_SIZE = 16


def pad(data):
    return data + (BLOCK_SIZE - len(data) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(data) % BLOCK_SIZE)


def un_pad(data):
    return data[:-ord(data[len(data) - 1:])]


class Necrypt:
    def __init__(self, rsa_key_size=2048, aes_key=''):
        """
            Args:
                rsa_key_size (int): size of the RSA key
                aes_key (str): salt of the AES key
        """
        self._rsa_key = RSA.generate(rsa_key_size)
        self._aes_key = hashlib.sha256(aes_key.encode()).digest()

    @property
    def aes_key(self):
        return self._aes_key

    @aes_key.setter
    def aes_key(self, aes_key):
        self._aes_key = hashlib.sha256(aes_key.encode()).digest()

    @property
    def rsa_key(self):
        return self.rsa_key

    @rsa_key.setter
    def rsa_key(self, rsa_key):
        self._rsa_key = rsa_key

    def encrypt(self, plain):
        plain = pad(b64encode(plain.encode()).decode())
        iv = Random.new().read(AES.block_size)
        aes_cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        aes_b64encoded_cipher = b64encode(iv + aes_cipher.encrypt(plain.encode()))
        rsa_cipher = PKCS1_OAEP.new(self._rsa_key)
        return b64encode(rsa_cipher.encrypt(aes_b64encoded_cipher))

    def decrypt(self, aes_cipher):
        rsa_cipher = PKCS1_OAEP.new(self._rsa_key)
        rsa_decrypted_b64decoded_cipher = b64decode(rsa_cipher.decrypt(b64decode(aes_cipher)))
        iv = rsa_decrypted_b64decoded_cipher[:BLOCK_SIZE]
        aes_cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
        return b64decode(un_pad(aes_cipher.decrypt(rsa_decrypted_b64decoded_cipher[BLOCK_SIZE:]))).decode('utf8')

    def sign(self, plain):
        return pkcs1_15.new(self._rsa_key).sign(SHA256.new(plain.encode()))

    def verify(self, plain, signature):
        return pkcs1_15.new(self._rsa_key).verify(SHA256.new(plain.encode()), signature)

    def encrypt_file(self, input_file_path, output_file_path):
        with open(input_file_path, 'rb') as input_file:
            file_data = input_file.read()

        plain = pad(b64encode(file_data).decode())
        iv = Random.new().read(AES.block_size)
        aes_cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        aes_b64encoded_cipher = b64encode(iv + aes_cipher.encrypt(plain.encode()))
        rsa_cipher = PKCS1_OAEP.new(self._rsa_key)
        with open(output_file_path, 'wb') as output_file:
            output_file.write(rsa_cipher.encrypt(aes_b64encoded_cipher))

    def decrypt_file(self, input_file_path, output_file_path):
        with open(input_file_path, 'rb') as input_file:
            file_data = input_file.read()
        rsa_cipher = PKCS1_OAEP.new(self._rsa_key)
        rsa_decrypted_b64decoded_cipher = b64decode(rsa_cipher.decrypt(file_data))
        iv = rsa_decrypted_b64decoded_cipher[:BLOCK_SIZE]
        aes_cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)

        with open(output_file_path, 'wb') as output_file:
            output_file.write(b64decode(un_pad(aes_cipher.decrypt(rsa_decrypted_b64decoded_cipher[BLOCK_SIZE:]))))

    def export_key(self, key_file_path):
        with open(key_file_path, 'wb') as key_file:
            rsa_key = pad(self._rsa_key.export_key('PEM').decode()).encode()
            iv = Random.new().read(AES.block_size)
            aes_cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            key_file.write(iv + aes_cipher.encrypt(rsa_key))

    def import_key(self, key_file_path, aes_key=''):
        self._aes_key = hashlib.sha256(aes_key.encode()).digest()
        with open(key_file_path, 'rb') as key_file:
            key = key_file.read()
            iv = key[:BLOCK_SIZE]
            aes_cipher = AES.new(self._aes_key, AES.MODE_CBC, iv)
            self._rsa_key = RSA.import_key(un_pad(aes_cipher.decrypt(key[BLOCK_SIZE:])))

    def fingerprint(self):
        pass
