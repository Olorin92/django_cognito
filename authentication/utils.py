import hashlib
import hmac
import base64
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from authentication.cognito.base import client_secret, client_id


class PublicKey(object):
    def __init__(self, pubkey):
        self.exponent = self.base64_to_long(pubkey['e'])
        self.modulus = self.base64_to_long(pubkey['n'])
        self.pem = self.convert(self.exponent, self.modulus)

    def int_array_to_long(self, array):
        return int(''.join(['{:02x}'.format(b) for b in array]), 16)

    def base64_to_long(self, data):
        data = data.encode('ascii')
        _ = base64.urlsafe_b64decode(bytes(data) + b'==')
        return self.int_array_to_long(struct.unpack('%sB' % len(_), _))

    def convert(self, exponent, modulus):
        components = RSAPublicNumbers(exponent, modulus)
        pub = components.public_key(backend=default_backend())
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)


@staticmethod
def get_cognito_secret_hash(username: str) -> str:
    message = username + client_id
    digest = hmac.new(str(client_secret).encode('UTF-8'), msg=str(message).encode('UTF-8'),
                      digestmod=hashlib.sha256).digest()

    return base64.b64encode(digest).decode()
