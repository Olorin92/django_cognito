import hashlib
import hmac
import base64
import json
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from urllib.request import urlopen

from django_cognito.authentication.cognito import constants


class PublicKey(object):
    def __init__(self, pubkey):
        self.exponent = self.base64_to_long(pubkey['e'])
        self.modulus = self.base64_to_long(pubkey['n'])
        self.pem = PublicKey.convert(self.exponent, self.modulus)

    def int_array_to_long(self, array):
        return int(''.join(['{:02x}'.format(b) for b in array]), 16)

    def base64_to_long(self, data):
        data = data.encode('ascii')
        _ = base64.urlsafe_b64decode(bytes(data) + b'==')
        return self.int_array_to_long(struct.unpack('%sB' % len(_), _))

    @staticmethod
    def convert(exponent, modulus):
        components = RSAPublicNumbers(exponent, modulus)
        pub = components.public_key(backend=default_backend())
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)


def get_cognito_secret_hash(username: str) -> str:
    message = username + constants.CLIENT_ID
    digest = hmac.new(str(constants.CLIENT_SECRET).encode('UTF-8'), msg=str(message).encode('UTF-8'),
                      digestmod=hashlib.sha256).digest()

    return base64.b64encode(digest).decode()


def get_public_keys():
    public_keys_url = urlopen("https://cognito-idp." + constants.POOL_ID.split("_", 1)[0] + ".amazonaws.com/"
                              + constants.POOL_ID + "/.well-known/jwks.json")
    public_keys = json.loads(public_keys_url.read().decode('utf-8'))

    return public_keys
