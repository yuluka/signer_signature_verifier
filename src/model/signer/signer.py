import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import base64

class Signer:

    def __init__(self):
        self.keys_path = "keys"

        if not os.path.exists(self.keys_path):
            os.makedirs(self.keys_path)

    def generate_rsa_keys(self, public_key_name: str, private_key_name: str, key_size: int, password: str = "123456") -> str:
        """
        Generate RSA keys.

        :param public_key_name: Public key name.
        :type public_key_name: str
        :param private_key_name: Private key name.
        :type private_key_name: str
        :param key_size: Key size in bits.
        :type key_size: int
        :return: str: Message with the result of the operation.
        :rtype: str
        """

        os.system(f"openssl genrsa -out {self.keys_path}/{private_key_name} {key_size}")
        os.system(f"openssl rsa -in {self.keys_path}/{private_key_name} -pubout -out {self.keys_path}/{public_key_name}")

        self.lock_file_with_password(f"{self.keys_path}/{private_key_name}", password)

        return f"Se han generado las llaves {public_key_name} y {private_key_name} de tamaño {key_size} bits."
    
    def lock_file_with_password(self, file_path: str, password: str) -> str:
        """
        Lock file with the given password.

        :param file_path: File path.
        :type file_path: str
        :param password: Password to encrypt the file.
        :type password: str
        :return: str: Message with the result of the operation.
        :rtype: str
        """

        print("Locking file...")

        pwd_bytes: bytes = password.encode("utf-8")

        salt: bytes = os.urandom(16)

        kdf: PBKDF2HMAC = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )

        key: bytes = kdf.derive(pwd_bytes)
        key = base64.urlsafe_b64encode(key)

        fertnet: Fernet = Fernet(key)

        with open(file_path, "rb") as file:
            file_data: bytes = file.read()

        encrypted_data: bytes = fertnet.encrypt(file_data)

        with open(f"{file_path}", "wb") as file:
            file.write(encrypted_data)
    
    def sign_file(self, file, priv_key_file, password):
        pass

    def verify_signature(self, file, signature_file, pub_key_file):
        pass