import os
import zipfile
import io

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


import base64

class Signer:

    def __init__(self):
        self.keys_path = "keys"
        self.salt_size = 16

        if not os.path.exists(self.keys_path):
            os.makedirs(self.keys_path)

    def generate_rsa_keys(self, public_key_name: str, private_key_name: str, key_size: int, password: str = "123456") -> bytes:
        """
        Generate RSA keys.

        :param public_key_name: Public key name.
        :type public_key_name: str
        :param private_key_name: Private key name.
        :type private_key_name: str
        :param key_size: Key size in bits.
        :type key_size: int
        :return: ZIP file with the generated keys.
        :rtype: bytes
        """

        private_key_path: str = f"{self.keys_path}/{private_key_name}"
        public_key_path: str = f"{self.keys_path}/{public_key_name}"
        
        os.system(f"openssl genrsa -out {private_key_path} {key_size}")
        os.system(f"openssl rsa -in {private_key_path} -pubout -out {public_key_path}")

        self.lock_file_with_password(f"{private_key_path}", password)

        return self.generate_zip([public_key_path, private_key_path])
    
    def lock_file_with_password(self, file_path: str, password: str) -> str:
        """
        Lock file with the given password.

        :param file_path: File path.
        :type file_path: str
        :param password: Password to encrypt the file.
        :type password: str
        :return: Message with the result of the operation.
        :rtype: str
        """

        salt: bytes = os.urandom(self.salt_size)

        key: bytes = self.derive_password(password, salt)

        fertnet: Fernet = Fernet(key)

        with open(file_path, "rb") as file:
            file_data: bytes = file.read()

        encrypted_data: bytes = fertnet.encrypt(file_data)

        with open(f"{file_path}", "wb") as file:
            file.write(salt + encrypted_data)
    
    def unlock_file_with_password(self, encrypted_file_path: str, password: str, output_file_path: str) -> str:
        """
        Unlock (decrypt) a file using the given password.

        :param encrypted_file_path: Path to the encrypted file.
        :type encrypted_file_path: str
        :param password: Password to decrypt the file.
        :type password: str
        :param output_file_path: Path to save the decrypted file.
        :type output_file_path: str
        :return: Message with the result of the operation.
        :rtype: str
        """

        with open(encrypted_file_path, "rb") as file:
            salt: bytes = file.read(self.salt_size)
            encrypted_data: bytes = file.read()

        key: bytes = self.derive_password(password, salt)

        fernet: Fernet = Fernet(key)

        try:
            decrypted_data: bytes = fernet.decrypt(encrypted_data)

            with open(output_file_path, "wb") as file:
                file.write(decrypted_data)

            return f"Archivo desbloqueado con éxito y guardado en {output_file_path}"
            
        except Exception as e:
            return f"Error al descifrar el archivo: {e}"
    
    def derive_password(self, password: str, salt: bytes) -> bytes:
        """
        Derive a password using a salt.

        :param password: Password to derive.
        :type password: str
        :param salt: Salt to use in the derivation.
        :type salt: bytes
        :return: Derived password.
        :rtype: bytes
        """

        pwd_bytes: bytes = password.encode("utf-8")

        kdf: PBKDF2HMAC = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )

        key: bytes = kdf.derive(pwd_bytes)
        key = base64.urlsafe_b64encode(key)

        return key

    def sign_file(self, file, priv_key_file, password):
        pass

    def verify_signature(self, file, signature_file, pub_key_file):
        pass

    def generate_zip(self, files: list[str]) -> bytes:
        """
        Generate a ZIP file from a list of files.

        :param files: List of files to include in the ZIP file.
        :type files: list[str]
        :return: ZIP file as bytes.
        :rtype: bytes
        """

        zip_buffer: io.BytesIO = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
            for file in files:
                zip_file.write(file)

        return zip_buffer.getvalue()