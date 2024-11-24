import subprocess
from subprocess import CompletedProcess
import os
import shutil
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

    def generate_rsa_keys(
        self, public_key_name: str, private_key_name: str, key_size: int, password: str
    ) -> bytes:
        """
        Generate RSA keys.

        :param public_key_name: Public key name.
        :type public_key_name: str
        :param private_key_name: Private key name.
        :type private_key_name: str
        :param key_size: Key size in bits.
        :type key_size: int
        :param password: Password to protect the private key.
        :type password: str
        :return: ZIP file with the generated keys.
        :rtype: bytes
        """

        os.makedirs(self.keys_path, exist_ok=True)

        private_key_path: str = f"{self.keys_path}/{private_key_name}"
        public_key_path: str = f"{self.keys_path}/{public_key_name}"

        os.system(f"openssl genrsa -out {private_key_path} {key_size}")
        os.system(f"openssl rsa -in {private_key_path} -pubout -out {public_key_path}")

        with open(f"{private_key_path}", "rb") as file:
            private_key_data: bytes = file.read()

        with open(f"{public_key_path}", "rb") as file:
            public_key_data: bytes = file.read()

        encrypted_key: bytes = self.lock_file_with_password(private_key_data, password)

        shutil.rmtree(self.keys_path)

        return self.generate_zip(
            [(public_key_name, public_key_data), (private_key_name, encrypted_key)]
        )

    def lock_file_with_password(self, file: bytes, password: str) -> bytes:
        """
        Lock file with the given password.

        :param file: File to encrypt.
        :type file: bytes
        :param password: Password to encrypt the file.
        :type password: str
        :return: Encrypted file data in bytes.
        :rtype: bytes
        """

        salt: bytes = os.urandom(self.salt_size)

        key: bytes = self.derive_password(password, salt)

        fertnet: Fernet = Fernet(key)

        encrypted_data: bytes = fertnet.encrypt(file)

        return salt + encrypted_data

    def unlock_file_with_password(self, encrypted_data: bytes, password: str) -> bytes:
        """
        Unlock (decrypt) a file using the given password.

        :param encrypted_data: Encrypted file data in bytes.
        :type encrypted_data: bytes
        :param password: Password to decrypt the file.
        :type password: str
        :return: Decrypted file data in bytes.
        :rtype: bytes
        """

        salt: bytes = encrypted_data[: self.salt_size]
        encrypted_content: bytes = encrypted_data[self.salt_size :]

        key: bytes = self.derive_password(password, salt)

        fernet: Fernet = Fernet(key)

        try:
            decrypted_data: bytes = fernet.decrypt(encrypted_content)

            return decrypted_data

        except Exception as e:
            raise Exception("Contraseña incorrecta")

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
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000
        )

        key: bytes = kdf.derive(pwd_bytes)
        key = base64.urlsafe_b64encode(key)

        return key

    def sign_file(
        self,
        file_name: str,
        file_to_sign: bytes,
        priv_key_file: bytes,
        password: str,
        sha_algorithm: str = "sha256",
    ) -> bytes:
        """
        Sign a file using a private key.

        :param file_name: Name of the file to sign.
        :type file_name: str
        :param file_to_sign: File to sign.
        :type file_to_sign: bytes
        :param priv_key_file: Private key file.
        :type priv_key_file: bytes
        :param password: Password to unlock the private key.
        :type password: str
        :param sha_algorithm: SHA algorithm to use. Default is "sha256".
        :type sha_algorithm: str
        :return: Signature of the file.
        :rtype: bytes
        """

        os.makedirs(self.keys_path, exist_ok=True)

        priv_key_data: bytes = self.unlock_file_with_password(priv_key_file, password)

        temporal_key_path: str = f"{self.keys_path}/temp_key.pem"
        temporal_file_to_sign_path: str = f"{self.keys_path}/{file_name}"

        with open(temporal_key_path, "wb") as file:
            file.write(priv_key_data)

        with open(temporal_file_to_sign_path, "wb") as file:
            file.write(file_to_sign)

        os.system(
            f"openssl dgst -{sha_algorithm} -sign {temporal_key_path} -out {self.keys_path}/signature.bin {temporal_file_to_sign_path}"
        )

        with open(f"{self.keys_path}/signature.bin", "rb") as file:
            signature: bytes = file.read()

        shutil.rmtree(self.keys_path)

        return signature

    def verify_signature(
        self,
        file_name: str,
        signed_file: bytes,
        signature_file: bytes,
        pub_key_file: bytes,
        sha_algorithm: str = "sha256",
    ) -> bool:
        """
        Verify the signature of a file.

        :param file_name: Name of the file to verify.
        :type file_name: str
        :param signed_file: File to verify.
        :type signed_file: bytes
        :param signature_file: Signature of the file.
        :type signature_file: bytes
        :param pub_key_file: Public key file.
        :type pub_key_file: bytes
        :param sha_algorithm: SHA algorithm to use. Must be the same which was used when signing the file.Default is "sha256".
        :type sha_algorithm: str
        :return: True if the signature is valid, False otherwise.
        :rtype: bool
        """
        os.makedirs(self.keys_path, exist_ok=True)

        temporal_key_path: str = f"{self.keys_path}/temp_key.pem"
        temporal_signature_path: str = f"{self.keys_path}/signature.bin"
        temporal_signed_file_path: str = f"{self.keys_path}/{file_name}"

        with open(temporal_key_path, "wb") as file:
            file.write(pub_key_file)

        with open(temporal_signature_path, "wb") as file:
            file.write(signature_file)

        with open(temporal_signed_file_path, "wb") as file:
            file.write(signed_file)

        try:
            cmdlt_result: CompletedProcess[str] = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    f"-{sha_algorithm}",
                    "-verify",
                    temporal_key_path,
                    "-signature",
                    temporal_signature_path,
                    temporal_signed_file_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            return "Verified OK" in cmdlt_result.stdout

        finally:
            shutil.rmtree(self.keys_path)

    def generate_zip(self, files: list[tuple[str, bytes]]) -> bytes:
        """
        Generate a ZIP file from a list of file contents in bytes.

        :param files: List of tuples with file names and their corresponding content in bytes.
                    Example: [("file1.txt", b"content1"), ("file2.txt", b"content2")]
        :type files: list[tuple[str, bytes]]
        :return: ZIP file as bytes.
        :rtype: bytes
        """

        zip_buffer: io.BytesIO = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for file_name, file_content in files:
                zip_file.writestr(file_name, file_content)

        zip_buffer.seek(0)

        return zip_buffer.getvalue()
