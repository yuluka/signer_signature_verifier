import subprocess
from subprocess import CompletedProcess
import os
import shutil
import zipfile
import io

import base64
import hashlib
from pyasn1.type.univ import Sequence, Integer
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.cer import encoder

import random
from sympy import isprime, mod_inverse

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import base64


class Signer:

    def __init__(self, custom_rsa_algorithm: bool = False):
        self.custom_rsa_algorithm = custom_rsa_algorithm
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

        if self.custom_rsa_algorithm:
            return self.generate_rsa_keys_custom_algorithm(
                public_key_name, private_key_name, key_size, password
            )
        else:
            return self.generate_rsa_keys_default(
                public_key_name, private_key_name, key_size, password
            )

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

        if self.custom_rsa_algorithm:
            return self.sign_file_custom_algorithm(
                file_name, file_to_sign, priv_key_file, password, sha_algorithm
            )
        else:
            return self.sign_file_default(
                file_name, file_to_sign, priv_key_file, password, sha_algorithm
            )

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

        if self.custom_rsa_algorithm:
            return self.verify_signature_custom_algorithm(
                file_name, signed_file, signature_file, pub_key_file, sha_algorithm
            )
        else:
            return self.verify_signature_default(
                file_name, signed_file, signature_file, pub_key_file, sha_algorithm
            )

    # ------------ CUSTOM RSA ALGORITHM ------------
    def generate_rsa_keys_custom_algorithm(
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

        # Step 1: Generate two prime numbers p and q
        p: int = self.generate_prime_number(key_size // 2)
        q: int = self.generate_prime_number(key_size // 2)

        # Step 2: Calculate n = p * q
        n: int = p * q

        # Step 3: Calculate phi = (p - 1) * (q - 1)
        phi: int = (p - 1) * (q - 1)

        # Step 4: Find e such that 1 < e < phi and gcd(e, phi) = 1 (e is coprime with phi)
        e: int = 3
        while e < phi and self.gcd(e, phi) != 1:
            e += 2

        # Step 5: Calculate d such that (d * e) * mod(phi) = 1 (d is the modular multiplicative inverse of e)
        d: int = mod_inverse(e, phi)

        public_key: bytes = self.public_key_to_pkcs1(e, n)
        private_key: bytes = self.private_key_to_pkcs1(d, n, e, p, q)

        encrypted_key: bytes = self.lock_file_with_password(private_key, password)

        return self.generate_zip(
            [(public_key_name, public_key), (private_key_name, encrypted_key)]
        )

    def generate_prime_number(self, bits: int) -> int:
        """
        Generate a prime number with the given number of bits.

        :param bits: Number of bits of the prime number.
        :type bits: int
        :return: Prime number.
        :rtype: int
        """

        while True:
            number: int = random.getrandbits(bits)

            if isprime(number):
                return number

    def gcd(self, a: int, b: int) -> int:
        """
        Calculate the Greatest Common Divisor (GCD) of two numbers.

        :param a: First number.
        :type a: int
        :param b: Second number.
        :type b: int
        :return: Greatest common divisor.
        :rtype: int
        """

        while b:
            a, b = b, a % b

        return a

    def private_key_to_pkcs1(self, d: int, n: int, e: int, p: int, q: int) -> bytes:
        """
        Convert a private key to PKCS1 format.

        :param d: Private exponent.
        :type d: int
        :param n: Modulus.
        :type n: int
        :param e: Public exponent.
        :type e: int
        :param p: First prime factor.
        :type p: int
        :param q: Second prime factor.
        :type q: int
        :return: Private key in PKCS1 format.
        :rtype: bytes
        """

        dmp1 = d % (p - 1)
        dmq1 = d % (q - 1)
        iqmp = pow(q, -1, p)

        private_key = Sequence()
        private_key.setComponentByPosition(0, Integer(0))
        private_key.setComponentByPosition(1, Integer(n))
        private_key.setComponentByPosition(2, Integer(e))
        private_key.setComponentByPosition(3, Integer(d))
        private_key.setComponentByPosition(4, Integer(p))
        private_key.setComponentByPosition(5, Integer(q))
        private_key.setComponentByPosition(6, Integer(dmp1))
        private_key.setComponentByPosition(7, Integer(dmq1))
        private_key.setComponentByPosition(8, Integer(iqmp))

        der_encoded = encode(private_key)

        pem_key = base64.encodebytes(der_encoded).decode("utf-8")
        pem_key = (
            f"-----BEGIN RSA PRIVATE KEY-----\n{pem_key}-----END RSA PRIVATE KEY-----\n"
        )

        return pem_key.encode("utf-8")

    def public_key_to_pkcs1(self, e: int, n: int) -> bytes:
        """
        Convert a public key to PKCS1 format.

        :param e: Public exponent.
        :type e: int
        :param n: Modulus.
        :type n: int
        :return: Public key in PKCS1 format.
        :rtype: bytes
        """

        public_key: Sequence = Sequence()
        public_key.setComponentByPosition(0, Integer(n))
        public_key.setComponentByPosition(1, Integer(e))

        der_encoded = encode(public_key)

        pem_key = base64.encodebytes(der_encoded).decode("utf-8")
        pem_key = (
            f"-----BEGIN RSA PUBLIC KEY-----\n{pem_key}-----END RSA PUBLIC KEY-----\n"
        )

        return pem_key.encode("utf-8")

    def sign_file_custom_algorithm(
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

        priv_key_data: bytes = self.unlock_file_with_password(priv_key_file, password)

        d, n = self.extract_private_key_params(priv_key_data)

        hash_file: int = self.generate_hash(file_to_sign, sha_algorithm)
        signature: int = self.sign_hash(hash_file, d, n)

        return signature.to_bytes((signature.bit_length() + 7) // 8, byteorder="big")

    def extract_private_key_params(self, private_key: bytes) -> tuple[int, int]:
        """
        Extract the private key parameters (d, n) from the PKCS#1-encoded key.

        :param private_key: PEM-encoded private key in bytes.
        :type private_key: bytes
        :return: Tuple containing (d, n).
        :rtype: tuple
        """

        private_key_str: str = private_key.decode("utf-8")
        private_key_str = private_key_str.replace("-----BEGIN RSA PRIVATE KEY-----", "")
        private_key_str = private_key_str.replace("-----END RSA PRIVATE KEY-----", "")
        private_key_str = private_key_str.strip()

        der_encoded_key: bytes = base64.b64decode(private_key_str)
        private_key, _ = decode(der_encoded_key, asn1Spec=Sequence())

        n = int(private_key.getComponentByPosition(1))
        e = int(private_key.getComponentByPosition(2))
        d = int(private_key.getComponentByPosition(3))

        return d, n

    def generate_hash(self, file: bytes, sha_algorithm: str = "sha256") -> int:
        """
        Generate the hash of a file. The hash algorithm can be specified. Default is SHA-256.

        :param file: File to hash.
        :type file: bytes
        :param sha_algorithm: SHA algorithm to use. Default is "sha256".
        :type sha_algorithm: str
        :return: Hash of the file.
        :rtype: int
        """

        hash_function = getattr(hashlib, sha_algorithm.lower())()
        hash_function.update(file)

        return int.from_bytes(hash_function.digest(), byteorder="big")

    def sign_hash(self, hash_value: int, d: int, n: int) -> int:
        """
        Sign a hash using the private key.

        :param hash_value: Hash value to sign.
        :type hash_value: int
        :param d: Private exponent.
        :type d: int
        :param n: Modulus.
        :type n: int
        :return: Signature of the hash.
        :rtype: int
        """

        return pow(hash_value, d, n)

    def verify_signature_custom_algorithm(
        self,
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

        pub_key_data: bytes = pub_key_file

        e, n = self.extract_public_key_params(pub_key_data)

        hash_file: int = self.generate_hash(signed_file, sha_algorithm)
        signature: int = int.from_bytes(signature_file, byteorder="big")

        hash_signature: int = pow(signature, e, n)

        return hash_signature == hash_file
    
    def extract_public_key_params(self, public_key: bytes) -> tuple[int, int]:
        """
        Extract the public key parameters (e, n) from the PKCS#1-encoded key.

        :param public_key: PEM-encoded public key in bytes.
        :type public_key: bytes
        :return: Tuple containing (e, n).
        :rtype: tuple
        """

        public_key_str: str = public_key.decode("utf-8")
        public_key_str = public_key_str.replace("-----BEGIN RSA PUBLIC KEY-----", "")
        public_key_str = public_key_str.replace("-----END RSA PUBLIC KEY-----", "")
        public_key_str = public_key_str.strip()

        der_encoded_key: bytes = base64.b64decode(public_key_str)
        public_key, _ = decode(der_encoded_key, asn1Spec=Sequence())

        n = int(public_key.getComponentByPosition(0))
        e = int(public_key.getComponentByPosition(1))

        return e, n

    # ------------ DEFAULT RSA ALGORITHM (OpenSSL) ------------
    def generate_rsa_keys_default(
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

    def sign_file_default(
        self,
        file_name: str,
        file_to_sign: bytes,
        priv_key_file: bytes,
        password: str,
        sha_algorithm: str = "sha256",
    ) -> bytes:
        """
        Sign a file using a private key using the openssl command.

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

    def verify_signature_default(
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
