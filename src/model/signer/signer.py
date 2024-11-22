import os

class Signer:

    def __init__(self):
        self.private_key: str = ""
        self.public_key: str = ""

    def generate_rsa_keys(self, public_key_name: str, private_key_name: str, key_size: int) -> str:
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

        os.system(f"openssl genrsa -out {private_key_name} {key_size}")
        os.system(f"openssl rsa -in {private_key_name} -pubout -out {public_key_name}")

        return f"Se han generado las llaves {public_key_name} y {private_key_name} de tamaño {key_size} bits."
    
    def sign_file(self, file, priv_key_file, password):
        pass

    def verify_signature(self, file, signature_file, pub_key_file):
        pass