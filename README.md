# Signer and Sign Verifier

## Author

- Yuluka Gigante Muriel


## Overview

This repository provides an implementation of a digital signature application, enabling secure file signing and signature verification using RSA cryptography. It is designed to offer both functionality and flexibility, catering to different user needs.

**Key features:**

1. **_RSA Key Generation:_** Create secure RSA key pairs for signing, encryption, and decryption.
2. **_Private Key Protection:_** Encrypt (lock) the private key with a password for enhanced security.
3. **_Private Key Access:_** Decrypt (unlock) the locked private key using the correct password.
4. **_File Signing:_** Generate digital signatures for files using your private key.
5. **_Signature Verification:_** Validate file signatures with the corresponding public key.

Keys can be generated in two ways: 1) using OpenSSL commands, or 2) using a manual implementation of the RSA algorithm.



