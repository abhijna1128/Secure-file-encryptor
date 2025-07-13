# aes_utils.py
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

backend = default_backend()

def derive_key(password: str, salt: bytes, iterations=100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return kdf.derive(password.encode())

def pad_data(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt_file(file_path: str, password: str) -> str:
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padded = pad_data(data)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    encrypted = salt + iv + ciphertext

    out_path = os.path.join("output", os.path.basename(file_path) + ".aes")
    os.makedirs("output", exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(encrypted)

    return out_path

def decrypt_file(file_path: str, password: str) -> str:
    with open(file_path, 'rb') as f:
        encrypted = f.read()

    salt = encrypted[:16]
    iv = encrypted[16:32]
    ciphertext = encrypted[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    data = unpad_data(padded)

    out_path = os.path.join("output", os.path.basename(file_path).replace(".aes", ".decrypted"))
    os.makedirs("output", exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(data)

    return out_path
# For direct encryption of bytes (used in steganography and batch encryption)

def encrypt_aes256(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padded = pad_data(data)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return salt + iv + ciphertext  # Return raw encrypted bytes with salt + iv

def decrypt_aes256(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_data(padded)
