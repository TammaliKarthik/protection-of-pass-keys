import os
import hashlib
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Directories
BASE_DIR = '/mnt/encryption_app/'
ENCRYPTED_DIR = os.path.join(BASE_DIR, 'encrypted/')
SAMPLE_FILES_DIR = os.path.join(BASE_DIR, 'sample_files/')
KEYS_DIR = os.path.join(BASE_DIR, 'keys/')

# Ensure directories exist
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(SAMPLE_FILES_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# File Paths
SAMPLE_FILE_PATH = os.path.join(SAMPLE_FILES_DIR, 'sample_file.txt')
ENCRYPTED_FILE_PATH = os.path.join(ENCRYPTED_DIR, 'encrypted_file.enc')
KEY_FILE_PATH = os.path.join(KEYS_DIR, 'encrypted_key.key')

# Function to derive key from passphrase
def derive_key(passphrase, salt, length=32):
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    return key

# Function to encrypt a file
def encrypt_file(file_path, passphrase):
    # Generate random key and IV
    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)  # 16 bytes IV for AES

    # Read file content
    with open(file_path, 'rb') as f:
        data = f.read()

    # Pad data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write encrypted file
    with open(ENCRYPTED_FILE_PATH, 'wb') as f:
        f.write(iv + encrypted_data)

    # Encrypt and store the key
    salt = os.urandom(16)
    derived_key = derive_key(passphrase, salt)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(key) + encryptor.finalize()

    with open(KEY_FILE_PATH, 'wb') as f:
        f.write(salt + iv + encrypted_key)

# Main logic
if __name__ == '__main__':
    user_passphrase = input("Enter your passphrase: ")

    # Encrypt the file
    print("Encrypting file...")
    encrypt_file(SAMPLE_FILE_PATH, user_passphrase)
    print(f"File encrypted and stored at {ENCRYPTED_FILE_PATH}")
    print(f"Encrypted key stored at {KEY_FILE_PATH}")
