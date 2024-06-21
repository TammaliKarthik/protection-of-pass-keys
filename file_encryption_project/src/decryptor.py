import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Directories
BASE_DIR = '/mnt/encryption_app/'
ENCRYPTED_DIR = os.path.join(BASE_DIR, 'encrypted/')
DECRYPTED_DIR = os.path.join(BASE_DIR, 'decrypted/')
KEYS_DIR = os.path.join(BASE_DIR, 'keys/')

# Ensure directories exist
os.makedirs(DECRYPTED_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# File Paths
ENCRYPTED_FILE_PATH = os.path.join(ENCRYPTED_DIR, 'encrypted_file.enc')
DECRYPTED_FILE_PATH = os.path.join(DECRYPTED_DIR, 'decrypted_file.txt')
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

# Function to decrypt a file
def decrypt_file(encrypted_file_path, key_file_path, passphrase):
    # Read encrypted file
    with open(encrypted_file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    # Read encrypted key and IV
    with open(key_file_path, 'rb') as f:
        salt = f.read(16)
        iv_key = f.read(16)
        encrypted_key = f.read()

    # Derive key from passphrase
    derived_key = derive_key(passphrase, salt)

    # Decrypt the key
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv_key), backend=default_backend())
    decryptor = cipher.decryptor()
    key = decryptor.update(encrypted_key) + decryptor.finalize()

    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    # Write decrypted file
    with open(DECRYPTED_FILE_PATH, 'wb') as f:
        f.write(data)

# Main logic
if __name__ == '__main__':
    user_passphrase = input("Enter your passphrase: ")

    # Decrypt the file
    print("Decrypting file...")
    decrypt_file(ENCRYPTED_FILE_PATH, KEY_FILE_PATH, user_passphrase)
    print(f"File decrypted and stored at {DECRYPTED_FILE_PATH}")
