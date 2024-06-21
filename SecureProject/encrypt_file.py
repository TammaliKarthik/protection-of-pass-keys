import os
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def encrypt_file(file_path, output_path):
    """
    Encrypts a file using AES-256 with a user-provided password.

    Parameters:
    - file_path: Path to the plaintext file.
    - output_path: Path where the encrypted file will be saved.
    """
    # Get password from user securely (input will not be echoed)
    password = getpass("Enter encryption password: ")

    # Generate a random salt
    salt = os.urandom(16)

    # Derive a key from the password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Adjust iterations based on your security needs
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Encrypt the file
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write encrypted data along with salt and IV to output file
    with open(output_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)

    print(f'File encrypted successfully and saved to {output_path}')

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Encrypt a file using AES-256 encryption.')
    parser.add_argument('input_file', help='Input file path.')
    parser.add_argument('output_file', help='Output file path.')

    args = parser.parse_args()

    encrypt_file(args.input_file, args.output_file)
