import os
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def decrypt_file(file_path, output_path):
    """
    Decrypts a file using AES-256 with a user-provided password.

    Parameters:
    - file_path: Path to the encrypted file.
    - output_path: Path where the decrypted file will be saved.
    """
    # Get password from user securely (input will not be echoed)
    password = getpass("Enter decryption password: ")

    # Read the salt, IV, and ciphertext from the input file
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    # Derive the key from the password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Same iterations as used for encryption
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Decrypt the file
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Write decrypted data to output file
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    print(f'File decrypted successfully and saved to {output_path}')

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Decrypt a file using AES-256 decryption.')
    parser.add_argument('input_file', help='Input file path.')
    parser.add_argument('output_file', help='Output file path.')

    args = parser.parse_args()

    decrypt_file(args.input_file, args.output_file)
