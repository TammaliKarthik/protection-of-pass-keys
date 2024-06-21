import os
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def encrypt_file(file_path, output_path, password):
    try:
        # Generate a random salt
        salt = os.urandom(16)

        # Derive a key from the password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
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

        messagebox.showinfo("Success", f'File encrypted successfully and saved to {output_path}')
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_file(file_path, output_path, password):
    try:
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
            iterations=100000,
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

        messagebox.showinfo("Success", f'File decrypted successfully and saved to {output_path}')
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

class FileEncryptorDecryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("File Encryptor/Decryptor")

        self.label = Label(master, text="Select a file and enter a password to encrypt or decrypt.")
        self.label.pack()

        self.file_button = Button(master, text="Select File", command=self.select_file)
        self.file_button.pack()

        self.file_label = Label(master, text="")
        self.file_label.pack()

        self.password_label = Label(master, text="Enter Password:")
        self.password_label.pack()

        self.password_entry = Entry(master, show='*')
        self.password_entry.pack()

        self.encrypt_button = Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack()

        self.decrypt_button = Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()

        self.selected_file_path = None

    def select_file(self):
        self.selected_file_path = filedialog.askopenfilename()
        self.file_label.config(text=f"Selected File: {self.selected_file_path}")

    def encrypt(self):
        if not self.selected_file_path:
            messagebox.showerror("Error", "No file selected.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "No password entered.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                   filetypes=[("Encrypted files", "*.enc")])
        if not output_path:
            return

        encrypt_file(self.selected_file_path, output_path, password)

    def decrypt(self):
        if not self.selected_file_path:
            messagebox.showerror("Error", "No file selected.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "No password entered.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                   filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not output_path:
            return

        decrypt_file(self.selected_file_path, output_path, password)

if __name__ == "__main__":
    root = Tk()
    app = FileEncryptorDecryptorApp(root)
    root.mainloop()
