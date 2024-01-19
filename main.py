import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class KeyGenerator:
    def __init__(self, master):
        self.master = master
        self.master.title("KeyGenerator")

        self.private_key = None
        self.public_key = None

        self.generate_keys_button = tk.Button(master, text="Generate Keys", command=self.generate_keys)
        self.generate_keys_button.pack(pady=10)

        self.export_public_key_button = tk.Button(master, text="Export Public Key", command=self.export_public_key)
        self.export_public_key_button.pack()

        self.import_public_key_button = tk.Button(master, text="Import Public Key", command=self.import_public_key)
        self.import_public_key_button.pack(pady=10)

        self.encrypt_button = tk.Button(master, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(master, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack(pady=10)

        self.quit_button = tk.Button(master, text="Quit", command=master.quit)
        self.quit_button.pack(pady=10)

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def export_public_key(self):
        if self.public_key:
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open("public_key.pem", "wb") as f:
                f.write(pem)
            print("Public key exported to public_key.pem")
        else:
            print("Generate keys first.")

    def import_public_key(self):
        file_path = filedialog.askopenfilename(title="Select Public Key File", filetypes=[("PEM files", "*.pem")])
        with open(file_path, "rb") as f:
            self.public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        print("Public key imported successfully.")

    def encrypt_file(self):
        if self.public_key:
            file_path = filedialog.askopenfilename(title="Select File to Encrypt", filetypes=[("All files", "*.*")])
            with open(file_path, "rb") as f:
                plaintext = f.read()

            ciphertext = self.public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            with open("encrypted_file.bin", "wb") as f:
                f.write(ciphertext)
            print("File encrypted and saved as encrypted_file.bin")
        else:
            print("Import public key first.")

    def decrypt_file(self):
        if self.private_key:
            file_path = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("All files", "*.*")])
            with open(file_path, "rb") as f:
                ciphertext = f.read()

            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            with open("decrypted_file.txt", "wb") as f:
                f.write(plaintext)
            print("File decrypted and saved as decrypted_file.txt")
        else:
            print("Generate keys first.")


if __name__ == "__main__":
    root = tk.Tk()
    app = KeyGenerator(root)
    root.mainloop()
