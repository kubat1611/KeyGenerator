# KeyGenerator
 
Overview

The KeyGenerator is a simple Python script using the tkinter library for creating, exporting, importing, encrypting, and decrypting RSA key pairs. The script employs the cryptography library to handle cryptographic operations. The graphical user interface (GUI) enables users to generate RSA key pairs, export/import public keys, and perform file encryption and decryption using the generated keys.
Features

    Generate Keys:
        Click the "Generate Keys" button to generate a new RSA key pair with a specified public exponent, key size, and backend.

    Export Public Key:
        Click the "Export Public Key" button to export the generated public key to a PEM file named public_key.pem.

    Import Public Key:
        Click the "Import Public Key" button to import a public key from a PEM file selected through a file dialog.

    Encrypt File:
        After generating or importing a public key, click the "Encrypt File" button to encrypt a selected file using the RSA public key. The encrypted file is saved as encrypted_file.bin.

    Decrypt File:
        After generating a private key, click the "Decrypt File" button to decrypt a selected file using the RSA private key. The decrypted file is saved as decrypted_file.txt.

    Quit: 
        Click the "Quit" button to exit the application.

Author

Mundek
