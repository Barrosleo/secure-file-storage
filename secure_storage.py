pip install cryptography

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Encryption and Decryption Function
def encrypt_file(file_path, password):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(file_path, 'rb') as f:
        data = f.read()

    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + iv + encrypted_data)

def decrypt_file(file_path, password):
    backend = default_backend()
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(file_path[:-4], 'wb') as f:
        f.write(unpadded_data)

# Access Control Mechanisms
users = {
    "admin": "admin_password",
    "user1": "user1_password"
}

def authenticate(username, password):
    if username in users and users[username] == password:
        return True
    return False

def authorize(username, action):
    if username == "admin":
        return True
    elif username == "user1" and action in ["read", "write"]:
        return True
    return False
 
  # Main Function to Run the System
  if __name__ == "__main__":
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    if authenticate(username, password):
        action = input("Do you want to (e)ncrypt, (d)ecrypt, (r)ead, or (w)rite a file? ")

        if authorize(username, action):
            if action == 'e':
                file_path = input("Enter the file path to encrypt: ")
                file_password = input("Enter the file password: ")
                encrypt_file(file_path, file_password)
                print("File encrypted successfully.")

            elif action == 'd':
                file_path = input("Enter the file path to decrypt: ")
                file_password = input("Enter the file password: ")
                decrypt_file(file_path, file_password)
                print("File decrypted successfully.")

            elif action == 'r':
                file_path = input("Enter the file path to read: ")
                with open(file_path, 'r') as f:
                    print(f.read())

            elif action == 'w':
                file_path = input("Enter the file path to write: ")
                content = input("Enter the content to write: ")
                with open(file_path, 'w') as f:
                    f.write(content)
                print("File written successfully.")
        else:
            print("Unauthorized action.")
    else:
        print("Authentication failed.")
