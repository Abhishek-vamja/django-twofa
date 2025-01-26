from cryptography.fernet import Fernet
import time

# Generate a key (keep this safe!)
KEY = b'bK5PQB-QN3CbvUc5Xuy191gimbygf12RzmQlEbGMetk='
fernet = Fernet(KEY)

# Encrypt a message
def encrypt_message(message):
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

# Decrypt a message
def decrypt_message(encrypted_message):
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message