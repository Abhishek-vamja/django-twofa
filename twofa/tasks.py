import json
from cryptography.fernet import Fernet

# Generate a key (keep this safe!)
KEY = b'bK5PQB-QN3CbvUc5Xuy191gimbygf12RzmQlEbGMetk='
fernet = Fernet(KEY)


def encrypt_message(message):
    """Encrypts a string or dictionary."""
    if isinstance(message, dict):
        message = json.dumps(message)
    elif not isinstance(message, str):
        raise ValueError("Only strings or dictionaries are allowed")
    
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    """Decrypts a message and converts JSON strings back to dictionaries if applicable."""
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    
    try:
        return json.loads(decrypted_message)
    except json.JSONDecodeError:
        return decrypted_message