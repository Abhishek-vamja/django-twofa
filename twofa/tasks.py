from cryptography.fernet import Fernet
import time

# Generate a key (keep this safe!)
KEY = b'bK5PQB-QN3CbvUc5Xuy191gimbygf12RzmQlEbGMetk='

class TimedKeyFernet:
    """
    A wrapper class for handling Fernet encryption/decryption with a time-bound key (3 minutes).
    """
    def __init__(self, timeout=180):
        self.timeout = timeout
        self.key = KEY
        self.fernet = Fernet(self.key)
        self.timestamp = time.time()

    def generate_key(self):
        """
        Generate a new Fernet key.
        """
        return Fernet.generate_key()

    def check_key_expiration(self):
        """
        Check if the key has expired (i.e., if it was generated more than 3 minutes ago).
        """
        if time.time() - self.timestamp > self.timeout:
            raise ValueError("The key has expired. Please generate a new one.")
    
    def encrypt_message(self, message):
        """
        Encrypt a message using the current key.
        """
        self.check_key_expiration()  # Check key expiration before using it
        return self.fernet.encrypt(message.encode())

    def decrypt_message(self, encrypted_message):
        """
        Decrypt a message using the current key.
        """
        self.check_key_expiration()  # Check key expiration before using it
        return self.fernet.decrypt(encrypted_message).decode()