import random
import string
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Substitusi Sederhana
def generate_key():
    chars = " " + string.punctuation + string.digits + string.ascii_letters
    chars = list(chars)
    key = chars.copy()
    random.shuffle(key)
    return chars, key

def encrypt_substitution(plain_text, chars, key):
    cipher_text = ""
    for letter in plain_text:
        index = chars.index(letter)
        cipher_text += key[index]
    return cipher_text

def decrypt_substitution(cipher_text, chars, key):
    plain_text = ""
    for letter in cipher_text:
        index = key.index(letter)
        plain_text += chars[index]
    return plain_text

# RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_keys(private_key, public_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def load_keys(private_pem, public_pem):
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
    )
    public_key = serialization.load_pem_public_key(
        public_pem,
    )
    return private_key, public_key

def encrypt_rsa(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_rsa(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Main Function
def main():
    while True:
        print("\nSelect Encryption Method:")
        print("1. Assymetric Cipher")
        print("2. RSA Encryption")
        print("Q. Quit")
        method = input("Enter your choice (1/2/Q): ").upper()
        
        if method == '1':
            chars, key = generate_key()
            while True:
                action = input("\nDo you want to (E)ncrypt or (D)ecrypt a message? (E/D) or (B)ack to main menu: ").upper()
                if action == 'E':
                    plain_text = input("Enter a message to encrypt: ")
                    cipher_text = encrypt_substitution(plain_text, chars, key)
                    print(f"Original message : {plain_text}")
                    print(f"Encrypted message: {cipher_text}")
                elif action == 'D':
                    cipher_text = input("Enter a message to decrypt: ")
                    plain_text = decrypt_substitution(cipher_text, chars, key)
                    print(f"Encrypted message: {cipher_text}")
                    print(f"Original message : {plain_text}")
                elif action == 'B':
                    break
                else:
                    print("Invalid choice. Please select 'E' to encrypt, 'D' to decrypt, or 'B' to go back to the main menu.")
        
        elif method == '2':
            private_key, public_key = generate_rsa_keys()
            private_pem, public_pem = serialize_keys(private_key, public_key)
            private_key, public_key = load_keys(private_pem, public_pem)
            while True:
                action = input("\nDo you want to (E)ncrypt or (D)ecrypt a message? (E/D) or (B)ack to main menu: ").upper()
                if action == 'E':
                    plain_text = input("Enter a message to encrypt: ")
                    encrypted_message = encrypt_rsa(public_key, plain_text)
                    print(f"Original message : {plain_text}")
                    print(f"Encrypted message: {encrypted_message}")
                elif action == 'D':
                    encrypted_message = input("Enter a message to decrypt (as byte literal, e.g., b'...'): ")
                    try:
                        decrypted_message = decrypt_rsa(private_key, eval(encrypted_message))
                        print(f"Encrypted message: {encrypted_message}")
                        print(f"Original message : {decrypted_message}")
                    except Exception as e:
                        print(f"Decryption failed: {e}")
                elif action == 'B':
                    break
                else:
                    print("Invalid choice. Please select 'E' to encrypt, 'D' to decrypt, or 'B' to go back to the main menu.")
        
        elif method == 'Q':
            break
        else:
            print("Invalid choice. Please select '1' for Substitution Cipher, '2' for RSA Encryption, or 'Q' to quit.")

if __name__ == "__main__":
    main()
