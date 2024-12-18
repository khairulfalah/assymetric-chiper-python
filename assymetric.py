import random
import string
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

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
    return base64.b64encode(encrypted).decode()

def decrypt_rsa(private_key, encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message.encode())
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# GUI Application
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption App")
        self.create_widgets()
        
    def create_widgets(self):
        # Method selection
        self.method_label = tk.Label(self.root, text="Select Encryption Method:")
        self.method_label.pack()

        self.method_var = tk.StringVar(value="1")
        self.substitution_radio = tk.Radiobutton(self.root, text="Substitution Cipher", variable=self.method_var, value="1")
        self.rsa_radio = tk.Radiobutton(self.root, text="RSA Encryption", variable=self.method_var, value="2")
        self.substitution_radio.pack()
        self.rsa_radio.pack()

        # Message entry
        self.message_label = tk.Label(self.root, text="Enter your message:")
        self.message_label.pack()
        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.pack()

        # Action buttons
        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_message)
        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_message)
        self.encrypt_button.pack()
        self.decrypt_button.pack()

        # Result display
        self.result_label = tk.Label(self.root, text="Result:")
        self.result_label.pack()
        self.result_text = tk.Text(self.root, height=10, width=50)
        self.result_text.pack()

        # Initialize RSA keys
        self.private_key, self.public_key = generate_rsa_keys()
        self.private_pem, self.public_pem = serialize_keys(self.private_key, self.public_key)
        self.private_key, self.public_key = load_keys(self.private_pem, self.public_pem)

        # Initialize Substitution Cipher keys
        self.chars, self.key = generate_key()

    def encrypt_message(self):
        message = self.message_entry.get()
        method = self.method_var.get()

        if method == "1":
            encrypted_message = encrypt_substitution(message, self.chars, self.key)
        elif method == "2":
            encrypted_message = encrypt_rsa(self.public_key, message)
        else:
            encrypted_message = "Invalid method selected."

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, encrypted_message)

    def decrypt_message(self):
        message = self.message_entry.get()
        method = self.method_var.get()

        try:
            if method == "1":
                decrypted_message = decrypt_substitution(message, self.chars, self.key)
            elif method == "2":
                decrypted_message = decrypt_rsa(self.private_key, message)
            else:
                decrypted_message = "Invalid method selected."
        except Exception as e:
            decrypted_message = f"Decryption failed: {e}"

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, decrypted_message)

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

