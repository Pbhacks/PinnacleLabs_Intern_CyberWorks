import customtkinter as ctk
from tkinter import messagebox
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class EncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption App")
        self.root.geometry("400x300")
        self.root.resizable(False, False)

        # Encryption Algorithms
        self.encryptor = Encryptor()

        # Input Text
        self.input_label = ctk.CTkLabel(root, text="Input Text:")
        self.input_label.pack(pady=(10, 0))
        self.input_text = ctk.CTkEntry(root, width=300)
        self.input_text.pack(pady=(0, 10))

        # Encryption Method
        self.method_label = ctk.CTkLabel(root, text="Select Encryption Method:")
        self.method_label.pack()
        self.method_var = ctk.StringVar(value="AES")
        self.method_combobox = ctk.CTkComboBox(root, variable=self.method_var, values=["AES", "DES", "RSA"])
        self.method_combobox.pack(pady=(0, 10))

        # Buttons
        self.encrypt_button = ctk.CTkButton(root, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=(0, 5))
        self.decrypt_button = ctk.CTkButton(root, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(pady=(0, 10))

        # Output Text
        self.output_label = ctk.CTkLabel(root, text="Output Text:")
        self.output_label.pack()
        self.output_text = ctk.CTkEntry(root, width=300)
        self.output_text.pack(pady=(0, 10))

    def encrypt(self):
        plaintext = self.input_text.get()
        method = self.method_var.get()
        try:
            if method == "AES":
                encrypted = self.encryptor.encrypt_aes(plaintext)
            elif method == "DES":
                encrypted = self.encryptor.encrypt_des(plaintext)
            elif method == "RSA":
                encrypted = self.encryptor.encrypt_rsa(plaintext)
            else:
                raise ValueError("Invalid encryption method.")
            self.output_text.delete(0, ctk.END)
            self.output_text.insert(0, encrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt(self):
        encrypted_text = self.output_text.get()
        method = self.method_var.get()
        try:
            if method == "AES":
                decrypted = self.encryptor.decrypt_aes(encrypted_text)
            elif method == "DES":
                decrypted = self.encryptor.decrypt_des(encrypted_text)
            elif method == "RSA":
                decrypted = self.encryptor.decrypt_rsa(encrypted_text)
            else:
                raise ValueError("Invalid encryption method.")
            self.output_text.delete(0, ctk.END)
            self.output_text.insert(0, decrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

class Encryptor:
    def __init__(self):
        # AES setup
        self.aes_key = get_random_bytes(16)
        self.aes_cipher = AES.new(self.aes_key, AES.MODE_CBC)
        self.aes_iv = self.aes_cipher.iv

        # DES setup
        self.des_key = get_random_bytes(8)
        self.des_cipher = DES.new(self.des_key, DES.MODE_CBC)
        self.des_iv = self.des_cipher.iv

        # RSA setup
        self.rsa_key = RSA.generate(2048)
        self.rsa_public_key = self.rsa_key.publickey()
        self.rsa_cipher = PKCS1_OAEP.new(self.rsa_public_key)

    def encrypt_aes(self, plaintext):
        padded_text = pad(plaintext.encode(), AES.block_size)
        ciphertext = self.aes_cipher.encrypt(padded_text)
        return base64.b64encode(self.aes_iv + ciphertext).decode('utf-8')

    def decrypt_aes(self, encrypted_text):
        raw_data = base64.b64decode(encrypted_text)
        iv = raw_data[:AES.block_size]
        ciphertext = raw_data[AES.block_size:]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')

    def encrypt_des(self, plaintext):
        padded_text = pad(plaintext.encode(), DES.block_size)
        ciphertext = self.des_cipher.encrypt(padded_text)
        return base64.b64encode(self.des_iv + ciphertext).decode('utf-8')

    def decrypt_des(self, encrypted_text):
        raw_data = base64.b64decode(encrypted_text)
        iv = raw_data[:DES.block_size]
        ciphertext = raw_data[DES.block_size:]
        cipher = DES.new(self.des_key, DES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return plaintext.decode('utf-8')

    def encrypt_rsa(self, plaintext):
        ciphertext = self.rsa_cipher.encrypt(plaintext.encode())
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt_rsa(self, encrypted_text):
        ciphertext = base64.b64decode(encrypted_text)
        plaintext = PKCS1_OAEP.new(self.rsa_key).decrypt(ciphertext)
        return plaintext.decode('utf-8')

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")  # Modes: "System" (default), "Dark", "Light"
    ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "green", "dark-blue"

    root = ctk.CTk()
    app = EncryptorApp(root)
    root.mainloop()
