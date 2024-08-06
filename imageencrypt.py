import customtkinter as ctk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os

class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryptor App")
        self.root.geometry("400x300")
        self.root.resizable(False, False)

        # UI Elements
        self.label = ctk.CTkLabel(root, text="Image Encryptor Control Panel")
        self.label.pack(pady=(20, 10))

        self.upload_button = ctk.CTkButton(root, text="Upload Image", command=self.upload_image)
        self.upload_button.pack(pady=(10, 5))

        self.encrypt_button = ctk.CTkButton(root, text="Encrypt Image", command=self.encrypt_image)
        self.encrypt_button.pack(pady=(5, 5))

        self.decrypt_button = ctk.CTkButton(root, text="Decrypt Image", command=self.decrypt_image)
        self.decrypt_button.pack(pady=(5, 5))

        self.status_label = ctk.CTkLabel(root, text="Status: No image uploaded")
        self.status_label.pack(pady=(10, 20))

        self.image_path = None
        self.encrypted_image_path = None
        self.key = None  # Store the key for decryption

    def upload_image(self):
        self.image_path = filedialog.askopenfilename(
            title="Select an Image",
            filetypes=(("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"), ("All Files", "*.*"))
        )
        if self.image_path:
            self.status_label.configure(text=f"Selected: {os.path.basename(self.image_path)}")

    def encrypt_image(self):
        if not self.image_path:
            messagebox.showwarning("Warning", "No image selected.")
            return

        try:
            with open(self.image_path, 'rb') as f:
                image_data = f.read()

            self.key = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_CBC)
            iv = cipher.iv
            encrypted_data = cipher.encrypt(pad(image_data, AES.block_size))
            encrypted_content = base64.b64encode(iv + encrypted_data).decode('utf-8')

            self.encrypted_image_path = self.image_path + ".encrypted"
            with open(self.encrypted_image_path, 'w') as f:
                f.write(encrypted_content)

            self.status_label.configure(text="Image Encrypted Successfully")
            messagebox.showinfo("Success", f"Image encrypted and saved as {self.encrypted_image_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_image(self):
        if not self.encrypted_image_path or not self.key:
            messagebox.showwarning("Warning", "No encrypted image selected or key missing.")
            return

        try:
            with open(self.encrypted_image_path, 'r') as f:
                encrypted_content = f.read()

            encrypted_data = base64.b64decode(encrypted_content)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

            decrypted_image_path = self.encrypted_image_path.replace(".encrypted", ".decrypted.png")
            with open(decrypted_image_path, 'wb') as f:
                f.write(decrypted_data)

            self.status_label.configure(text="Image Decrypted Successfully")
            messagebox.showinfo("Success", f"Image decrypted and saved as {decrypted_image_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    app = ImageEncryptorApp(root)
    root.mainloop()
