import customtkinter as ctk
from tkinter import filedialog, messagebox, Scrollbar, VERTICAL, RIGHT, Y
import random
import string
import re

class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Analyzer and Suggester")
        self.root.geometry("600x500")
        self.root.resizable(False, False)

        # UI Elements
        self.label = ctk.CTkLabel(root, text="Password Analyzer and Suggester")
        self.label.pack(pady=(20, 10))

        self.password_entry = ctk.CTkEntry(root, placeholder_text="Enter Password")
        self.password_entry.pack(pady=(10, 5), padx=20, fill='x')

        self.analyze_button = ctk.CTkButton(root, text="Analyze Password", command=self.analyze_password)
        self.analyze_button.pack(pady=(5, 5))

        self.suggest_button = ctk.CTkButton(root, text="Suggest Improvements", command=self.suggest_improvements)
        self.suggest_button.pack(pady=(5, 5))

        self.generate_button = ctk.CTkButton(root, text="Generate Secure Password", command=self.generate_password)
        self.generate_button.pack(pady=(5, 10))

        self.analysis_frame = ctk.CTkFrame(root)
        self.analysis_frame.pack(pady=(10, 5), padx=20, fill='both', expand=True)

        self.analysis_label = ctk.CTkLabel(self.analysis_frame, text="Analysis Result:")
        self.analysis_label.pack(anchor='w')

        self.analysis_text = ctk.CTkTextbox(self.analysis_frame, height=10, width=70)
        self.analysis_text.pack(side='left', fill='both', expand=True)

        self.analysis_scrollbar = Scrollbar(self.analysis_frame, orient=VERTICAL, command=self.analysis_text.yview)
        self.analysis_scrollbar.pack(side=RIGHT, fill=Y)
        self.analysis_text.configure(yscrollcommand=self.analysis_scrollbar.set)

        self.suggestions_frame = ctk.CTkFrame(root)
        self.suggestions_frame.pack(pady=(10, 20), padx=20, fill='both', expand=True)

        self.suggestions_label = ctk.CTkLabel(self.suggestions_frame, text="Suggestions:")
        self.suggestions_label.pack(anchor='w')

        self.suggestions_text = ctk.CTkTextbox(self.suggestions_frame, height=10, width=70)
        self.suggestions_text.pack(side='left', fill='both', expand=True)

        self.suggestions_scrollbar = Scrollbar(self.suggestions_frame, orient=VERTICAL, command=self.suggestions_text.yview)
        self.suggestions_scrollbar.pack(side=RIGHT, fill=Y)
        self.suggestions_text.configure(yscrollcommand=self.suggestions_scrollbar.set)

    def analyze_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password to analyze.")
            return
        
        analysis_result = self.password_analysis(password)
        self.analysis_text.delete('1.0', ctk.END)
        self.analysis_text.insert('1.0', analysis_result)

    def suggest_improvements(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password to get suggestions.")
            return
        
        suggestions = self.password_suggestions(password)
        self.suggestions_text.delete('1.0', ctk.END)
        self.suggestions_text.insert('1.0', suggestions)

    def generate_password(self):
        password = self.generate_secure_password()
        messagebox.showinfo("Generated Password", f"Your new secure password is:\n{password}")

    def password_analysis(self, password):
        length_check = len(password) >= 12
        upper_check = bool(re.search(r'[A-Z]', password))
        lower_check = bool(re.search(r'[a-z]', password))
        digit_check = bool(re.search(r'\d', password))
        special_check = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        common_pattern_check = not self.has_common_patterns(password)

        result = []
        result.append(f"Length (at least 12): {'Pass' if length_check else 'Fail'}")
        result.append(f"Contains uppercase letters: {'Pass' if upper_check else 'Fail'}")
        result.append(f"Contains lowercase letters: {'Pass' if lower_check else 'Fail'}")
        result.append(f"Contains digits: {'Pass' if digit_check else 'Fail'}")
        result.append(f"Contains special characters: {'Pass' if special_check else 'Fail'}")
        result.append(f"Free from common patterns: {'Pass' if common_pattern_check else 'Fail'}")

        return "\n".join(result)

    def password_suggestions(self, password):
        suggestions = []
        if len(password) < 12:
            suggestions.append("Increase password length to at least 12 characters.")
        if not re.search(r'[A-Z]', password):
            suggestions.append("Include uppercase letters.")
        if not re.search(r'[a-z]', password):
            suggestions.append("Include lowercase letters.")
        if not re.search(r'\d', password):
            suggestions.append("Include digits.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            suggestions.append("Include special characters.")
        if self.has_common_patterns(password):
            suggestions.append("Avoid common patterns or sequences.")
        
        return "\n".join(suggestions) if suggestions else "Password is strong."

    def generate_secure_password(self, length=16):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    def has_common_patterns(self, password):
        common_patterns = [
            r"1234", r"password", r"qwerty", r"abc123", r"letmein", r"welcome", r"admin", r"password1"
        ]
        return any(pattern in password.lower() for pattern in common_patterns)

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    app = PasswordAnalyzerApp(root)
    root.mainloop()
