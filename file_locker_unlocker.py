import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import hashlib
import os

# --- Password to key ---
def password_to_key(password):
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()))

import base64

# --- Encryption ---
def encrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        key = password_to_key(password)
        encrypted_data = key.encrypt(data)

        with open(file_path + ".locked", 'wb') as f:
            f.write(encrypted_data)

        os.remove(file_path)
        messagebox.showinfo("Success", f"File encrypted: {file_path}.locked")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{e}")

# --- Decryption ---
def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        key = password_to_key(password)
        decrypted_data = key.decrypt(encrypted_data)

        original_path = file_path.replace(".locked", "")
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)

        os.remove(file_path)
        messagebox.showinfo("Success", f"File decrypted: {original_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{e}")

# --- GUI ---
def select_file_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return
        encrypt_file(file_path, password)

def select_file_decrypt():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.locked")])
    if file_path:
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            return
        decrypt_file(file_path, password)

# --- GUI Layout ---
root = tk.Tk()
root.title("🔒 File Locker & Unlocker")
root.geometry("400x300")
root.configure(bg="#2c3e50")
root.resizable(False, False)

tk.Label(root, text="File Locker & Unlocker", font=("Helvetica", 16, "bold"), fg="white", bg="#2c3e50").pack(pady=10)

tk.Label(root, text="Enter Password:", font=("Segoe UI", 11), fg="white", bg="#2c3e50").pack(pady=(10, 5))
password_entry = tk.Entry(root, width=30, show="*", font=("Segoe UI", 11))
password_entry.pack(pady=(0, 15))

btn_style = {"font": ("Segoe UI", 10, "bold"), "padx": 10, "pady": 5, "width": 25}

encrypt_btn = tk.Button(root, text="🔐 Lock File (Encrypt)", command=select_file_encrypt, bg="#27ae60", fg="white", **btn_style)
encrypt_btn.pack(pady=5)

decrypt_btn = tk.Button(root, text="🔓 Unlock File (Decrypt)", command=select_file_decrypt, bg="#2980b9", fg="white", **btn_style)
decrypt_btn.pack(pady=5)

exit_btn = tk.Button(root, text="❌ Exit", command=root.quit, bg="#c0392b", fg="white", **btn_style)
exit_btn.pack(pady=10)

root.mainloop()
