
# 🔐 File Locker & Unlocker

A secure, GUI-based file encryption & decryption tool written in Python. With **just a password and one click**, you can lock or unlock your files using AES encryption (`Fernet` from the `cryptography` library). Ideal for securing private documents, source code, or any sensitive file.

---

## 💡 Features

- ✅ **Simple GUI** built with Tkinter
- 🔐 **Encrypt any file** using your password
- 🔓 **Decrypt** encrypted files (with `.locked` extension)
- 🔁 Replaces original file with the encrypted version for security
- 📁 File selection via file dialog – no command line needed
- ❌ Secure deletion of original file after encryption
- 🧠 Password converted securely to encryption key using SHA-256

---

## 🖥️ GUI Overview

![GUI Screenshot](assets/screenshot.png) *(Add your screenshot here)*

- **Password Field**: Enter the password used for locking or unlocking files.
- **Lock File (Encrypt)**: Select a file to encrypt – original file gets deleted after `.locked` version is created.
- **Unlock File (Decrypt)**: Select a `.locked` file to decrypt it back to its original form (requires correct password).
- **Exit**: Close the application.

---

## 🔧 How It Works

### 1. Password → Key
We use SHA-256 to hash your password and generate a 32-byte key. This is passed to `Fernet` for AES encryption.

```python
def password_to_key(password):
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()))


2. Encrypting a File
Reads the selected file in binary.

Encrypts the contents using the generated key.

Writes encrypted contents to <filename>.locked.

Deletes the original file.

3. Decrypting a File
Reads the .locked file in binary.

Decrypts it using your password.

Restores the original file by writing decrypted contents.

Deletes the encrypted file.

🛠️ Tech Stack
Python 3.10+

tkinter (standard GUI library)

cryptography (for AES encryption via Fernet)

hashlib (SHA-256 hashing)

base64, os, filedialog, messagebox

🚀 Getting Started
🔄 Clone the repository
git clone https://github.com/yourusername/file-locker-unlocker.git
cd file-locker-unlocker


🐍 Install Dependencies
pip install cryptography

Note: tkinter comes pre-installed with Python on most systems.

▶️ Run the App
python file_locker.py
🧪 Example Use Case
Click "Lock File (Encrypt)" → Choose any file → Enter password.

The app will:

Encrypt the file

Save as filename.locked

Delete original file

To recover:

Click "Unlock File (Decrypt)" → Choose the .locked file → Enter same password.

⚠️ Notes & Warnings
Your password must be remembered – there's no way to recover the file without it.

Don't kill the app while encrypting/decrypting – it could cause file corruption.

Be careful with large files or important documents. Always test with sample files first.

🤝 Contributing
Feel free to:

Fork this repo 🍴

Create a feature branch 🌱

Submit a Pull Request ✅

Bug reports, feature requests, and stars ⭐ are always welcome!

📃 License
MIT License – Do whatever you want, but don’t blame me if you lose your files. 😄

📬 Contact
Made with ❤️ by Megh Jaiswal
LinkedIn https://www.linkedin.com/in/megh-jaiswal-0762b2339/
