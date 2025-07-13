# Secure File Locker - Phase C (Visual Enhancements)

import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import os, re, time
from aes_utils import encrypt_file, decrypt_file, encrypt_aes256, decrypt_aes256
from stego_utils import embed_data_into_image, extract_data_from_image

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def get_password_strength(pwd):
    if len(pwd) < 8:
        return "Weak", "red"
    score = 0
    if len(pwd) >= 12: score += 1
    if re.search(r'[a-z]', pwd): score += 1
    if re.search(r'[A-Z]', pwd): score += 1
    if re.search(r'[0-9]', pwd): score += 1
    if re.search(r'[^a-zA-Z0-9]', pwd): score += 1
    if score <= 2:
        return "Weak", "red"
    elif score <= 4:
        return "Moderate", "orange"
    return "Strong", "green"

class FileLockerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Secure File Locker - AES-256")
        self.geometry("650x600")
        self.file_path = ctk.StringVar()
        self.password = ctk.StringVar()
        self.confirm_password = ctk.StringVar()
        self.notebook = ttk.Notebook(self)
        self.build_tabs()

    def build_tabs(self):
        self.encrypt_tab = ctk.CTkFrame(self.notebook)
        self.stego_tab = ctk.CTkFrame(self.notebook)
        self.batch_tab = ctk.CTkFrame(self.notebook)
        self.settings_tab = ctk.CTkFrame(self.notebook)

        self.notebook.add(self.encrypt_tab, text="Encrypt/Decrypt")
        self.notebook.add(self.stego_tab, text="Steganography")
        self.notebook.add(self.batch_tab, text="Batch Mode")
        self.notebook.add(self.settings_tab, text="Settings")
        self.notebook.pack(expand=True, fill="both")

        self.build_encrypt_tab()
        self.build_stego_tab()
        self.build_batch_tab()
        self.build_settings_tab()

    def build_encrypt_tab(self):
        ctk.CTkLabel(self.encrypt_tab, text="File:").pack(pady=2)
        ctk.CTkEntry(self.encrypt_tab, textvariable=self.file_path, width=400).pack()
        ctk.CTkButton(self.encrypt_tab, text="Browse", command=self.browse_file).pack(pady=5)

        ctk.CTkLabel(self.encrypt_tab, text="Password:").pack(pady=(10, 2))
        pwd_entry = ctk.CTkEntry(self.encrypt_tab, textvariable=self.password, show="*", width=300)
        pwd_entry.pack()
        pwd_entry.bind("<KeyRelease>", self.update_strength)

        ctk.CTkLabel(self.encrypt_tab, text="Confirm Password:").pack(pady=(10, 2))
        ctk.CTkEntry(self.encrypt_tab, textvariable=self.confirm_password, show="*", width=300).pack()

        self.strength_label = ctk.CTkLabel(self.encrypt_tab, text="Password Strength: ", text_color="white")
        self.strength_label.pack(pady=5)

        ctk.CTkButton(self.encrypt_tab, text="Encrypt File", command=self.encrypt).pack(pady=5)
        ctk.CTkButton(self.encrypt_tab, text="Decrypt File", command=self.decrypt).pack(pady=5)

        self.progress = ttk.Progressbar(self.encrypt_tab, orient="horizontal", mode="determinate", length=300)
        self.progress.pack(pady=5)

        self.status_label = ctk.CTkLabel(self.encrypt_tab, text="", text_color="green")
        self.status_label.pack(pady=10)

        self.log_box = ctk.CTkTextbox(self.encrypt_tab, height=100, width=500)
        self.log_box.pack(pady=10)

    def build_stego_tab(self):
        ctk.CTkButton(self.stego_tab, text="Encrypt & Hide in Image", command=self.encrypt_and_hide).pack(pady=20)
        ctk.CTkButton(self.stego_tab, text="Extract & Decrypt from Image", command=self.extract_and_decrypt).pack(pady=10)

    def build_batch_tab(self):
        ctk.CTkButton(self.batch_tab, text="Batch Encrypt Files", command=self.batch_encrypt_files).pack(pady=20)

    def build_settings_tab(self):
        ctk.CTkLabel(self.settings_tab, text="(Settings coming soon)").pack(pady=20)

    def browse_file(self):
        file = filedialog.askopenfilename()
        self.file_path.set(file)

    def encrypt(self):
        path = self.file_path.get()
        pwd = self.password.get()
        confirm = self.confirm_password.get()
        self.progress['value'] = 0

        if not path or not pwd:
            messagebox.showerror("Error", "Please select a file and enter password.")
            return
        if pwd != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        try:
            start = time.time()
            out_path = encrypt_file(path, pwd)
            self.progress['value'] = 100
            end = time.time()
            size = os.path.getsize(out_path)
            self.status_label.configure(text=f"✅ Encrypted: {out_path}", text_color="green")
            self.log_box.insert("end", f"[+] File Encrypted: {out_path}\nSize: {size//1024} KB\nTime: {end-start:.2f}s\n")
        except Exception as e:
            self.status_label.configure(text=f"❌ Error: {e}", text_color="red")
            self.log_box.insert("end", f"[!] Error: {e}\n")

    def decrypt(self):
        path = self.file_path.get()
        pwd = self.password.get()
        self.progress['value'] = 0

        if not path or not pwd:
            messagebox.showerror("Error", "Please select a file and enter password.")
            return
        try:
            start = time.time()
            out_path = decrypt_file(path, pwd)
            self.progress['value'] = 100
            end = time.time()
            size = os.path.getsize(out_path)
            self.status_label.configure(text=f"✅ Decrypted: {out_path}", text_color="green")
            self.log_box.insert("end", f"[+] File Decrypted: {out_path}\nSize: {size//1024} KB\nTime: {end-start:.2f}s\n")
        except Exception as e:
            self.status_label.configure(text=f"❌ Decryption Failed: {e}", text_color="red")
            self.log_box.insert("end", f"[!] Error: {e}\n")

    def encrypt_and_hide(self):
        file_path = self.file_path.get()
        pwd = self.password.get()
        confirm = self.confirm_password.get()

        if not file_path or not pwd:
            messagebox.showerror("Error", "Please select file and enter password.")
            return
        if pwd != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        image_path = filedialog.askopenfilename(title="Choose cover image (.png or .bmp)",
                                                filetypes=[("Image files", "*.png *.bmp")])
        if not image_path:
            return

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()

            encrypted = encrypt_aes256(file_data, pwd)
            os.makedirs("output", exist_ok=True)
            out_image_path = os.path.join("output", "stego_image.png")
            embed_data_into_image(image_path, encrypted, out_image_path)

            self.status_label.configure(text=f"✅ Data hidden in image: {out_image_path}", text_color="green")
            self.log_box.insert("end", f"[+] Data hidden in image: {out_image_path}\n")

        except Exception as e:
            self.status_label.configure(text=f"❌ Error: {e}", text_color="red")
            self.log_box.insert("end", f"[!] Error: {e}\n")

    def extract_and_decrypt(self):
        image_path = filedialog.askopenfilename(title="Select image with hidden data",
                                                filetypes=[("Image files", "*.png *.bmp")])
        pwd = self.password.get()
        if not image_path or not pwd:
            messagebox.showerror("Error", "Select an image and enter password.")
            return

        try:
            hidden_data = extract_data_from_image(image_path)
            decrypted = decrypt_aes256(hidden_data, pwd)
            os.makedirs("output", exist_ok=True)
            out_path = os.path.join("output", "extracted_decrypted_file")
            with open(out_path, 'wb') as f:
                f.write(decrypted)

            self.status_label.configure(text=f"✅ File extracted and decrypted: {out_path}", text_color="green")
            self.log_box.insert("end", f"[+] File extracted and decrypted: {out_path}\n")

        except Exception as e:
            self.status_label.configure(text=f"❌ Failed: {e}", text_color="red")
            self.log_box.insert("end", f"[!] Error: {e}\n")

    def batch_encrypt_files(self):
        file_paths = filedialog.askopenfilenames(title="Select multiple files to encrypt")
        pwd = self.password.get()
        confirm = self.confirm_password.get()

        if not file_paths or not pwd:
            messagebox.showerror("Error", "Please select files and enter password.")
            return
        if pwd != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        success, failed = [], []
        os.makedirs("output", exist_ok=True)

        for file_path in file_paths:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypted = encrypt_aes256(data, pwd)
                out_path = os.path.join("output", os.path.basename(file_path) + ".aes")
                with open(out_path, 'wb') as f:
                    f.write(encrypted)
                success.append(os.path.basename(file_path))
            except Exception as e:
                failed.append(f"{os.path.basename(file_path)} - {e}")

        result_msg = f"✅ Encrypted: {len(success)} files.\n"
        if failed:
            result_msg += f"❌ Failed: {len(failed)} files:\n" + "\n".join(failed)
            self.status_label.configure(text="Batch encryption completed with some errors.", text_color="orange")
        else:
            self.status_label.configure(text="✅ All files encrypted successfully.", text_color="green")

        self.log_box.insert("end", result_msg + "\n")
        messagebox.showinfo("Batch Encrypt Result", result_msg)

    def update_strength(self, event=None):
        pwd = self.password.get()
        label, color = get_password_strength(pwd)
        self.strength_label.configure(text=f"Password Strength: {label}", text_color=color)

if __name__ == "__main__":
    app = FileLockerApp()
    app.mainloop()
