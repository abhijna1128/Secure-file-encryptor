from aes_utils import encrypt_aes256, decrypt_aes256

def encrypt_file():
    file_path = input("Enter path to file to encrypt: ")
    password = input("Enter password: ")

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        encrypted = encrypt_aes256(data, password)

        out_file = file_path + ".aes"
        with open(out_file, 'wb') as f:
            f.write(encrypted)

        print(f"✅ File encrypted and saved as: {out_file}")
    except Exception as e:
        print("❌ Error:", e)

def decrypt_file():
    file_path = input("Enter path to encrypted file: ")
    password = input("Enter password: ")

    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted = decrypt_aes256(encrypted_data, password)

        out_file = file_path.replace(".aes", ".decrypted.txt")
        with open(out_file, 'wb') as f:
            f.write(decrypted)

        print(f"✅ File decrypted and saved as: {out_file}")
    except Exception as e:
        print("❌ Decryption failed:", e)

def main():
    print("🔐 AES-256 File Locker")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Choose option (1/2): ")

    if choice == '1':
        encrypt_file()
    elif choice == '2':
        decrypt_file()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()