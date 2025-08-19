# Crypto Steganography Tool

A Python-based tool that combines AES encryption with image steganography to securely hide encrypted data within images.

## Overview

This project provides a complete solution for:
- AES encryption/decryption of files
- Hiding encrypted data within images using steganography
- Extracting and decrypting hidden data from images

## Features

- **AES Encryption**: Secure file encryption using AES-256-CBC
- **Image Steganography**: Hide encrypted data within PNG images using LSB (Least Significant Bit) technique
- **Cross-platform**: Works on Windows, macOS, and Linux
- **User-friendly**: Simple command-line interface

## Requirements

- Python 3.6+
- PIL (Pillow) library
- cryptography library

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd crypto
```

2. Install required dependencies:
```bash
pip install pillow cryptography
```

## Usage

### Basic Workflow

1. **Encrypt and Hide a File**:
   - Encrypt your file using AES encryption
   - Hide the encrypted data within an image

2. **Extract and Decrypt**:
   - Extract hidden data from the image
   - Decrypt the extracted data back to original file

### File Structure

```
crypto/
├── aes_utils.py          # AES encryption/decryption utilities
├── stego_utils.py        # Steganography functions
├── main.py              # Main application entry point
├── output/              # Output directory for processed files
│   ├── *.aes            # Encrypted files
│   ├── *.decrypted      # Decrypted files
│   └── stego_image.png  # Image with hidden data
└── README.md            # This file
```

### Modules

#### aes_utils.py
- `encrypt_file(input_file, password)`: Encrypts a file using AES-256-CBC
- `decrypt_file(encrypted_file, password)`: Decrypts an AES-encrypted file
- `generate_key(password)`: Derives encryption key from password

#### stego_utils.py
- `hide_data(image_path, data, output_path)`: Hides binary data within an image
- `extract_data(image_path)`: Extracts hidden data from an image
- `get_max_hidden_size(image_path)`: Returns maximum bytes that can be hidden

#### main.py
- Command-line interface for the tool
- Coordinates encryption and steganography operations

## Security Notes

- **Password Security**: Use strong, unique passwords for encryption
- **Image Selection**: Use high-resolution images for better hiding capacity
- **Backup**: Always keep backups of original files before encryption

## Limitations

- Only supports PNG images for steganography
- Maximum hidden data size depends on image dimensions
- No integrity verification for extracted data

## Future Improvements

- [ ] Add support for additional image formats (JPEG, BMP)
- [ ] Implement integrity verification using checksums
- [ ] Add GUI interface
- [ ] Support for hiding multiple files
- [ ] Add compression before encryption
- [ ] Implement steganography detection resistance
- [ ] Add batch processing capabilities
- [ ] Support for audio/video steganography

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is open source and available under the [MIT License](LICENSE).

## Disclaimer

This tool is for educational and legitimate use only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this software.
