from PIL import Image
import math

EOF_MARKER = b"###END###"  # To identify end of embedded data

def embed_data_into_image(image_path, data: bytes, output_path):
    data += EOF_MARKER  # append end marker
    binary_data = ''.join(format(byte, '08b') for byte in data)
    data_len = len(binary_data)

    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    encoded = img.copy()
    width, height = img.size

    if data_len > width * height * 3:
        raise ValueError("Data too large to embed in this image")

    idx = 0
    for y in range(height):
        for x in range(width):
            if idx >= data_len:
                break
            r, g, b = img.getpixel((x, y))
            r = (r & ~1) | int(binary_data[idx])
            idx += 1
            if idx < data_len:
                g = (g & ~1) | int(binary_data[idx])
                idx += 1
            if idx < data_len:
                b = (b & ~1) | int(binary_data[idx])
                idx += 1
            encoded.putpixel((x, y), (r, g, b))
        if idx >= data_len:
            break

    encoded.save(output_path, "PNG")
    return output_path

def extract_data_from_image(image_path):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    width, height = img.size
    bits = ""
    for y in range(height):
        for x in range(width):
            r, g, b = img.getpixel((x, y))
            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)

    all_bytes = [bits[i:i+8] for i in range(0, len(bits), 8)]
    data = bytearray()
    for byte in all_bytes:
        data.append(int(byte, 2))
        if data[-8:] == EOF_MARKER:
            break

    return bytes(data[:-8])  # remove EOF
