import base64
from cipher.caesar import caesar_encrypt, caesar_decrypt
from symmetric.aes import aes_encrypt, aes_decrypt

def encrypt_file(filepath, key, algorithm):
    """Encrypt binary files (e.g., images, PDFs)."""
    with open(filepath, "rb") as file:
        file_data = file.read()

    if algorithm == "AES":
        if len(key) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 characters long!")
        encrypted_data = aes_encrypt(base64.b64encode(file_data).decode(), key).encode()
    elif algorithm == "Caesar Cipher":
        encrypted_data = caesar_encrypt(base64.b64encode(file_data).decode(), int(key)).encode()
    else:
        raise ValueError("Unsupported algorithm for file encryption.")

    output_path = f"{filepath}.enc"
    with open(output_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    return output_path


def decrypt_file(filepath, key, algorithm):
    """Decrypt binary files (e.g., images, PDFs)."""
    with open(filepath, "rb") as file:
        encrypted_data = file.read()

    if algorithm == "AES":
        if len(key) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 characters long!")
        decrypted_data = base64.b64decode(aes_decrypt(encrypted_data.decode(), key))
    elif algorithm == "Caesar Cipher":
        decrypted_data = base64.b64decode(caesar_decrypt(encrypted_data.decode(), int(key)))
    else:
        raise ValueError("Unsupported algorithm for file decryption.")

    output_path = filepath.replace(".enc", "_decrypted")
    with open(output_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    return output_path
