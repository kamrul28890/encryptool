from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

def des_encrypt(text, key):
    """Encrypt text using DES."""
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text.encode('utf-8'), DES.block_size))
    return base64.b64encode(encrypted).decode('utf-8')

def des_decrypt(encrypted_text, key):
    """Decrypt text using DES."""
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), DES.block_size)
    return decrypted.decode('utf-8')
