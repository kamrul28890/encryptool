from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64

def triple_des_encrypt(text, key):
    """Encrypt text using Triple DES."""
    key = DES3.adjust_key_parity(key.encode('utf-8'))
    cipher = DES3.new(key, DES3.MODE_ECB)
    encrypted = cipher.encrypt(pad(text.encode('utf-8'), DES3.block_size))
    return base64.b64encode(encrypted).decode('utf-8')

def triple_des_decrypt(encrypted_text, key):
    """Decrypt text using Triple DES."""
    key = DES3.adjust_key_parity(key.encode('utf-8'))
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), DES3.block_size)
    return decrypted.decode('utf-8')
