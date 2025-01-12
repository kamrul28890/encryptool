from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import base64

def blowfish_encrypt(text, key):
    """Encrypt text using Blowfish."""
    cipher = Blowfish.new(key.encode('utf-8'), Blowfish.MODE_ECB)
    encrypted = cipher.encrypt(pad(text.encode('utf-8'), Blowfish.block_size))
    return base64.b64encode(encrypted).decode('utf-8')

def blowfish_decrypt(encrypted_text, key):
    """Decrypt text using Blowfish."""
    cipher = Blowfish.new(key.encode('utf-8'), Blowfish.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), Blowfish.block_size)
    return decrypted.decode('utf-8')
