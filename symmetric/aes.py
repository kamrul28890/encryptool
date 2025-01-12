from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def aes_encrypt(text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return base64.b64encode(encrypted).decode('utf-8')

def aes_decrypt(encrypted_text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size)
    return decrypted.decode('utf-8')
