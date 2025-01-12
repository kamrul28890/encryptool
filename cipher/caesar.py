def caesar_encrypt(text, shift):
    encrypted = ''.join(
        chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else
        chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else char
        for char in text
    )
    return encrypted

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)
