def vigenere_encrypt(text, key):
    key = (key * (len(text) // len(key) + 1))[:len(text)]
    encrypted = ''.join(
        chr((ord(t) + ord(k) - 2 * 65) % 26 + 65) if t.isupper() else
        chr((ord(t) + ord(k) - 2 * 97) % 26 + 97) if t.islower() else t
        for t, k in zip(text, key)
    )
    return encrypted

def vigenere_decrypt(text, key):
    key = (key * (len(text) // len(key) + 1))[:len(text)]
    decrypted = ''.join(
        chr((ord(t) - ord(k)) % 26 + 65) if t.isupper() else
        chr((ord(t) - ord(k)) % 26 + 97) if t.islower() else t
        for t, k in zip(text, key)
    )
    return decrypted
