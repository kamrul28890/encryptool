import hashlib

def sha256_hash(text):
    hash_object = hashlib.sha256(text.encode('utf-8'))
    return hash_object.hexdigest()
