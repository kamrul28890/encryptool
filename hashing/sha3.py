import hashlib

def sha3_hash(text):
    """Generate SHA-3 hash of the given text."""
    hash_object = hashlib.sha3_256(text.encode('utf-8'))
    return hash_object.hexdigest()
