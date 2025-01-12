import os
import random

def secure_delete(filepath, passes=3):
    """Securely delete a file by overwriting it with random data."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"The file '{filepath}' does not exist.")

    file_size = os.path.getsize(filepath)
    with open(filepath, "wb") as file:
        for _ in range(passes):
            file.write(random.randbytes(file_size))

    os.remove(filepath)
