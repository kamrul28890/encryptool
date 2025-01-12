import unittest
from cipher.caesar import caesar_encrypt, caesar_decrypt

class TestCaesarCipher(unittest.TestCase):
    def test_encrypt(self):
        self.assertEqual(caesar_encrypt("HELLO", 3), "KHOOR")

    def test_decrypt(self):
        self.assertEqual(caesar_decrypt("KHOOR", 3), "HELLO")

if __name__ == "__main__":
    unittest.main()
