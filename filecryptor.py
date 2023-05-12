import argparse
import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
...
class FileEncryptor:
    def __init__(self, password=None, algorithm="AES", key_size=32, iterations=100000):
        self.password = password
        self.algorithm = algorithm
        self.key_size = key_size
        self.iterations = iterations
        self.backend = default_backend()

    def generate_key_from_password(self, password, salt):
        # Paroladan anahtar üret
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(password)

    def encrypt_file(self, file_name):
        # Dosyayı şifrele
        salt = os.urandom(16)
        key = self.generate_key_from_password(self.password.encode(), salt)
        cipher = Cipher(getattr(algorithms, self.algorithm)(key), modes.CBC(os.urandom(16)), backend=self.backend)

        with open(file_name, "rb") as file:
            file_data = file.read()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(file_name + ".encrypted", "wb") as file:
            file.write(salt + encrypted_data)

    def decrypt_file(self, file_name):
        # Dosyayı çöz
        with open(file_name, "rb") as file:
            data = file.read()

        salt = data[:16]
        encrypted_data = data[16:]

        key = self.generate_key_from_password(self.password.encode(), salt)
        cipher = Cipher(getattr(algorithms, self.algorithm)(key), modes.CBC(os.urandom(16)), backend=self.backend)

        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        with open(file_name[:-10], "wb") as file:
            file.write(unpadded_data)

    def process_file(self, file_name, encrypt=False, decrypt=False, remove=False):
        if encrypt and decrypt:
            print("Error: Encrypt and decrypt option specified at the same time.")
            return

        if self.password and (encrypt or decrypt):
            if encrypt:
                self.encrypt_file(file_name)
                print(f"{file_name} file is encrypted.")

                if remove:
                    os.remove(file_name)
                    print(f"{file_name} file deleted.")

            elif decrypt:
                if file_name.endswith(".encrypted"):
                    self.decrypt_file(file_name)
                    print(f"{file_name} file resolved.")

                    if remove:
                        os.remove(file_name)
                        print(f"{file_name} file deleted.")
                else:
                    print("Error: Invalid encrypted filename.")

        else:
            print("Error: No password specified.")


def main():
    parser = argparse.ArgumentParser(description="File encryption and decryption tool")
    parser.add_argument("dosya_adi", help="The name of the file you want to encrypt or decrypt")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt file")
    parser.add_argument("-d", "--decrypt", action="store_true", help="decode file")
    parser.add_argument("-p", "--password", help="Password to use")
    parser.add_argument("-r", "--remove", action="store_true", help="delete original file")
    parser.add_argument("-a", "--algorithm", default="AES", help="The encryption algorithm to be used")

    args = parser.parse_args()

    file_encryptor = FileEncryptor(password=args.password, algorithm=args.algorithm)

    file_encryptor.process_file(args.dosya_adi, encrypt=args.encrypt, decrypt=args.decrypt, remove=args.remove)


if __name__ == "__main__":
    main()
