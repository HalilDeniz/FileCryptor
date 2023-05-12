
# FileCryptor

FileCryptor is a command-line tool for encrypting and decrypting files securely. It uses AES encryption algorithm with CBC mode to provide strong encryption for your files.

## Features

- File Encryption: Encrypts the specified file and generates an encrypted file.
- File Decryption: Decrypts an encrypted file and restores the original file.
- Password-Based Encryption: Uses a password provided by the user to derive the encryption key.
- Automatic Key Generation: If no password is provided, the program automatically generates a random encryption key.
- File Removal Option: Allows automatic deletion of the original file after encryption or decryption.
- Error Handling: Provides informative error messages and ensures proper termination of the program.
- Multiple Encryption Algorithms: Currently supports the AES algorithm with CBC mode. The code can be extended to support other cryptographic algorithms.
- Key Management: Supports key generation, loading, and storing operations using a file-based key management system.
- Progress Indicator: Provides progress indication during encryption or decryption of large files or slow operations.
- Error Handling: Handles file read/write errors, encryption/decryption errors, and other exceptional situations.


## Installation

To install FileCryptor, you can simply clone the repository from GitHub:

```
git clone https://github.com/HalilDeniz/FileCryptor.git
```

## Requirements

Before you can use FileCryptor, you need to make sure that you have the necessary requirements installed. You can install these requirements by running the following command:

```
pip install -r requirements.txt
```

## Getting Started
```
To use FileCryptor, simply run the following command:
root@denizhalil:~/PycharmProjects/pythonProject/myProject/FileCryptor# python3 filecryptor.py --help
usage: filecryptor.py [-h] [-e] [-d] [-p PASSWORD] [-r] [-a ALGORITHM] dosya_adi

File encryption and decryption tool

positional arguments:
  dosya_adi             The name of the file you want to encrypt or decrypt

options:
  -h, --help            show this help message and exit
  -e, --encrypt         Encrypt file
  -d, --decrypt         decode file
  -p PASSWORD, --password PASSWORD
                        Password to use
  -r, --remove          delete original file
  -a ALGORITHM, --algorithm ALGORITHM
                        The encryption algorithm to be used
```

## Usage

Encrypt a file:

1. Encrypt a file with a password:

```shell
python filecryptor.py --encrypt --file document.txt --password mysecretpassword
```

This command encrypts the `document.txt` file with the password "mysecretpassword" and generates an encrypted file.

2. Decrypt an encrypted file with a password:

```shell
python filecryptor.py --decrypt --file document.txt.encrypted --password mysecretpassword --remove
```

This command decrypts the `document.txt.encrypted` file using the password "mysecretpassword" and removes the original encrypted file after decryption.

3. Encrypt a file with automatic key generation:

```shell
python filecryptor.py --encrypt --file sensitive.docx
```

This command encrypts the `sensitive.docx` file using an automatically generated encryption key. When no password is provided, the program automatically generates a random key.

4. Encrypt a file with a different encryption algorithm:

```shell
python filecryptor.py --encrypt --file data.txt --password mypassword --algorithm AES256
```

This command encrypts the `data.txt` file with the password "mypassword" using the AES256 encryption algorithm.

5. Decrypt a file without removing the original file:

```shell
python filecryptor.py --decrypt --file confidential.txt.encrypted --password mypass
```

This command decrypts the `confidential.txt.encrypted` file using the password "mypass" and keeps the original encrypted file intact.

6. Encrypt multiple files with the same password:

```shell
python filecryptor.py --encrypt --file file1.txt file2.txt file3.txt --password sharedpassword
```

This command encrypts multiple files `file1.txt`, `file2.txt`, and `file3.txt` with the same password "sharedpassword" in a single encryption operation.

These examples demonstrate different usage scenarios for the FileCryptor program, showcasing its flexibility and functionality for file encryption and decryption tasks.
## Contact

If you have any questions, comments, or suggestions about Tool Name, please feel free to contact me:

- LinkedIn: https://www.linkedin.com/in/halil-ibrahim-deniz/
- TryHackMe: https://tryhackme.com/p/halilovic
- Instagram: https://www.instagram.com/deniz.halil333/
- YouTube: https://www.youtube.com/c/HalilDeniz
- Email: halildeniz313@gmail.com

## License

Tool Name is released under the MIT License. See LICENSE for more information.