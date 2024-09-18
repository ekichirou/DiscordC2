from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import glob
import random
import os

enc_files = glob.glob("*image_*.zip.enc*")

if enc_files:
    print(f"Found files {enc_files}")
else:
    print(f"Missing encrypted files")
    os._exit(0)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def decrypt_file(password, input_file, output_file):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        salt = f_in.read(16)
        iv = f_in.read(16)
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        for chunk in iter(lambda: f_in.read(1024), b''):
            f_out.write(decryptor.update(chunk))

def combine_files(input_enc_file, output_zip_file):
    with open(output_zip_file, 'wb') as f_out:
        for i in range(100):
            chunk_files = glob.glob(f'{input_enc_file}.{i}')
            if not chunk_files:
                break
            for chunk_file in chunk_files:
                with open(chunk_file, 'rb') as f_chunk:
                    f_out.write(f_chunk.read())

input_enc_file = "image_*.zip.enc"
output_zip_file = f'exfil_files_{random.randint(1000, 9999)}.zip'

password = input("Enter encryption password: ")
combine_files(input_enc_file, 'combined.enc')
decrypt_file(password, 'combined.enc', output_zip_file)
print(f"Successfully decrypted into {output_zip_file}")

rem_files= glob.glob("*enc*")
for file_path in rem_files:
    os.remove(file_path)
    print(f"Removed file: {file_path}")
