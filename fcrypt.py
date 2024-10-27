# This code is primarily based on examples from the official
# PyCryptodome website (https://www.pycryptodome.org/src/examples)
# Adjustments have been made to fit the specific requirements of this program, 
# but the core structure and logic are derived from the referenced examples.

import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open("private.pem", "wb") as file:
        file.write(private_key)
    public_key = key.publickey().export_key()
    with open("receiver.pem", "wb") as file:
        file.write(public_key)

def encrypt_file(public_key_file, input_file, output_file):
    recipient_key = RSA.import_key(open(public_key_file).read())
    session_key = get_random_bytes(16)  

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    with open(input_file, "rb") as file:
        data = file.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    with open(output_file, "wb") as file:
        file.write(enc_session_key)
        file.write(cipher_aes.nonce)
        file.write(tag)
        file.write(ciphertext)

def decrypt_file(private_key_file, input_file, output_file):
    private_key = RSA.import_key(open(private_key_file).read())

    with open(input_file, "rb") as file:
        enc_session_key = file.read(private_key.size_in_bytes())
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()
    
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    with open(output_file, "wb") as file:
        file.write(data)

def main():
    arg = sys.argv[1]

    if arg == "--generate-keys":
        generate_keys()
    elif arg == "--encrypt" and len(sys.argv) == 5:
        key_file = sys.argv[2]
        input_file = sys.argv[3]
        output_file = sys.argv[4]
        encrypt_file(key_file, input_file, output_file)
    elif arg == "--decrypt" and len(sys.argv) == 5:
        key_file = sys.argv[2]
        input_file = sys.argv[3]
        output_file = sys.argv[4]
        decrypt_file(key_file, input_file, output_file)
    else:
        print("Usage:")
        print("python3 fcrypt.py --generate-keys")
        print("python3 fcrypt.py --encrypt <receiver-public-key> <plaintext-file> <encrypted-file>")
        print("python3 fcrypt.py --decrypt <receiver-private-key> <encrypted-file> <decrypted-file>")

if __name__ == "__main__":
    main()
