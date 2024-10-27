import sys
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)
    public_key = key.publickey().export_key()
    with open("receiver.pem", "wb") as f:
        f.write(public_key)
    print("Key pair generated: private.pem and receiver.pem")

def load_rsa_key(key_file, is_private=False):
    with open(key_file, 'rb') as f:
        key_data = f.read()
    return RSA.import_key(key_data)

def encrypt_file(public_key_file, input_file, output_file):
    

    print("Encryption Successful.")

def decrypt_file(private_key_file, input_file, output_file):
    
    print("Decryption Successful.")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("python3 fcrypt.py --generate-keys")
        print("python3 fcrypt.py --encrypt <receiver-public-key> <plaintext-file> <encrypted-file>")
        print("python3 fcrypt.py --decrypt <receiver-private-key> <encrypted-file> <decrypted-file>")
        sys.exit(1)

    operation = sys.argv[1]

    if operation == "--generate-keys":
        generate_key()
    elif operation == "--encrypt" and len(sys.argv) == 5:
        key_file = sys.argv[2]
        input_file = sys.argv[3]
        output_file = sys.argv[4]
        encrypt_file(key_file, input_file, output_file)
    elif operation == "--decrypt" and len(sys.argv) == 5:
        key_file = sys.argv[2]
        input_file = sys.argv[3]
        output_file = sys.argv[4]
        decrypt_file(key_file, input_file, output_file)
    else:
        print("Invalid operation or incorrect number of arguments.")

if __name__ == "__main__":
    main()
