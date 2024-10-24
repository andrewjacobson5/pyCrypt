from Crypto.Publickey import RSA

def generate_key():
    key = RSA.generate(2048)
    privateKey = key.export_key()
    with open("private.pem", "wb") as f:
        f.write(privateKey)
    public_key = key.publickey().export_key()
    with open("receiver.pem", "wb") as f:
        f.write(public_key)