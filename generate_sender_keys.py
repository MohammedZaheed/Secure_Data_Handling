from Crypto.PublicKey import RSA

key = RSA.generate(2048)
with open("sender_private.pem", "wb") as f:
    f.write(key.export_key())
with open("sender_public.pem", "wb") as f:
    f.write(key.publickey().export_key())
