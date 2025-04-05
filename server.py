import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def receive_all(sock, length):
    data = b''
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise Exception("Incomplete data")
        data += part
    return data

# Load keys once
server_private_key = RSA.import_key(open("server_private.pem").read())
sender_public_key = RSA.import_key(open("sender_public.pem").read())

# Start server
HOST = 'localhost'
PORT = 9999

with socket.socket() as server:
    server.bind((HOST, PORT))
    server.listen(5)
    print("Server ready on port 9999...")

    while True:
        conn, addr = server.accept()
        with conn:
            print(f"\n🔗 Connected by {addr}")
            try:
                # Decrypt AES key
                enc_key_len = int.from_bytes(conn.recv(4), 'big')
                enc_key = receive_all(conn, enc_key_len)
                cipher_rsa = PKCS1_OAEP.new(server_private_key)
                aes_key = cipher_rsa.decrypt(enc_key)

                # Receive digital signature
                sig_len = int.from_bytes(conn.recv(4), 'big')
                signature = receive_all(conn, sig_len)

                # Receive encrypted file data
                data_len = int.from_bytes(conn.recv(8), 'big')
                encrypted_data = receive_all(conn, data_len)

                # Decrypt file with AES
                iv = encrypted_data[:16]
                ciphertext = encrypted_data[16:]
                cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
                plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
                #Simulate tampering by altering the file after decryption
                plaintext = b"This file has been tampered with after encryption!"

                # Verify signature
                hash_obj = SHA256.new(plaintext)
                try:
                    pkcs1_15.new(sender_public_key).verify(hash_obj, signature)
                    print("Signature verified. File is authentic.")
                    with open("files/decrypted_output.txt", "wb") as f:
                        f.write(plaintext)
                    print("File decrypted and stored securely.")
                except (ValueError, TypeError):
                    print("Signature verification FAILED: File is tampered or untrusted!")
            except Exception as e:
                print(f"Error during processing: {e}")
