import socket
import os
from tkinter import Tk, Label, Button, filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def send_encrypted_file(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Step 1: Hash and sign
        h = SHA256.new(data)
        sender_private_key = RSA.import_key(open("sender_private.pem").read())
        signature = pkcs1_15.new(sender_private_key).sign(h)

        # Step 2: AES encryption
        aes_key = get_random_bytes(32)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))
        iv = cipher_aes.iv
        encrypted_data = iv + ciphertext

        # Step 3: Encrypt AES key with server's public RSA key
        server_public_key = RSA.import_key(open("server_public.pem").read())
        cipher_rsa = PKCS1_OAEP.new(server_public_key)
        enc_key = cipher_rsa.encrypt(aes_key)

        # Step 4: Send everything to server
        client = socket.socket()
        client.connect(('localhost', 9999))

        client.send(len(enc_key).to_bytes(4, 'big'))
        client.send(enc_key)

        client.send(len(signature).to_bytes(4, 'big'))
        client.send(signature)

        client.send(len(encrypted_data).to_bytes(8, 'big'))
        client.send(encrypted_data)

        client.close()
        messagebox.showinfo("Success", "File sent securely with signature.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        send_encrypted_file(file_path)

# GUI setup
def create_gui():
    root = Tk()
    root.title("Secure File Sender")
    root.geometry("300x200")

    Label(root, text="Secure File Transfer", font=("Arial", 14)).pack(pady=10)
    Button(root, text="Browse and Send File", width=25, command=browse_file).pack(pady=20)
    Button(root, text="Exit", width=25, command=root.quit).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
