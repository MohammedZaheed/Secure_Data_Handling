# 🔐 Secure Data Handling System

This project demonstrates secure file handling using cryptographic techniques. It includes:

✅ **(a) Secure Data Storage**  
✅ **(b) Secure Data Transmission**  
✅ **(c) Digital Signature Creation and Verification**

A GUI-based client is used to sign and encrypt the file, which is sent to a server that decrypts and verifies it before storing.

---

## 📽️ Demo Video

🎬 [Watch the Full Demo](https://your-video-link-here.com)  
*(Replace this link with your YouTube/Drive video after uploading)*

---

## 🚀 Features Implemented

### ✅ (a) Secure Data Storage

**Goal:** Ensure that data is stored only after its integrity and authenticity are confirmed.

**Working:**
- The server receives an encrypted payload from the client.
- The payload includes:
  - Encrypted file data (AES)
  - Encrypted AES key (RSA)
  - Digital signature
- The server performs:
  1. Decrypts the AES key using its private RSA key.
  2. Verifies the signature using the sender's public key.
  3. If valid, decrypts the file using AES and stores it inside the `files/` directory.

**Security Mechanism:**
- Files are not stored unless they pass verification.
- Ensures authenticity and integrity before storage.

---

### ✅ (b) Secure Data Transmission

**Goal:** Transmit data securely over a network to prevent interception or tampering.

**Working:**
- Client generates a random AES-256 key and encrypts the file.
- AES key is encrypted using the server’s RSA public key.
- File and signature are sent over sockets in a secure payload.

**Security Mechanism:**
- AES for fast, secure file encryption.
- RSA for secure AES key exchange.
- Protects data in transit from eavesdropping and MITM attacks.

---

### ✅ (c) Digital Signature Creation and Verification

**Goal:** Ensure the file has not been modified and is sent by a trusted source.

**Working:**
- Client computes a SHA-256 hash of the file and signs it using its RSA private key.
- Server uses sender’s public key to verify the signature by comparing it with the received file’s hash.

**Security Mechanism:**
- Unforgeable signature confirms the sender’s identity.
- Ensures file integrity — any modification is detectable.

---

## 🗂️ Project Structure

```
secure_data_project/
├── gui_client.py               # Client GUI for file selection and sending
├── server.py                   # Server that receives, verifies, decrypts and stores files
├── generate_keys.py            # Generates server's RSA key pair
├── generate_sender_keys.py     # Generates sender's RSA key pair
├── server_public.pem
├── server_private.pem
├── sender_public.pem
├── sender_private.pem
├── files/                      # Stores verified, decrypted files
│   └── decrypted_output.txt
```

---

## ⚙️ Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/MohammedZaheed/Secure_Data_Handling.git
cd Secure_Data_Handling
```

### 2. Create Virtual Environment
```bash
python -m venv venv
# Activate the environment:
venv\Scripts\activate      # On Windows
source venv/bin/activate   # On Linux/macOS
```

### 3. Install Dependencies
```bash
pip install pycryptodome
```

### 4. Generate RSA Keys
```bash
python generate_keys.py
python generate_sender_keys.py
```

### 5. Create Output Folder
```bash
mkdir files
```

---

## ▶️ How to Run

### Step 1: Start the Server
```bash
python server.py
```

### Step 2: Launch the GUI Client (in a new terminal)
```bash
python gui_client.py
```

### Step 3: Use the GUI to:
- Select a file from your system  
- The client will:
  - Digitally sign the file
  - Encrypt it using AES
  - Encrypt AES key with RSA
  - Send the secure payload to the server  
- The server will:
  - Decrypt the AES key
  - Verify the digital signature
  - Decrypt and store the file if valid

### Output:
- Decrypted file is saved at: `files/decrypted_output.txt`  
- The terminal logs show step-by-step results for encryption, signing, transmission, decryption, and verification

---

## 📜 Requirements

- Python 3.6 or higher
- `pycryptodome`
- `tkinter` (usually bundled with Python)

---
