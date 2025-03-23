from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import os

app = Flask(__name__)

# Secure key derivation using PBKDF2
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000

# Encrypt data using AES-256 (GCM mode for security)
def encrypt_data(text, password):
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

    encrypted_payload = base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()
    return encrypted_payload

# Decrypt data using AES-256
def decrypt_data(encrypted_text, password):
    try:
        data = base64.b64decode(encrypted_text)
        salt, nonce, tag, ciphertext = data[:SALT_SIZE], data[SALT_SIZE:SALT_SIZE+16], data[SALT_SIZE+16:SALT_SIZE+32], data[SALT_SIZE+32:]

        key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_text = cipher.decrypt_and_verify(ciphertext, tag).decode()

        return decrypted_text
    except Exception as e:
        return "Invalid Key or Data!"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json['text']
    password = request.json['password']
    encrypted_text = encrypt_data(data, password)
    return jsonify({'encrypted_text': encrypted_text})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_text = request.json['text']
    password = request.json['password']
    decrypted_text = decrypt_data(encrypted_text, password)
    return jsonify({'decrypted_text': decrypted_text})

if __name__ == '__main__':
    app.run(debug=True)
