import os
import threading
import socket
from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(_name_)
messages = []
aes_key = None
client_socket = None

# AES Encryption and Decryption functions
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return plaintext

# RSA Decryption
def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Handle messages from the server and receive data
def handle_client(conn, private_key):
    global aes_key
    encrypted_aes_key = conn.recv(1024)
    aes_key = rsa_decrypt(private_key, encrypted_aes_key)

    def receive_messages():
        while True:
            encrypted_message = conn.recv(4096)
            if not encrypted_message:
                break
            message = aes_decrypt(aes_key, encrypted_message).decode()
            messages.append(f"Client: {message}")
            print(f"Received message: {message}")
            # Send a response back to the client
            response = "Message received"
            encrypted_response = aes_encrypt(aes_key, response.encode())
            conn.send(encrypted_response)

    threading.Thread(target=receive_messages, daemon=True).start()

    # Forward the Flask message to the client
    def send_flask_message_to_client(message):
        if client_socket:
            encrypted_message = aes_encrypt(aes_key, message.encode())
            client_socket.send(encrypted_message)

    return send_flask_message_to_client

# Start the server
def start_server():
    global client_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5001))  # Port 5001 for the server
    server_socket.listen(5)

    private_key, public_key = generate_rsa_keys()

    while True:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr}")
        client_socket = conn  # Store the client socket
        conn.send(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        send_flask_message_to_client = handle_client(conn, private_key)
        return send_flask_message_to_client  # This function will be used to send messages from Flask to the client

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Flask route for the index page
@app.route("/", methods=["GET", "POST"])
def index():
    global aes_key, client_socket
    send_message_function = None  # Reference for sending messages to client

    if request.method == "POST":
        user_message = request.form["message"]
        messages.append(f"You: {user_message}")
        
        # Send message to the client terminal
        if send_message_function:
            send_message_function(user_message)

        # Ensure socket is available
        if aes_key and client_socket and client_socket.fileno() != -1:
            try:
                encrypted_message = aes_encrypt(aes_key, user_message.encode())
                client_socket.send(encrypted_message)
            except BrokenPipeError:
                print("Connection closed. Cannot send message.")
                client_socket.close()
        else:
            print("Client socket is not available.")

    return render_template("index.html", messages=messages)

# Endpoint to get the latest messages (AJAX polling)
@app.route("/get_messages")
def get_messages():
    return jsonify(messages)

# Start both Flask and the socket server in separate threads
if _name_ == "_main_":
    threading.Thread(target=start_server, daemon=True).start()
    app.run(debug=True, use_reloader=False)  # Avoid reloader when using threads