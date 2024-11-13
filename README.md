# Cryptography-and-Data-Protection-
# app.py
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

# client.py
import os
import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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

# RSA Encryption
def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Connect to server
def connect_to_server(ip, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ip, port))

    # Receive public key from server
    server_public_key_data = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_data, backend=default_backend())

    # Generate AES key and encrypt it with server public key
    aes_key = os.urandom(32)
    encrypted_aes_key = rsa_encrypt(server_public_key, aes_key)
    client_socket.send(encrypted_aes_key)

    def receive_messages():
        while True:
            try:
                encrypted_response = client_socket.recv(1024)
                if not encrypted_response:
                    break
                response = aes_decrypt(aes_key, encrypted_response).decode()
                print(f"Server: {response}")  # Print received message on client terminal
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    threading.Thread(target=receive_messages, daemon=True).start()

    return client_socket, aes_key

# Main function to start client
def main():
    client_socket, aes_key = connect_to_server('localhost', 5001)

    while True:
        user_message = input("Enter your message: ")
        encrypted_message = aes_encrypt(aes_key, user_message.encode())
        client_socket.send(encrypted_message)

if _name_ == "_main_":
    main()


# index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Chat</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #be2e82;
            color: #333;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .chat-container {
            width: 100%;
            max-width: 600px;
            background-color: #ffffff;
            box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.1);
            border-radius: 8px;
            overflow: hidden;
        }

        .header {
            background-color: #007bff;
            color: #ffffff;
            padding: 15px;
            text-align: center;
            font-size: 1.5em;
            font-weight: bold;
        }

        .messages {
            padding: 15px;
            max-height: 400px;
            overflow-y: auto;
        }

        .message {
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            font-size: 1em;
        }
        .message.user {
            background-color: #e7f3ff;
            text-align: right;
        }
        .message.server {
            background-color: #f1f1f1;
            text-align: left;
        }

        .message-form {
            display: flex;
            padding: 15px;
            border-top: 1px solid #ddd;
        }

        .message-input {
            flex: 1;
            padding: 10px;
            font-size: 1em;
            border: 1px solid #ddd;
            border-radius: 5px;
        }

        .send-btn {
            padding: 10px 15px;
            margin-left: 10px;
            background-color: #007bff;
            color: white;
            font-size: 1em;
            border: none;
            cursor: pointer;
            border-radius: 5px;
        }

        .send-btn:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="chat-container">
        <div class="header">Secure Chat</div>
        <div class="messages" id="messages">
            {% for message in messages %}
                <div class="message {% if 'You' in message %}user{% else %}server{% endif %}">{{ message }}</div>
            {% endfor %}
        </div>
        <form class="message-form" method="POST">
            <input type="text" name="message" class="message-input" placeholder="Enter your message" required>
            <button type="submit" class="send-btn">Send</button>
        </form>
    </div>

    <script>
        // Polling to check for new messages
        function fetchMessages() {
            fetch('/get_messages')
                .then(response => response.json())
                .then(data => {
                    const messagesContainer = document.getElementById('messages');
                    messagesContainer.innerHTML = ''; // Clear previous messages
                    data.forEach(message => {
                        const messageElement = document.createElement('div');
                        messageElement.classList.add('message');
                        if (message.includes('You:')) {
                            messageElement.classList.add('user');
                        } else {
                            messageElement.classList.add('server');
                        }
                        messageElement.textContent = message;
                        messagesContainer.appendChild(messageElement);
                    });
                });
        }

        // Poll every 2 seconds to update the chat
        setInterval(fetchMessages, 2000);
    </script>
</body>
</html>





# Execution steps:
1.	Save index.html to a folder named “templates”.
2.	Open one terminal and run app.py, you’ll get a link that will direct you to local host.
3.	Open another terminal and run client.py


