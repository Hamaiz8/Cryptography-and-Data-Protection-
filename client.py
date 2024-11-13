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