import socket
import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

HOST = '172.20.227.41'
PORT = 65432
BUFFER_SIZE = 1024

# Generate an RSA key pair (private and public key)
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Generate a random AES key (256-bit)
def generate_aes_key():
    return os.urandom(32)

# Encrypt a file using AES-CBC
def encrypt_file(file_path, aes_key):
    iv = os.urandom(16)  # Generate a random IV (16 bytes)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    # Add PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext  # Return IV + ciphertext

# Decrypt a file using AES-CBC
def decrypt_file(ciphertext, aes_key):
    iv = ciphertext[:16]  # Extract IV
    encrypted_data = ciphertext[16:]
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext

# Encrypt AES key with RSA public key
def encrypt_aes_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Decrypt AES key with RSA private key
def decrypt_aes_key(encrypted_key, private_key):
    aes_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Upload an encrypted file to the server
def upload_file(file_path, public_key):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    
    # Generate AES key and encrypt the file
    aes_key = generate_aes_key()
    ciphertext = encrypt_file(file_path, aes_key)
    
    # Encrypt AES key with RSA public key
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
    
    # Send file name
    file_name = os.path.basename(file_path)
    file_name_bytes = file_name.encode('utf-8')
    client_socket.send(struct.pack('>I', len(file_name_bytes)))  # Send file name length
    client_socket.send(file_name_bytes)  # Send file name
    
    # Send encrypted AES key length and data
    client_socket.send(struct.pack('>I', len(encrypted_aes_key)))  # Send AES key length
    client_socket.send(encrypted_aes_key)  # Send encrypted AES key
    
    # Send encrypted file data
    for i in range(0, len(ciphertext), BUFFER_SIZE):
        chunk = ciphertext[i:i + BUFFER_SIZE]
        client_socket.send(chunk)
    
    print(f"Encrypted file {file_name} sent successfully")
    client_socket.close()
    return aes_key  # Return AES key for debugging (in practice, save it)

# Download and decrypt a file from the server
def download_file(file_name, private_key):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    
    # Send download request
    request = f"DOWNLOAD:{file_name}".encode('utf-8')
    client_socket.send(struct.pack('>I', len(request)))  # Send request length
    client_socket.send(request)  # Send request
    
    # Receive encrypted AES key length and data
    aes_key_length_bytes = client_socket.recv(4)
    aes_key_length = struct.unpack('>I', aes_key_length_bytes)[0]
    encrypted_aes_key = client_socket.recv(aes_key_length)
    
    # Receive encrypted file data
    ciphertext = b""
    while True:
        data = client_socket.recv(BUFFER_SIZE)
        if not data:
            break
        ciphertext += data
    
    # Decrypt AES key with RSA private key
    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
    
    # Decrypt the file
    plaintext = decrypt_file(ciphertext, aes_key)
    
    # Save the decrypted file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    save_path = os.path.join(script_dir, f"decrypted_{file_name}")
    with open(save_path, 'wb') as f:
        f.write(plaintext)
    
    print(f"File {file_name} downloaded and decrypted successfully as {save_path}")
    client_socket.close()

if __name__ == "__main__":
    # Generate RSA key pair (in practice, distribute public key to server)
    private_key, public_key = generate_rsa_key_pair()
    
    # Test uploading a file
    file_to_upload = "/Users/garywen/Desktop/PolyU/COMP3334/project/part2/test.txt"
    if os.path.exists(file_to_upload):
        upload_file(file_to_upload, public_key)
    else:
        print("File does not exist, please check the path!")
    
    # Test downloading a file
    download_file("test.txt", private_key)