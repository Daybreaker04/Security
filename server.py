import socket
import os
import struct

HOST = '172.20.227.41'
PORT = 65432
BUFFER_SIZE = 1024

# Start the server to handle file uploads and downloads
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"Server started, listening on {HOST}:{PORT}...")
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from: {addr}")
        
        # Receive request length (4 bytes)
        length_bytes = client_socket.recv(4)
        if not length_bytes:
            client_socket.close()
            continue
        
        request_length = struct.unpack('>I', length_bytes)[0]
        request = client_socket.recv(request_length).decode('utf-8')
        
        if request.startswith("DOWNLOAD:"):
            # Handle download request
            requested_file = request.replace("DOWNLOAD:", "")
            file_path = os.path.join("server_files", requested_file)
            print(f"Download requested for: {requested_file}")
            
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    while True:
                        data = f.read(BUFFER_SIZE)
                        if not data:
                            break
                        client_socket.send(data)
                print(f"File {requested_file} sent successfully")
            else:
                print(f"File {requested_file} not found on server")
                client_socket.send(b"FILE_NOT_FOUND")
        else:
            # Handle upload request
            file_name = request
            print(f"Receiving encrypted file: {file_name}")
            
            file_path = os.path.join("server_files", file_name)
            with open(file_path, 'wb') as f:
                while True:
                    data = client_socket.recv(BUFFER_SIZE)
                    if not data:
                        break
                    f.write(data)
            
            print(f"Encrypted file {file_name} received successfully")
        
        client_socket.close()

if __name__ == "__main__":
    if not os.path.exists("server_files"):
        os.makedirs("server_files")
    start_server()