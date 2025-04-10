import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import base64
import secrets

def generate_key(file_name):
    """Generate and save a secure key for encryption."""
    # Ensure the "file_key" directory exists
    key_dir = "file_key"
    os.makedirs(key_dir, exist_ok=True)

    # Generate the key and save it in the "file_key" directory
    key = secrets.token_bytes(32)  # Generate a 256-bit key
    key_path = os.path.join(key_dir, f"{file_name}_key.txt")
    with open(key_path, 'wb') as key_file:
        key_file.write(key)
    return key

def load_key(file_name):
    """Load the encryption key from the key file."""
    key_dir = "file_key"
    key_path = os.path.join(key_dir, f"{file_name}_key.txt")
    with open(key_path, 'rb') as key_file:
        return key_file.read()

def encrypt_file_content(content, key):
    """Encrypt the file content using AES."""
    iv = secrets.token_bytes(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(content.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()  # Encode IV and ciphertext together

def decrypt_file_content(ciphertext, key):
    """Decrypt the file content using AES."""
    data = base64.b64decode(ciphertext)
    iv = data[:16]  # Extract the IV
    ciphertext = data[16:]  # Extract the actual ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode()

def handle_post_login_menu(client_socket):
    """Handle the post-login menu."""
    while True:
        # Receive and print the post-login menu from the server
        menu_prompt = client_socket.recv(1024).decode().strip()
        print(menu_prompt, end=" ")
        choice = input()
        client_socket.send(choice.encode())  # Send the choice to the server

        # Receive the server's response
        response = client_socket.recv(4096).decode().strip()

        if "Logging out" in response:
            print(response)
            return  # Return to the main menu
        elif "Shutting down" in response:
            print(response)
            exit()  # Terminate the client program
        elif "Server logs" in response:
            print("Server Logs:\n")
            print(response)  # Print the server logs
        elif "Download" in response:  # Handle file download
            download_file_from_server(client_socket)    
        elif "Upload" in response:  # Handle file upload
            upload_file_to_server(client_socket)
        elif "Enter file name" in response:
            handle_file_operations(client_socket, response)  # Handle file-related operations
        
        else:
            print(response)  # Print other responses (e.g., errors)

def handle_file_operations(client_socket, server_prompt):
    """
    Handle file-related operations such as adding, editing, deleting, sharing, reading, and showing files.

    Args:
        client_socket: The socket connected to the server.
        server_prompt: The initial prompt from the server for the file operation.
    """
    # Print the server's prompt and ask the user for the file name
    print(server_prompt, end=" ")
    file_name = input()

    # Send the file name to the server
    client_socket.send(file_name.encode())

    # Receive the next server response
    response = client_socket.recv(4096).decode().strip()

    if "Enter file content" in response:
        # Handle adding or editing a file
        print(response, end=" ")
        file_content = input()

        # Send the file content to the server
        client_socket.send(file_content.encode())

        # Receive and print the server's response (e.g., success or error message)
        response = client_socket.recv(4096).decode().strip()
        print(response)

    elif "Enter username to share with" in response:
        # Handle sharing a file
        print(response, end=" ")
        username = input()

        # Send the username to the server
        client_socket.send(username.encode())

        # Receive and print the server's response (e.g., success or error message)
        response = client_socket.recv(4096).decode().strip()
        print(response)

    elif "Your Files" in response or "File content" in response:
        # Handle showing files or reading a file
        print(response)

    else:
        # Handle any other server responses
        print(response)

def upload_file_to_server(client_socket):
    """Handle uploading a file to the server with encryption."""
    local_file_path = input("Enter the absolute local file path to upload: ").strip()
    if not os.path.exists(local_file_path):
        print(f"Error: File does not exist at '{local_file_path}'")
        client_socket.send("ERROR".encode())
        return
    if not local_file_path.endswith('.txt'):
        print("Error: Only .txt files are allowed.")
        client_socket.send("ERROR".encode())
        return

    try:
        with open(local_file_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        client_socket.send("ERROR".encode())
        return

    # Prompt the user for a new name to store the file on the server
    new_file_name = input("Enter the new name for the file to store on the server: ").strip()
    if not new_file_name:
        print("Error: The file name cannot be empty.")
        client_socket.send("ERROR".encode())
        return

    key = generate_key(new_file_name)  # Generate and save a key for this file
    encrypted_content = encrypt_file_content(file_content, key)  # Encrypt the file content

    client_socket.send(new_file_name.encode())  # Send the new file name
    response = client_socket.recv(4096).decode().strip()
    if "Wait for new name" in response:
        client_socket.send(new_file_name.encode())  # Send the new file name again
        client_socket.send(encrypted_content.encode())  # Send the encrypted content
        server_response = client_socket.recv(4096).decode().strip()
        print(server_response)

def download_file_from_server(client_socket):
    """Handle downloading a file from the server with decryption."""
    file_name = input("Enter the file name to download (without suffix .txt): ").strip()
    client_socket.send(file_name.encode())  # Send the file name to the server

    response = client_socket.recv(4096).decode().strip()
    
    if response == "File found. Preparing to send content...":  # Match the exact server response
        # Send confirmation to the server to proceed with sending the file content
        client_socket.send("Ready to receive file content".encode())

        encrypted_content = client_socket.recv(4096).decode().strip()

        # Prompt the user for a valid destination path
        while True:
            dest_path = input("Enter the local absolute destination path to save the file: ").strip()
            if os.path.isdir(dest_path):
                dest_path = os.path.join(dest_path, file_name)
                break
            else:
                print("Error: The specified path does not exist. Please enter a valid path.")

        if "Error" not in encrypted_content:
            try:
                key = load_key(file_name)  # Load the encryption key for this file
                decrypted_content = decrypt_file_content(encrypted_content, key)  # Decrypt the file content
                with open(dest_path, 'w', encoding='utf-8') as f:
                    f.write(decrypted_content)
                print(f"File downloaded and decrypted successfully to '{dest_path}'")
            except Exception as e:
                print(f"Error decrypting or saving file: {e}")
        else:
            print(encrypted_content)  # Print error message from the server
    else:
        print(response)  # Print the server's response if the file is not found

def main():
    # Ask user for the server IP address
    server_ip = input("Enter the server IP address (e.g., 192.168.1.1): ")
    # The port should match the one used by the server
    server_port = 8888

    try:
        # Create a TCP/IP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the server's IP address and port
        client_socket.connect((server_ip, server_port))

        while True:  # Main menu loop
            # Receive initial message from the server (includes the choice prompt)
            welcome_message = client_socket.recv(1024).decode().strip()  # Strip any extra newlines
            print(welcome_message, end=" ")  # Print the server's message with a space

            # Let the user choose an option (1: Register, 2: Login, 3: Reset Password)
            option = input()  # The prompt is already included in the server's message
            client_socket.send(option.encode())  # Send the chosen option to the server

            if option == "1":  # Register
                while True:
                    # Receive the server's prompt
                    server_prompt = client_socket.recv(1024).decode().strip()

                    # Check if the server is asking for the username
                    if "Enter username" in server_prompt:
                        print(server_prompt, end=" ")
                        username = input()
                        client_socket.send(username.encode())  # Send the username to the server

                    # Check if the server is asking for the password
                    elif "Enter password" in server_prompt:
                        print(server_prompt, end=" ")
                        password = input()
                        client_socket.send(password.encode())  # Send the password to the server

                    # Check if the server is asking for the email address
                    elif "Enter email address" in server_prompt:
                        print(server_prompt, end=" ")
                        email = input()
                        client_socket.send(email.encode())  # Send the email to the server

                    # Check if the server sent a success message
                    elif "Registration successful" in server_prompt:
                        print(server_prompt)
                        break  # Exit the loop if registration is successful

                    # Handle error messages from the server
                    elif "Error" in server_prompt:
                        print(server_prompt)  # Print the error message and continue the loop

            elif option == "2":  # Login
                while True:  # Loop until login is successful
                    # Receive and print the username prompt from the server
                    server_response = client_socket.recv(1024).decode().strip()
                    if "Enter username" in server_response:
                        print(server_response, end=" ")
                        username = input()
                        client_socket.send(username.encode())  # Send the username to the server
                    elif "Choose login method" in server_response:
                        # Receive and print the login method prompt from the server
                        print(server_response, end=" ")
                        login_method = input()
                        client_socket.send(login_method.encode())  # Send the chosen login method to the server

                        if login_method == "1":  # Password login
                            # Receive and print the password prompt from the server
                            password_prompt = client_socket.recv(1024).decode().strip()
                            print(password_prompt, end=" ")
                            password = input()
                            client_socket.send(password.encode())  # Send the password to the server

                        elif login_method == "2":  # OTP login
                            # Receive and print the OTP prompt from the server
                            otp_prompt = client_socket.recv(1024).decode().strip()
                            print(otp_prompt, end=" ")
                            otp = input()
                            client_socket.send(otp.encode())  # Send the OTP to the server

                        # Receive the server's response
                        response = client_socket.recv(1024).decode().strip()
                        print(response)
                        if "Login successful" in response:
                            handle_post_login_menu(client_socket)  # Call the post-login menu
                            break  # Exit the login loop
                    elif "Error" in server_response:
                        # Handle error messages from the server
                        print(server_response)  # Print the error message and continue the loop
                    else:
                        # Handle unexpected server responses
                        print(f"Unexpected response from server: {server_response}")

            elif option == "3":  # Reset Password
                while True:  # Loop until password reset is successful
                    # Receive and print the username prompt from the server
                    username_prompt = client_socket.recv(1024).decode().strip()
                    print(username_prompt, end=" ")
                    username = input()
                    client_socket.send(username.encode())  # Send the username to the server

                    # Receive and print the original password prompt from the server
                    original_password_prompt = client_socket.recv(1024).decode().strip()
                    print(original_password_prompt, end=" ")
                    original_password = input()
                    client_socket.send(original_password.encode())  # Send the original password to the server

                    # Receive and print the new password prompt from the server
                    new_password_prompt = client_socket.recv(1024).decode().strip()
                    if "Enter new password" in new_password_prompt:
                        print(new_password_prompt, end=" ")
                        new_password = input()
                        client_socket.send(new_password.encode())  # Send the new password to the server

                    # Receive the server's response
                    response = client_socket.recv(1024).decode().strip()
                    print(response)
                    if "Password reset successful" in response:
                        break  # Exit the loop if password reset is successful

            else:
                print("Invalid option. Please try again.")

    except ConnectionRefusedError:
        # Handle the case where the server is not running or cannot be reached
        print("Error: Unable to connect to the server. Make sure the server is running.")
    except Exception as e:
        # Handle any other exceptions that may occur
        print(f"An error occurred: {e}")
    finally:
        # Close the client socket
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    # Run the main function
    main()