import socket

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