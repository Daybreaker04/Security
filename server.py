import socket
import sqlite3
import threading
import requests
import bcrypt
import re  # Import re for email validation
from OTP_Email_sender import generate_secure_otp, send_email  # Import OTP functions
from datetime import datetime  # Import datetime for timestamps
# Import file management functions
from file_management import (
    handle_add_file,
    handle_edit_file,
    handle_delete_file,
    handle_share_file,
    handle_read_file,
    handle_show_files,
    handle_upload_file,
    handle_download_file 
)

# Global lock for database access
db_lock = threading.RLock()

# Flag to indicate if the server should keep running
server_running = True

# Email validation function
def is_valid_email(email):
    """Validate the email address using a regular expression."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def log_operation(message):
    """Log critical operations to a text file with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get the current timestamp
    with open("server_log.txt", "a") as log_file:  # Open the log file in append mode
        log_file.write(f"[{timestamp}] {message}\n")  # Write the timestamp and message

# Database setup
def setup_database():
    # Connect to the SQLite database (creates the file if it doesn't exist)
    conn = sqlite3.connect("userinfo.db")
    cursor = conn.cursor()
    # Create the users table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            account_type TEXT NOT NULL DEFAULT 'normal'  -- Default account type is 'normal'
        )
    """)

    # Create files table to track file ownership
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            owner_username TEXT NOT NULL,
            file_path TEXT NOT NULL,
            FOREIGN KEY (owner_username) REFERENCES users(username)
        )
    """)

    # Create shared_files table to manage file sharing
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            shared_with_username TEXT NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id),
            FOREIGN KEY (shared_with_username) REFERENCES users(username)
        )
    """)

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

# Handle client requests (registration, login, password reset)
def handle_client(client_socket):
    try:
        while True:  # Loop to allow the client to return to the main menu after logging out
            # Send welcome message to the client with numeric options
            client_socket.send(
                "Welcome! Please choose an option:\n"
                "1. Register\n"
                "2. Login\n"
                "3. Reset Password\n"
                "Enter your choice (1/2/3): ".encode()
            )
            
            # Receive the client's choice
            choice = client_socket.recv(1024).decode().strip()

            if choice == "1":
                handle_registration(client_socket)
            elif choice == "2":
                handle_login(client_socket)
            elif choice == "3":
                handle_password_reset(client_socket)
            else:
                client_socket.send("Invalid option. Please try again.\n".encode())
    except Exception as e:
        print(f"An error occurred while handling the client: {e}")
    finally:
        # Close the client socket
        client_socket.close()
        print("Client connection closed.")

# Handle client registration
def handle_registration(client_socket):
    try:
        while True:  # Loop until the user successfully registers
            # Prompt the client for a username
            client_socket.send("Enter username: ".encode())
            username = client_socket.recv(1024).decode().strip()

            # Prompt the client for a password
            client_socket.send("Enter password: ".encode())
            password = client_socket.recv(1024).decode().strip()

            # Prompt the client for an email address
            while True:
                client_socket.send("Enter email address: ".encode())
                email = client_socket.recv(1024).decode().strip()

                # Validate the email address
                if is_valid_email(email):
                    break  # Exit the loop if the email is valid
                else:
                    client_socket.send("Error: Invalid email address. Please try again.\n".encode())
                    print(f"Invalid email address provided: {email}")  # Debugging statement

            # Hash the password using bcrypt
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            # Use the lock to ensure exclusive access to the database
            with db_lock:
                try:
                    # Connect to the SQLite database
                    conn = sqlite3.connect("userinfo.db")
                    cursor = conn.cursor()

                    # Insert the new user into the users table with the hashed password and email
                    cursor.execute(
                        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                        (username, hashed_password.decode(), email),
                    )

                    # Commit the changes and close the connection
                    conn.commit()
                    conn.close()

                    # Notify the client of successful registration
                    client_socket.send("Registration successful!\n".encode())
                    print(f"User {username} registered successfully with email {email}.")  # Debugging statement

                    # Log the registration event
                    log_operation(f"Registration: User {username} registered successfully with email {email}.")
                    break  # Exit the loop if registration is successful
                except sqlite3.IntegrityError:
                    # Notify the client if the username already exists
                    client_socket.send("Error: Username already exists. Try again.\n".encode())
                    print(f"Registration failed: Username {username} already exists.")  # Debugging statement
                    log_operation(f"Registration failed: Username {username} already exists.")
    except Exception as e:
        # Handle any unexpected errors during registration
        client_socket.send(f"Error: {e}\n".encode())
        print(f"An error occurred during registration: {e}")  # Debugging statement
        log_operation(f"An error occurred during registration for user {username}: {e}")

# Handle client login
def handle_login(client_socket):
    try:
        while True:  # Loop until the user provides valid credentials
            # Prompt the client for a username
            client_socket.send("Enter username: ".encode())
            username = client_socket.recv(1024).decode().strip()

            # Use the lock to ensure exclusive access to the database
            with db_lock:
                # Connect to the SQLite database
                conn = sqlite3.connect("userinfo.db")
                cursor = conn.cursor()
                # Retrieve the hashed password and email for the given username
                cursor.execute("SELECT password, email FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                conn.close()

            if result:
                stored_hashed_password, email = result

                # Prompt the client to choose login method
                client_socket.send(
                    "Choose login method:\n"
                    "1. Password\n"
                    "2. OTP (sent to your registered email)\n"
                    "Enter your choice (1/2): ".encode()
                )
                login_method = client_socket.recv(1024).decode().strip()

                if login_method == "1":  # Password login
                    # Prompt the client for a password
                    client_socket.send("Enter password: ".encode())
                    password = client_socket.recv(1024).decode().strip()

                    # Verify the provided password against the stored hashed password
                    if bcrypt.checkpw(password.encode(), stored_hashed_password.encode()):
                        # Notify the client of successful login
                        client_socket.send("Login successful! Welcome back.\n".encode())
                        print(f"User {username} logged in successfully using password.")  # Debugging statement
                        log_operation(f"Login: User {username} logged in successfully using password.")
                        post_login_menu(client_socket, username)  # Show post-login menu
                        break  # Exit the loop
                    else:
                        # Notify the client of failed login and allow retry
                        client_socket.send("Error: Invalid password. Please try again.\n".encode())
                        print(f"Login failed for user {username}: Incorrect password.")  # Debugging statement
                        log_operation(f"Login failed: User {username} entered an incorrect password.")

                elif login_method == "2":  # OTP login
                    # Generate a secure OTP
                    otp = generate_secure_otp(length=6)

                    # Send the OTP to the user's registered email
                    send_email(email, otp)

                    # Prompt the client to enter the OTP
                    client_socket.send("Enter the OTP sent to your registered email: ".encode())
                    entered_otp = client_socket.recv(1024).decode().strip()

                    # Verify the OTP
                    if entered_otp == otp:
                        # Notify the client of successful login
                        client_socket.send("Login successful! Welcome back.\n".encode())
                        print(f"User {username} logged in successfully using OTP.")  # Debugging statement
                        log_operation(f"Login: User {username} logged in successfully using OTP.")
                        post_login_menu(client_socket, username)  # Show post-login menu
                        break  # Exit the loop
                    else:
                        # Notify the client of failed OTP verification
                        client_socket.send("Error: Invalid OTP. Please try again.\n".encode())
                        print(f"Login failed for user {username}: Incorrect OTP.")  # Debugging statement
                        log_operation(f"Login failed: User {username} entered an incorrect OTP.")

                else:
                    # Notify the client of invalid login method
                    client_socket.send("Error: Invalid login method. Please try again.\n".encode())
                    print(f"Login failed for user {username}: Invalid login method.")  # Debugging statement
                    log_operation(f"Login failed: User {username} selected an invalid login method.")
            else:
                # Notify the client if the username does not exist
                client_socket.send("Error: Username does not exist. Please try again.\n".encode())
                print(f"Login failed: Username {username} does not exist.")  # Debugging statement
                log_operation(f"Login failed: Username {username} does not exist.")
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode())
        print(f"An error occurred during login: {e}")  # Debugging statement
        log_operation(f"An error occurred during login for user {username}: {e}")

# Handle password reset
def handle_password_reset(client_socket):
    try:
        while True:  # Loop until the user provides valid credentials
            # Prompt the client for a username
            client_socket.send("Enter username: ".encode())
            username = client_socket.recv(1024).decode().strip()
            # Prompt the client for the original password
            client_socket.send("Enter original password: ".encode())
            original_password = client_socket.recv(1024).decode().strip()

            # Use the lock to ensure exclusive access to the database
            with db_lock:
                # Connect to the SQLite database
                conn = sqlite3.connect("userinfo.db")
                cursor = conn.cursor()
                # Retrieve the hashed password for the given username
                cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()

                if result:
                    stored_hashed_password = result[0]
                    # Verify the provided original password against the stored hashed password
                    if bcrypt.checkpw(original_password.encode(), stored_hashed_password.encode()):
                        # Prompt the client for a new password
                        client_socket.send("Enter new password: ".encode())
                        new_password = client_socket.recv(1024).decode().strip()
                        # Hash the new password
                        new_hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                        # Update the password for the given username
                        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_hashed_password.decode(), username))
                        conn.commit()
                        conn.close()
                        # Notify the client of successful password reset
                        client_socket.send("Password reset successful!\n".encode())
                        print(f"Password reset successful for user {username}.")  # Debugging statement
                        break  # Exit the loop
                    else:
                        # Notify the client of failed verification and allow retry
                        client_socket.send("Error: Invalid username or original password. Please try again.\n".encode())
                        print(f"Password reset failed for user {username}: Incorrect original password.")  # Debugging statement
                else:
                    # Notify the client if the username does not exist
                    client_socket.send("Error: Invalid username or original password. Please try again.\n".encode())
                    print(f"Password reset failed: Username {username} does not exist.")  # Debugging statement
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode())
        print(f"An error occurred during password reset: {e}")  # Debugging statement

# Function to listen for shutdown command
def listen_for_commands():
    """Listen for server commands such as shutdown or promoting users."""
    global server_running
    print("Type 'shutdown' to terminate the server or 'promote' to promote a user to administrator.")
    while True:
        command = input("> ").strip()
        if command.lower() == "shutdown":
            server_running = False
            print("Shutting down the server...")
            break
        elif command.lower() == "promote":
            # Display a list of all usernames
            try:
                with db_lock:
                    conn = sqlite3.connect("userinfo.db")
                    cursor = conn.cursor()
                    cursor.execute("SELECT username FROM users")
                    users = cursor.fetchall()
                    conn.close()

                if users:
                    print("List of users:")
                    for user in users:
                        print(f"- {user[0]}")
                else:
                    print("No users found in the database.")
                    continue  # Skip the rest of the loop if no users are found

                # Prompt the admin to enter a username to promote
                username = input("Enter the username to promote to administrator: ").strip()
                if username:
                    promote_to_admin(username)  # Call promote_to_admin outside the lock
                else:
                    print("Error: No username entered.")
            except Exception as e:
                print(f"An error occurred while retrieving users: {e}")
        else:
            print("Invalid command. Available commands: 'shutdown', 'promote'")

def post_login_menu(client_socket, username):
    """Show the post-login menu to the client."""
    try:
        # Check the user's account type once, outside the loop
        with db_lock:
            conn = sqlite3.connect("userinfo.db")
            cursor = conn.cursor()
            cursor.execute("SELECT account_type FROM users WHERE username = ?", (username,))
            account_type = cursor.fetchone()[0]
            conn.close()

        while True:
            # Send the post-login menu options
            # NEW CODE START: Updated menu with upload and download options
            if account_type == "admin":
                client_socket.send(
                    "Post-login Menu:\n"
                    "1. Add file\n"
                    "2. Edit file\n"
                    "3. Delete file\n"
                    "4. Share file\n"
                    "5. Read file\n"
                    "6. Show files\n"
                    "7. Upload file\n"  
                    "8. Download file\n"  
                    "9. Log out\n"
                    "10. Shut down\n"
                    "11. Access server logs\n"
                    "Enter your choice (1-11): ".encode()
                )
            else:
                client_socket.send(
                    "Post-login Menu:\n"
                    "1. Add file\n"
                    "2. Edit file\n"
                    "3. Delete file\n"
                    "4. Share file\n"
                    "5. Read file\n"
                    "6. Show files\n"
                    "7. Upload file\n" 
                    "8. Download file\n"  
                    "9. Log out\n"
                    "10. Shut down\n"
                    "Enter your choice (1-10): ".encode()
                )
            # NEW CODE END

            # Receive the client's choice
            choice = client_socket.recv(1024).decode().strip()

            # Handle file-related options
            if choice == "1":
                handle_add_file(client_socket, username)
            elif choice == "2":
                handle_edit_file(client_socket, username)
            elif choice == "3":
                handle_delete_file(client_socket, username)
            elif choice == "4":
                handle_share_file(client_socket, username)
            elif choice == "5":
                handle_read_file(client_socket, username)
            elif choice == "6":
                handle_show_files(client_socket, username)
            # NEW CODE START: Handle new upload and download choices
            elif choice == "7":
                handle_upload_file(client_socket, username)  # Call upload function
            elif choice == "8":
                handle_download_file(client_socket, username)  # Call download function
            # NEW CODE END
            # Handle logout, shutdown, and access logs
            elif choice == "9":
                # Log out: Break the loop and return to the main menu
                client_socket.send("Logging out...\n".encode())
                print("Client has logged out and returned to the main menu.")  # Log the logout event
                log_operation(f"Log out: User {username} logged out.")
                break
            elif choice == "10":
                # Shut down: Close the connection and terminate the client
                client_socket.send("Shutting down the client...\n".encode())
                client_socket.close()
                print(f"User {username} chose to shut down and disconnected.")  # Log the shutdown event
                log_operation(f"Shut down: User {username} chose to shut down and disconnected.")
                return
            elif choice == "11" and account_type == "admin":
                # Access server logs: Send the log file to the client
                try:
                    with open("server_log.txt", "r") as log_file:
                        logs = log_file.read()  # Read the entire log file
                    client_socket.send(logs.encode())  # Send the logs to the client
                    print(f"Server logs sent to administrator {username}.")  # Debugging statement
                    log_operation(f"Server logs accessed by administrator {username}.")
                except FileNotFoundError:
                    client_socket.send("Error: Log file not found.\n".encode())
                    print("Error: Log file not found.")  # Debugging statement
            else:
                # Invalid option or unauthorized access
                client_socket.send("Invalid option or unauthorized access. Please try again.\n".encode())
    except Exception as e:
        print(f"An error occurred in the post-login menu: {e}")
        log_operation(f"An error occurred in the post-login menu for user {username}: {e}")

def promote_to_admin(username):
    """Promote a normal user to an administrator."""
    print(f"Attempting to promote user: {username}")  # Debugging statement
    
    with db_lock:
        try:
        
            # Connect to the SQLite database
            conn = sqlite3.connect("userinfo.db")
            cursor = conn.cursor()

            # Debugging: Print the SQL query and parameters
            print(f"Executing SQL: UPDATE users SET account_type = 'admin' WHERE username = '{username}'")

            # Update the account type to 'admin' for the given username
            cursor.execute("UPDATE users SET account_type = 'admin' WHERE username = ?", (username,))
            if cursor.rowcount > 0:
                conn.commit()
                print(f"User {username} has been promoted to administrator.")
                log_operation(f"Promotion: User {username} has been promoted to administrator.")
            else:
                print(f"Error: User {username} does not exist.")
        except Exception as e:
            print(f"An error occurred while promoting user {username} to administrator: {e}")
        finally:
            conn.close()

# Main server function
def start_server():
    global server_running

    # Set up the database
    setup_database()

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to all available interfaces on port 8888
    server_socket.bind(("0.0.0.0", 8888))
    # Listen for incoming connections (up to 5 simultaneous connections)
    server_socket.listen(5)
    print("Server is running and listening for connections...")

    # Get the local IP address
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    # Get the public IP address
    public_ip = requests.get('https://api.ipify.org').text
    
    # Print the URLs to access the server
    print(f"Access the server at:")
    print(f"  Local: http://{local_ip}:8888/")
    print(f"  Public: http://{public_ip}:8888/")

    # Start a thread to listen for server commands
    command_thread = threading.Thread(target=listen_for_commands)
    command_thread.start()

    # Set a timeout for the server socket to allow periodic checks of the server_running flag
    server_socket.settimeout(1.0)

    while server_running:
        try:
            # Accept a new connection (with timeout)
            client_socket, addr = server_socket.accept()
            print(f"Connection received from {addr}")
            # Create a new thread to handle the client
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()
        except socket.timeout:
            # Timeout occurs if no connection is received within the timeout period
            # This allows the loop to check the server_running flag
            continue
        except Exception as e:
            print(f"An error occurred while accepting a connection: {e}")

    # Close the server socket
    server_socket.close()
    print("Server has been shut down.")



if __name__ == "__main__":
    # Start the server
    start_server()