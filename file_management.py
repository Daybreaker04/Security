import os
import sqlite3
import string
from threading import RLock
from datetime import datetime

# Global lock for database access
db_lock = RLock()

def log_operation(message):
    """Log critical operations to a text file with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get the current timestamp
    with open("server_log.txt", "a") as log_file:  # Open the log file in append mode
        log_file.write(f"[{timestamp}] {message}\n")  # Write the timestamp and message

def is_valid_filename(filename):
    """Validate the file name to prevent directory traversal and invalid characters."""
    if any(char in filename for char in ['/', '\\', '..']):
        return False
    valid_chars = set(string.ascii_letters + string.digits + '_-.')
    return all(char in valid_chars for char in filename) and len(filename) > 0

def handle_add_file(client_socket, username):
    """Handle adding a new file with single-line content input."""
    try:
        client_socket.send("Enter file name: ".encode())
        filename = client_socket.recv(1024).decode().strip()
        if not filename or not is_valid_filename(filename):
            client_socket.send("Error: Invalid file name.\n".encode())
            log_operation(f"File add failed: {username} provided invalid file name.")
            return

        client_socket.send("Enter file content (single line): ".encode())
        content = client_socket.recv(4096).decode().strip()
        if not content:
            client_socket.send("Error: File content cannot be empty.\n".encode())
            log_operation(f"File add failed: {username} provided empty content for file {filename}.")
            return

        file_path = f"files/{username}/{filename}"
        os.makedirs(f"files/{username}", exist_ok=True)

        with db_lock:
            conn = sqlite3.connect("userinfo.db")
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM files WHERE file_path = ?", (file_path,))
            if cursor.fetchone():
                client_socket.send("Error: File already exists.\n".encode())
                log_operation(f"File add failed: {username} tried to add duplicate file {filename}.")
                conn.close()
                return

            cursor.execute(
                "INSERT INTO files (filename, owner_username, file_path) VALUES (?, ?, ?)",
                (filename, username, file_path)
            )
            conn.commit()
            conn.close()

        with open(file_path, "w") as f:
            f.write(content)

        client_socket.send("File added successfully!\n".encode())
        log_operation(f"File added: {username} created file {filename}.")
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode())
        log_operation(f"File add failed: {username} encountered an error - {e}.")

def handle_edit_file(client_socket, username):
    """Handle editing an existing file."""
    try:
        client_socket.send("Enter file name to edit: ".encode())
        filename = client_socket.recv(1024).decode().strip()
        file_path = f"files/{username}/{filename}"

        with db_lock:
            conn = sqlite3.connect("userinfo.db")
            cursor = conn.cursor()
            cursor.execute("SELECT owner_username FROM files WHERE file_path = ?", (file_path,))
            result = cursor.fetchone()
            conn.close()

            if not result or result[0] != username:
                client_socket.send("Error: You can only edit your own files.\n".encode())
                log_operation(f"File edit failed: {username} tried to edit unauthorized file {filename}.")
                return

        if not os.path.exists(file_path):
            client_socket.send("Error: File does not exist.\n".encode())
            log_operation(f"File edit failed: {username} tried to edit non-existent file {filename}.")
            return

        client_socket.send("Enter new content: ".encode())
        new_content = client_socket.recv(4096).decode().strip()

        with open(file_path, "w") as f:
            f.write(new_content)

        client_socket.send("File edited successfully!\n".encode())
        log_operation(f"File edited: {username} modified file {filename}.")
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode())
        log_operation(f"File edit failed: {username} encountered an error - {e}.")

def handle_delete_file(client_socket, username):
    """Handle deleting an existing file."""
    try:
        client_socket.send("Enter file name to delete: ".encode())
        filename = client_socket.recv(1024).decode().strip()
        file_path = f"files/{username}/{filename}"

        with db_lock:
            conn = sqlite3.connect("userinfo.db")
            cursor = conn.cursor()
            cursor.execute("SELECT owner_username FROM files WHERE file_path = ?", (file_path,))
            result = cursor.fetchone()

            if not result or result[0] != username:
                client_socket.send("Error: You can only delete your own files.\n".encode())
                log_operation(f"File delete failed: {username} tried to delete unauthorized file {filename}.")
                conn.close()
                return

            cursor.execute("DELETE FROM files WHERE file_path = ?", (file_path,))
            conn.commit()
            conn.close()

        if os.path.exists(file_path):
            os.remove(file_path)

        client_socket.send("File deleted successfully!\n".encode())
        log_operation(f"File deleted: {username} removed file {filename}.")
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode())
        log_operation(f"File delete failed: {username} encountered an error - {e}.")

def handle_share_file(client_socket, username):
    """Handle sharing a file with another user."""
    try:
        client_socket.send("Enter file name to share: ".encode())
        filename = client_socket.recv(1024).decode().strip()
        file_path = f"files/{username}/{filename}"

        with db_lock:
            conn = sqlite3.connect("userinfo.db")
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM files WHERE file_path = ?", (file_path,))
            result = cursor.fetchone()

            if not result:
                client_socket.send("Error: File not found.\n".encode())
                log_operation(f"File share failed: {username} tried to share non-existent file {filename}.")
                conn.close()
                return

            file_id = result[0]
            client_socket.send("Enter username to share with: ".encode())
            share_with_username = client_socket.recv(1024).decode().strip()

            cursor.execute("SELECT username FROM users WHERE username = ?", (share_with_username,))
            if not cursor.fetchone():
                client_socket.send("Error: User does not exist.\n".encode())
                log_operation(f"File share failed: {username} tried to share file {filename} with non-existent user.")
                conn.close()
                return

            cursor.execute(
                "INSERT INTO shared_files (file_id, shared_with_username) VALUES (?, ?)",
                (file_id, share_with_username)
            )
            conn.commit()
            conn.close()

        client_socket.send(f"File shared successfully with {share_with_username}!\n".encode())
        log_operation(f"File shared: {username} shared file {filename} with {share_with_username}.")
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode())
        log_operation(f"File share failed: {username} encountered an error - {e}.")

def handle_read_file(client_socket, username):
    """Handle reading a file (own or shared)."""
    try:
        client_socket.send("Enter file name to read: ".encode())
        filename = client_socket.recv(1024).decode().strip()

        with db_lock:
            conn = sqlite3.connect("userinfo.db")
            cursor = conn.cursor()
            cursor.execute("SELECT file_path FROM files WHERE filename = ? AND owner_username = ?", (filename, username))
            result = cursor.fetchone()

            if not result:
                cursor.execute("""
                    SELECT f.file_path 
                    FROM files f 
                    JOIN shared_files sf ON f.id = sf.file_id 
                    WHERE f.filename = ? AND sf.shared_with_username = ?
                """, (filename, username))
                result = cursor.fetchone()

            conn.close()

        if not result or not os.path.exists(result[0]):
            client_socket.send("Error: File not found or access denied.\n".encode())
            log_operation(f"File read failed: {username} tried to access unauthorized or non-existent file {filename}.")
            return

        with open(result[0], "r") as f:
            content = f.read()

        client_socket.send(f"File content:\n{content}\n".encode())
        log_operation(f"File read: {username} accessed file {filename}.")
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode())
        log_operation(f"File read failed: {username} encountered an error - {e}.")

def handle_show_files(client_socket, username):
    """Handle showing the user's own files and files shared with them."""
    try:
        with db_lock:
            conn = sqlite3.connect("userinfo.db")
            cursor = conn.cursor()

            cursor.execute("SELECT filename FROM files WHERE owner_username = ?", (username,))
            own_files = cursor.fetchall()

            cursor.execute("""
                SELECT f.filename, f.owner_username 
                FROM files f 
                JOIN shared_files sf ON f.id = sf.file_id 
                WHERE sf.shared_with_username = ?
            """, (username,))
            shared_files = cursor.fetchall()

            conn.close()

        response = "Your Files:\n"
        response += "\n".join(f"- {file[0]}" for file in own_files) if own_files else "- None"
        response += "\n\nFiles Shared with You:\n"
        response += "\n".join(f"- {file[0]} (shared by {file[1]})" for file in shared_files) if shared_files else "- None"

        client_socket.send(response.encode())
        log_operation(f"Show files: {username} viewed their file list.")
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode())
        log_operation(f"Show files failed: {username} encountered an error - {e}.")

# Function to handle file upload from client
def handle_upload_file(client_socket, username):
    """Handle uploading a file from the client."""
    try:
        client_socket.send("Upload file ".encode())  # Prompt client for local file path
        local_file_path = client_socket.recv(1024).decode().strip()
        print(f"Received local file path: {local_file_path}")  # Debug to confirm receipt
        if local_file_path == "ERROR":  # Check if client reported an error
            client_socket.send("Error: Invalid file path on client side.\n".encode())
            return

        client_socket.send("Wait for new name ".encode())  # Prompt for server-side filename
        filename = client_socket.recv(1024).decode().strip()
        print(f"Received file name: '{filename}'")  # Debug to confirm receipt
        if not is_valid_filename(filename):  # Validate filename
            client_socket.send("Error: Invalid file name.\n".encode())
            log_operation(f"File upload failed: {username} provided invalid file name.")
            return

        file_content = client_socket.recv(4096).decode().strip()  # Receive file content
        print("Receive file content ")  # Debug to confirm content
        # Removed empty content check to allow empty files
        file_path = f"files/{username}/{filename}"  # Define server-side file path
        os.makedirs(f"files/{username}", exist_ok=True)  # Ensure directory exists

        with db_lock:  # Lock database access
            conn = sqlite3.connect("userinfo.db")
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM files WHERE file_path = ?", (file_path,))
            if cursor.fetchone():  # Check for duplicate file
                client_socket.send("Error: File already exists.\n".encode())
                log_operation(f"File upload failed: {username} tried to upload duplicate file {filename}.")
                conn.close()
                return
            # Insert file metadata into database
            cursor.execute(
                "INSERT INTO files (filename, owner_username, file_path) VALUES (?, ?, ?)",
                (filename, username, file_path)
            )
            conn.commit()
            conn.close()

        with open(file_path, "w", encoding='utf-8') as f:  # Specify encoding for consistency
            f.write(file_content)

        client_socket.send("File uploaded successfully!\n".encode())  # Notify client
        print(f"Sent success message to client for file: {filename}")  # Debug to confirm response sent
        log_operation(f"File uploaded: {username} uploaded file {filename}.")
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode())
        print(f"Error during upload: {e}")  # Debug to show error
        log_operation(f"File upload failed: {username} encountered an error - {e}.")

# Function to handle file download to client
def handle_download_file(client_socket, username):
    """Handle downloading a file to the client."""
    try:
        client_socket.send("Download file".encode())  # Prompt for filename
        filename = client_socket.recv(1024).decode().strip()

        with db_lock:  # Lock database access
            conn = sqlite3.connect("userinfo.db")
            cursor = conn.cursor()
            # Check if user owns the file
            cursor.execute("SELECT file_path FROM files WHERE filename = ? AND owner_username = ?", (filename, username))
            result = cursor.fetchone()
            if not result:  # Check if file is shared with user
                cursor.execute("""
                    SELECT f.file_path 
                    FROM files f 
                    JOIN shared_files sf ON f.id = sf.file_id 
                    WHERE f.filename = ? AND sf.shared_with_username = ?
                """, (filename, username))
                result = cursor.fetchone()
            conn.close()

        if not result or not os.path.exists(result[0]):  # Validate file existence and access
            client_socket.send("Error: File not found or access denied.\n".encode())
            log_operation(f"File download failed: {username} tried to download unauthorized or non-existent file {filename}.")
            return
        
        # Notify the client that the file was found
        client_socket.send("File found. Preparing to send content...\n".encode())

        # Wait for the client's confirmation message
        confirmation = client_socket.recv(1024).decode().strip()
        if confirmation != "Ready to receive file content":
            log_operation(f"File download aborted: {username} did not confirm readiness to receive file {filename}.")
            return

        with open(result[0], "r") as f:  # Read file content
            content = f.read()

        client_socket.send(content.encode())  # Send file content to client
        log_operation(f"File downloaded: {username} downloaded file {filename}.")
    except Exception as e:
        client_socket.send(f"Error: {e}\n".encode())
        log_operation(f"File download failed: {username} encountered an error - {e}.")
