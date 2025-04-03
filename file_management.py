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