import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def generate_secure_otp(length=6):
    """Generate a secure OTP with the specified number of digits."""
    return ''.join(str(int.from_bytes(os.urandom(1), 'big') % 10) for _ in range(length))

def send_email(recipient_email, number):
    """Send an OTP to the user's email address."""
    # SMTP server configuration
    smtp_server = "smtp.gmail.com"  # Use Gmail's SMTP server
    smtp_port = 587  # Port for TLS
    sender_email = "lhx20040727@gmail.com"  # Replace with your email address
    sender_password = "gdzcsfmnathgmyhz"  # Replace with your App Password

    try:
        # Create the email content
        subject = "Your OTP Verification Code"
        body = f"Your OTP verification code is: {number}"

        # Create a MIMEText email message
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = recipient_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        # Connect to the SMTP server and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Start TLS encryption
            server.login(sender_email, sender_password)  # Log in to the SMTP server
            server.sendmail(sender_email, recipient_email, message.as_string())  # Send the email

        print(f"Email sent successfully to {recipient_email}!")
    except Exception as e:
        print(f"Failed to send email: {e}")

def main():
    print("=== Email Verification Program ===")
    # Prompt the user for the recipient's email address
    recipient_email = input("Enter the recipient's email address: ")

    # Generate a secure 6-digit OTP
    verification_number = generate_secure_otp(length=6)

    # Send the email
    send_email(recipient_email, verification_number)

if __name__ == "__main__":
    main()