import socket
import threading
import logging
import time
import random
import re

# Logging configuration
logging.basicConfig(filename='honeypot_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Simulated services
class HoneypotServices:
    def __init__(self, host='ip address', port=8080):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = True

    def start(self):
        """Start the honeypot server to listen for incoming connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"Honeypot running on {self.host}:{self.port}")
            logging.info(f"Honeypot started on {self.host}:{self.port}")

            while self.running:
                client_socket, client_address = self.server_socket.accept()
                logging.info(f"Connection attempt from {client_address}")
                print(f"Connection attempt from {client_address}")

                # Handle the connection in a separate thread
                threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()

        except Exception as e:
            logging.error(f"Error starting honeypot: {e}")
            print(f"Error: {e}")

    def stop(self):
        """Stop the honeypot server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("Honeypot server stopped.")
        logging.info("Honeypot server stopped.")

    def handle_client(self, client_socket, client_address):
        """Handle incoming client connections and simulate different services"""
        try:
            # Simulate service (e.g., HTTP or FTP)
            request = client_socket.recv(1024).decode()
            if "GET" in request:
                self.handle_http(client_socket)
            elif "USER" in request and "PASS" in request:
                self.handle_ftp(client_socket, request)
            else:
                client_socket.send(b"Unknown service, closing connection...\n")
            client_socket.close()
        except Exception as e:
            logging.error(f"Error with client {client_address}: {e}")

    def handle_http(self, client_socket):
        """Simulate an HTTP service with a basic response"""
        http_response = """HTTP/1.1 200 OK
Content-Type: text/html

<html><body>
<h1>Welcome to the Honeypot!</h1>
<p>This is a simulated HTTP service.</p>
</body></html>"""
        client_socket.send(http_response.encode())

    def handle_ftp(self, client_socket, request):
        """Simulate an FTP service with basic commands"""
        if "USER" in request and "anonymous" in request:
            client_socket.send(b"230 Login successful.\n")
            self.handle_ftp_commands(client_socket)
        else:
            client_socket.send(b"530 Not logged in.\n")

    def handle_ftp_commands(self, client_socket):
        """Handle FTP commands (simulate vulnerability)"""
        while True:
            command = client_socket.recv(1024).decode().strip()
            if command.lower() == "quit":
                client_socket.send(b"221 Goodbye.\n")
                break
            elif command.lower() == "pwd":
                client_socket.send(b"257 \"/\" is the current directory.\n")
            elif "cd" in command:
                if "../" in command:
                    client_socket.send(b"550 Directory traversal not allowed.\n")
                else:
                    client_socket.send(b"250 Requested file action okay, completed.\n")
            else:
                client_socket.send(b"502 Command not implemented.\n")

    def simulate_attack(self, client_socket):
        """Simulate a weak password vulnerability (attack simulation)"""
        weak_passwords = ["12345", "password", "admin"]
        attempt = 0
        while attempt < 3:
            client_socket.send(b"Enter password: ")
            password = client_socket.recv(1024).decode().strip()
            if password in weak_passwords:
                client_socket.send(b"Login successful.\n")
                logging.info("Attack detected: Weak password login attempt.")
                return
            else:
                client_socket.send(b"Incorrect password.\n")
                attempt += 1
        client_socket.send(b"Too many incorrect attempts. Connection closing...\n")


# IDS/IPS Simulation
class HoneypotIDS:
    def __init__(self):
        self.failed_logins = {}

    def monitor_failed_logins(self, client_address):
        """Monitor failed login attempts from a specific IP address"""
        if client_address not in self.failed_logins:
            self.failed_logins[client_address] = 0
        self.failed_logins[client_address] += 1

        # If there are 3 failed attempts, we trigger an alert
        if self.failed_logins[client_address] >= 3:
            logging.warning(f"Potential brute-force attack detected from {client_address}")
            print(f"Brute-force attack detected from {client_address}.")
            self.failed_logins[client_address] = 0  # Reset after detection

    def monitor_traffic(self, client_address, request):
        """Basic traffic monitoring for attack patterns"""
        # Look for common attack patterns (e.g., SQL injection or shell command injection)
        attack_patterns = [
            "DROP TABLE", "--", ";", "/*", "*/", "bash", "rm -rf", "/etc/passwd"
        ]
        if any(pattern in request for pattern in attack_patterns):
            logging.warning(f"Suspicious activity detected from {client_address}: {request}")
            print(f"Suspicious activity detected: {request}")

# Main honeypot setup
if __name__ == "__main__":
    honeypot = HoneypotServices(host='ip address', port=8080)
    ids = HoneypotIDS()

    try:
        honeypot.start()
    except KeyboardInterrupt:
        honeypot.stop()

