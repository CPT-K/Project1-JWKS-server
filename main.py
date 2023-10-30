"""
	Aurthor kmm0571 && chatGPT
	Course: CSCE 3550.004
	Date: 27 October 2023
	Filename: main.py
	Description: Program to implement a basic JWKS server
"""

import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

# Define the SQLite database file.
db_file = 'totally_not_my_privateKeys.db'

# Define the host name and server port for the HTTP server.
hostName = "localhost"
serverPort = 8080

# Create or open the SQLite database and create the keys table if it doesn't exist.
db_file = 'totally_not_my_privateKeys.db'
conn = sqlite3.connect(db_file)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')
conn.commit()
conn.close()

# Function to save a private key to the database.
def save_private_key(key, exp_timestamp):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (key, exp_timestamp))
    conn.commit()
    conn.close()

# Function to retrieve a private key from the database.
def get_private_key(expired=False):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    if expired:
        cursor.execute('SELECT key FROM keys WHERE exp < ?', (int(datetime.datetime.utcnow().timestamp()),))
    else:
        cursor.execute('SELECT key FROM keys WHERE exp >= ?', (int(datetime.datetime.utcnow().timestamp()),))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result[0]
    return None

# Function to convert an integer to a Base64URL-encoded string.
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Create a custom HTTP server by inheriting from BaseHTTPRequestHandler.
class MyServer(BaseHTTPRequestHandler):
    # Define unsupported HTTP methods (PUT, PATCH, DELETE, HEAD).
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    # Handle the HTTP POST method.
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                private_key = get_private_key(expired=True)  # Retrieve an expired key if the "expired" query parameter is present
            else:
                private_key = get_private_key()  # Retrieve an unexpired key
            if private_key:
                encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
                return
        # Return a 405 Method Not Allowed for other paths.
        self.send_response(405)
        self.end_headers()
        return

    # Handle the HTTP GET method.
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        # Return a 405 Method Not Allowed for other paths.
        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    # Start the HTTP server and handle requests.
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    # Close the server if interrupted.
    webServer.server_close()
