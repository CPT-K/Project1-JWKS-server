"""
	Aurthor kmm0571 && chatGPT
	Course: CSCE 3550.004
	Date: 29 September 2023
	Filename: server.py
	Description: Program to implement a basic JWKS server
"""

import http.server
import socketserver
import json
from datetime import datetime, timedelta
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

# Generate RSA key pair with a Key ID (kid) and expiry timestamp
def generate_rsa_key_pair(kid, expiry_hours):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize private key to PEM format and encode as Base64
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_base64 = base64.b64encode(private_key_pem)

    # Get public key in JWK format
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    expiry_date = datetime.utcnow() + timedelta(hours=expiry_hours)
    return {
        'kid': kid,
        'expiry': expiry_date.timestamp(),
        'private_key': private_key_base64,
        'public_key': public_key
    }

# Function to generate JWT using the private key
def generate_jwt(private_key):
    # Decode Base64-encoded private key
    private_key_bytes = base64.b64decode(private_key)
    key = jwt.algorithms.RSAAlgorithm.from_pem(private_key_bytes)
    jwt_payload = {'sub': 'userABC', 'exp': datetime.utcnow() + timedelta(hours=1)}
    jwt_token = jwt.encode(jwt_payload, key, algorithm='RS256')
    return jwt_token

# Web Server Handlers
class JwksHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.command != 'GET':
            self.send_error(405, 'Method Not Allowed')
            return

        keys = [key['public_key'] for key in key_pairs if key['expiry'] > datetime.utcnow().timestamp()]
        jwks = {'keys': keys}
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.command != 'POST':
            self.send_error(405, 'Method Not Allowed')
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        credentials = json.loads(post_data.decode())

        # Mock authentication (replace with your actual authentication logic)
        if credentials.get('username') == 'userABC' and credentials.get('password') == 'password123':
            # Find an unexpired key
            unexpired_keys = [key for key in key_pairs if key['expiry'] > datetime.utcnow().timestamp()]
            if unexpired_keys:
                selected_key = unexpired_keys[0]
                jwt_token = generate_jwt(selected_key['private_key'])
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'token': jwt_token}).encode())
            else:
                self.send_error(500, 'No unexpired keys available')
        else:
            self.send_error(401, 'Unauthorized')

# Generate RSA key pair with a Key ID (kid) and expiry timestamp
key_pairs = [
    generate_rsa_key_pair(kid='key1', expiry_hours=1),
    generate_rsa_key_pair(kid='key2', expiry_hours=1)
]

# Set up the servers
port = 8080
jwks_handler = socketserver.TCPServer(("", port), JwksHandler)
auth_handler = socketserver.TCPServer(("", port + 1), AuthHandler)

# Run the servers
print(f"Starting JWKS server on port {port}")
jwks_handler.serve_forever()

print(f"Starting Auth server on port {port + 1}")
auth_handler.serve_forever()
