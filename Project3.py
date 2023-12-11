"""
	Aurthor kmm0571 && chatGPT
	Course: CSCE 3550.004
	Date: 29 September 2023
	Filename: server.py
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
from flask_bcrypt import Bcrypt  # Add this import
from flask_sqlalchemy import SQLAlchemy  # Add this import

# Define the SQLite database file.
db_file = 'totally_not_my_privateKeys.db'

# Define the host name and server port for the HTTP server.
hostName = "localhost"
serverPort = 8080

# Flask Configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///totally_not_my_privateKeys.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a strong secret key
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Create or open the SQLite database and create the keys table if it doesn't exist.
class Keys(db.Model):  # Update the database model
    kid = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.BLOB, nullable=False)
    exp = db.Column(db.Integer, nullable=False)

db.create_all()  # Create tables

# Function to save a private key to the database.
def save_private_key(key, exp_timestamp):
    new_key = Keys(key=key, exp=exp_timestamp)
    db.session.add(new_key)
    db.session.commit()

# Function to retrieve a private key from the database.
def get_private_key(expired=False):
    if expired:
        result = Keys.query.filter(Keys.exp < int(datetime.datetime.utcnow().timestamp())).first()
    else:
        result = Keys.query.filter(Keys.exp >= int(datetime.datetime.utcnow().timestamp())).first()
    if result:
        return result.key
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

# ... (Continue with the existing code)

# Registration Endpoint (Add this to your Flask app)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = str(uuid.uuid4())  # Generate a secure password using UUIDv4

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(username=username, email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'password': password}), 201

# Authentication Logging (Add this to your Flask app)
@app.route('/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data['username']
    password = data['password']
    request_ip = request.remote_addr

    # Your authentication logic here

    auth_log = AuthLog(request_ip=request_ip, user_id=user.id if user else None)
    db.session.add(auth_log)
    db.session.commit()

    return jsonify({'message': 'Authentication successful'}), 200
