from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'Ja50(G14P5)'
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = pbkdf2_sha256.hash(password)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password)

# Define Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.String(32), nullable=False)
    tag = db.Column(db.String(32), nullable=False)

# AES encryption functions
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(cipher.nonce).decode('utf-8'), base64.b64encode(tag).decode('utf-8')

def decrypt_message(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(nonce))
    plaintext = cipher.decrypt_and_verify(base64.b64decode(ciphertext), base64.b64decode(tag))
    return plaintext.decode('utf-8')

# Routes for user management
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token}), 200
    return jsonify({'message': 'Invalid username or password'}), 401

# Routes for messaging system
@app.route('/send_message', methods=['POST'])
@jwt_required()
def send_message():
    current_user = get_jwt_identity()  # Moved inside the route function
    data = request.get_json()
    recipient_username = data.get('recipient_username')
    content = data.get('content')
    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return jsonify({'message': 'Recipient not found'}), 404
    key = get_random_bytes(32)  # Generate AES key
    ciphertext, nonce, tag = encrypt_message(content.encode('utf-8'), key)
    new_message = Message(sender_id=current_user.id, recipient_id=recipient.id, content=ciphertext, nonce=nonce, tag=tag)
    db.session.add(new_message)
    db.session.commit()
    return jsonify({'message': 'Message sent successfully'}), 201

@app.route('/messages', methods=['GET'])
@jwt_required()
def get_messages():
    current_user = get_jwt_identity()
    key = get_random_bytes(32)  # Generate AES key for the user
    messages_sent = Message.query.filter_by(sender_id=current_user.id).all()
    messages_received = Message.query.filter_by(recipient_id=current_user.id).all()
    sent_messages = []
    received_messages = []
    for msg in messages_sent:
        plaintext = decrypt_message(msg.content, msg.nonce, msg.tag, key)
        sent_messages.append({'sender': current_user, 'recipient': User.query.get(msg.recipient_id).username, 'content': plaintext})
    for msg in messages_received:
        plaintext = decrypt_message(msg.content, msg.nonce, msg.tag, key)
        received_messages.append({'sender': User.query.get(msg.sender_id).username, 'recipient': current_user, 'content': plaintext})
    return jsonify({'sent_messages': sent_messages, 'received_messages': received_messages}), 200

@app.route('/')
def index():
    return app.send_static_file('index.html')

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)


