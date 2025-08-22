# INTEGRATION STEPS FOR YOUR UEP PROJECT

## 1. UPDATE routes/__init__.py or Create routes/extended_routes.py

# routes/extended_routes.py
"""
Extended algorithm routes integration
"""

from flask import Blueprint, request, jsonify
import base64
import os
import sys
sys.path.append('..')  # To import from crypto folder

from crypto.extended_algorithms import (
    XChaCha20Poly1305Cipher,
    FF1AESCipher,
    Kyber768,
    EnigmaMachine,
    get_algorithm_info,
    list_new_algorithms
)
from utils.validators import validate_encryption_request
from crypto.utils import derive_key

extended_bp = Blueprint('extended', __name__, url_prefix='/api')

# XChaCha20-Poly1305 Routes
@extended_bp.route('/encrypt/xchacha20', methods=['POST'])
def encrypt_xchacha20():
    """Encrypt using XChaCha20-Poly1305"""
    try:
        data = request.get_json()
        
        # Use your existing validation
        if not validate_encryption_input(data):
            return jsonify({'error': 'Invalid input'}), 400
        
        plaintext = data['text'].encode('utf-8')
        password = data['password']
        
        # Use your existing key derivation
        salt = os.urandom(16)
        key = derive_key(password, salt)
        
        cipher = XChaCha20Poly1305Cipher()
        result = cipher.encrypt(plaintext, key)
        result['salt'] = base64.b64encode(salt).decode('utf-8')
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@extended_bp.route('/decrypt/xchacha20', methods=['POST'])
def decrypt_xchacha20():
    """Decrypt using XChaCha20-Poly1305"""
    try:
        data = request.get_json()
        
        salt = base64.b64decode(data['salt'])
        key = derive_key(data['password'], salt)
        
        cipher = XChaCha20Poly1305Cipher()
        plaintext = cipher.decrypt(
            data['ciphertext'],
            key,
            data['nonce']
        )
        
        return jsonify({'plaintext': plaintext.decode('utf-8')}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# FF1-AES Routes
@extended_bp.route('/encrypt/ff1', methods=['POST'])
def encrypt_ff1():
    """Format-preserving encryption"""
    try:
        data = request.get_json()
        plaintext = data['text']
        password = data['password']
        
        salt = os.urandom(16)
        key = derive_key(password, salt)
        
        cipher = FF1AESCipher()
        result = cipher.encrypt(plaintext, key)
        result['salt'] = base64.b64encode(salt).decode('utf-8')
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@extended_bp.route('/decrypt/ff1', methods=['POST'])
def decrypt_ff1():
    """Decrypt format-preserved text"""
    try:
        data = request.get_json()
        
        salt = base64.b64decode(data['salt'])
        key = derive_key(data['password'], salt)
        
        cipher = FF1AESCipher()
        plaintext = cipher.decrypt(data['ciphertext'], key)
        
        return jsonify({'plaintext': plaintext}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Kyber-768 Routes
@extended_bp.route('/kyber/generate', methods=['POST'])
def generate_kyber_keypair():
    """Generate post-quantum keypair"""
    try:
        kyber = Kyber768()
        private_key, public_key = kyber.generate_keypair()
        
        return jsonify({
            'private_key': base64.b64encode(private_key).decode('utf-8'),
            'public_key': base64.b64encode(public_key).decode('utf-8'),
            'algorithm': 'Kyber-768'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@extended_bp.route('/kyber/encapsulate', methods=['POST'])
def kyber_encapsulate():
    """Generate shared secret"""
    try:
        data = request.get_json()
        public_key = base64.b64decode(data['public_key'])
        
        kyber = Kyber768()
        shared_secret, ciphertext = kyber.encapsulate(public_key)
        
        return jsonify({
            'shared_secret': base64.b64encode(shared_secret).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Enigma Routes
@extended_bp.route('/encrypt/enigma', methods=['POST'])
def encrypt_enigma():
    """Historical Enigma encryption"""
    try:
        data = request.get_json()
        
        config = {
            'rotors': data.get('rotors', ['I', 'II', 'III']),
            'positions': data.get('positions', [0, 0, 0]),
            'plugboard': data.get('plugboard', {})
        }
        
        enigma = EnigmaMachine()
        result = enigma.encrypt(data['text'], config)
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@extended_bp.route('/decrypt/enigma', methods=['POST'])
def decrypt_enigma():
    """Enigma decryption"""
    try:
        data = request.get_json()
        
        enigma = EnigmaMachine()
        plaintext = enigma.decrypt(
            data['ciphertext'],
            data['configuration']
        )
        
        return jsonify({'plaintext': plaintext}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Algorithm Information Routes
@extended_bp.route('/algorithms/extended/list', methods=['GET'])
def list_extended():
    """List all new algorithms"""
    algorithms = []
    for name in list_new_algorithms():
        info = get_algorithm_info(name)
        algorithms.append(info)
    
    return jsonify({'algorithms': algorithms}), 200

@extended_bp.route('/algorithms/extended/<name>', methods=['GET'])
def get_algorithm_details(name):
    """Get specific algorithm details"""
    info = get_algorithm_info(name)
    if not info:
        return jsonify({'error': 'Algorithm not found'}), 404
    return jsonify(info), 200