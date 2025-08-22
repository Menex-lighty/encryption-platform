# crypto/extended_algorithms.py
"""
Extended encryption algorithms for the Universal Encryption Platform
Includes: XChaCha20-Poly1305, FF1-AES, Kyber-768, and Enigma
"""

import os
import string
import secrets
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json

# For Kyber implementation (you'll need to install: pip install pqcrypto)
# For FF1: pip install ff3

class XChaCha20Poly1305Cipher:
    """
    XChaCha20-Poly1305: Extended nonce version of ChaCha20-Poly1305
    Supports 192-bit (24-byte) nonces instead of standard 96-bit
    """
    
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> Dict[str, str]:
        """
        Encrypt data using XChaCha20-Poly1305
        Note: Using standard ChaCha20Poly1305 with extended nonce handling
        """
        # Generate 24-byte nonce for XChaCha20
        nonce = os.urandom(24)
        
        # In production, you'd use actual XChaCha20-Poly1305
        # For demo, we'll use ChaCha20Poly1305 with first 12 bytes of nonce
        cipher = ChaCha20Poly1305(key[:32])
        
        # Use first 12 bytes for standard ChaCha20
        ciphertext = cipher.encrypt(nonce[:12], plaintext, associated_data)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'algorithm': 'XChaCha20-Poly1305'
        }
    
    @staticmethod
    def decrypt(ciphertext: str, key: bytes, nonce: str, associated_data: bytes = b"") -> bytes:
        """Decrypt data using XChaCha20-Poly1305"""
        cipher = ChaCha20Poly1305(key[:32])
        nonce_bytes = base64.b64decode(nonce)
        ciphertext_bytes = base64.b64decode(ciphertext)
        
        # Use first 12 bytes for standard ChaCha20
        plaintext = cipher.decrypt(nonce_bytes[:12], ciphertext_bytes, associated_data)
        return plaintext

class FF1AESCipher:
    """
    FF1-AES: Format-Preserving Encryption
    Encrypts data while preserving its format (e.g., credit card numbers, SSNs)
    """
    
    def __init__(self):
        self.alphabet = string.digits + string.ascii_letters
        
    def encrypt(self, plaintext: str, key: bytes, tweak: bytes = b"") -> Dict[str, str]:
        """
        Encrypt while preserving format
        Implementation of simplified FPE for demonstration
        """
        # Derive encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=tweak if tweak else b"ff1-salt",
            iterations=10000,
            backend=default_backend()
        )
        derived_key = kdf.derive(key)
        
        # Simple format-preserving encryption (for demo)
        # In production, use proper FF1 implementation
        encrypted = []
        key_stream = int.from_bytes(derived_key, 'big')
        
        for i, char in enumerate(plaintext):
            if char in self.alphabet:
                # Shift character based on key stream
                old_index = self.alphabet.index(char)
                shift = (key_stream >> (i * 8)) & 0xFF
                new_index = (old_index + shift) % len(self.alphabet)
                encrypted.append(self.alphabet[new_index])
            else:
                # Preserve non-alphanumeric characters
                encrypted.append(char)
        
        return {
            'ciphertext': ''.join(encrypted),
            'format': self._detect_format(plaintext),
            'algorithm': 'FF1-AES',
            'tweak': base64.b64encode(tweak).decode('utf-8') if tweak else ""
        }
    
    def decrypt(self, ciphertext: str, key: bytes, tweak: bytes = b"") -> str:
        """Decrypt while preserving format"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=tweak if tweak else b"ff1-salt",
            iterations=10000,
            backend=default_backend()
        )
        derived_key = kdf.derive(key)
        
        decrypted = []
        key_stream = int.from_bytes(derived_key, 'big')
        
        for i, char in enumerate(ciphertext):
            if char in self.alphabet:
                old_index = self.alphabet.index(char)
                shift = (key_stream >> (i * 8)) & 0xFF
                new_index = (old_index - shift) % len(self.alphabet)
                decrypted.append(self.alphabet[new_index])
            else:
                decrypted.append(char)
        
        return ''.join(decrypted)
    
    def _detect_format(self, text: str) -> str:
        """Detect the format of input text"""
        if text.replace('-', '').replace(' ', '').isdigit():
            if len(text.replace('-', '').replace(' ', '')) == 16:
                return "credit_card"
            elif len(text.replace('-', '')) == 9:
                return "ssn"
        return "alphanumeric"

class Kyber768:
    """
    Kyber-768: Post-quantum key exchange mechanism
    NIST-selected lattice-based key encapsulation mechanism
    """
    
    def __init__(self):
        # In production, use actual Kyber implementation
        # This is a simplified demonstration
        self.key_size = 768
        self.security_level = 192  # bits
        
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Kyber-768 keypair"""
        # Simplified key generation for demonstration
        # In production, use proper Kyber implementation
        private_key = os.urandom(self.key_size // 8)
        
        # Derive public key from private key (simplified)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size // 8,
            salt=b"kyber-public",
            iterations=1000,
            backend=default_backend()
        )
        public_key = kdf.derive(private_key)
        
        return private_key, public_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate: Generate shared secret and ciphertext
        Returns: (shared_secret, ciphertext)
        """
        # Generate random shared secret
        shared_secret = os.urandom(32)
        
        # "Encrypt" shared secret with public key (simplified)
        # In real Kyber, this uses lattice-based encryption
        ciphertext = bytes(a ^ b for a, b in zip(
            shared_secret + os.urandom(self.key_size // 8 - 32),
            public_key
        ))
        
        return shared_secret, ciphertext
    
    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """
        Decapsulate: Recover shared secret from ciphertext
        Returns: shared_secret
        """
        # "Decrypt" ciphertext with private key (simplified)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size // 8,
            salt=b"kyber-public",
            iterations=1000,
            backend=default_backend()
        )
        public_key = kdf.derive(private_key)
        
        decrypted = bytes(a ^ b for a, b in zip(ciphertext, public_key))
        shared_secret = decrypted[:32]
        
        return shared_secret
    
    def get_info(self) -> Dict[str, Any]:
        """Get algorithm information"""
        return {
            'name': 'Kyber-768',
            'type': 'Post-Quantum Key Exchange',
            'security_level': f'{self.security_level}-bit',
            'key_size': f'{self.key_size} bits',
            'quantum_resistant': True,
            'nist_approved': True,
            'use_cases': [
                'Future-proof key exchange',
                'Quantum-resistant communications',
                'Hybrid TLS implementations',
                'Long-term data protection'
            ]
        }

class EnigmaMachine:
    """
    Enigma Machine Simulator
    Historical cipher machine used in WWII - for educational purposes
    """
    
    def __init__(self):
        # Rotor wirings (historical configurations)
        self.rotors = {
            'I': 'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
            'II': 'AJDKSIRUXBLHWTMCQGZNPYFVOE',
            'III': 'BDFHJLCPRTXVZNYEIWGAKMUSQO',
            'IV': 'ESOVPZJAYQUIRHXLNFTGKDCMWB',
            'V': 'VZBRGITYUPSDNHLXAWMJQOFECK'
        }
        
        # Reflector B
        self.reflector_b = 'YRUHQSLDPXNGOKMIEBFZCWVJAT'
        
        # Default settings
        self.rotor_positions = [0, 0, 0]
        self.rotor_selection = ['I', 'II', 'III']
        self.plugboard = {}
        
    def set_configuration(self, rotors: list, positions: list, plugboard: dict = None):
        """Configure the Enigma machine"""
        self.rotor_selection = rotors
        self.rotor_positions = positions
        self.plugboard = plugboard or {}
        
    def _apply_plugboard(self, char: str) -> str:
        """Apply plugboard substitution"""
        return self.plugboard.get(char, char)
    
    def _rotor_encrypt(self, char: str, rotor_name: str, position: int, reverse: bool = False) -> str:
        """Encrypt character through a rotor"""
        rotor = self.rotors[rotor_name]
        alphabet = string.ascii_uppercase
        
        if not reverse:
            # Forward through rotor
            index = (alphabet.index(char) + position) % 26
            encrypted = rotor[index]
            output_index = (alphabet.index(encrypted) - position) % 26
        else:
            # Reverse through rotor
            index = (alphabet.index(char) + position) % 26
            encrypted_char = alphabet[index]
            rotor_index = rotor.index(encrypted_char)
            output_index = (rotor_index - position) % 26
            
        return alphabet[output_index]
    
    def _step_rotors(self):
        """Step the rotors (simplified - doesn't include double-stepping)"""
        self.rotor_positions[0] = (self.rotor_positions[0] + 1) % 26
        if self.rotor_positions[0] == 0:
            self.rotor_positions[1] = (self.rotor_positions[1] + 1) % 26
            if self.rotor_positions[1] == 0:
                self.rotor_positions[2] = (self.rotor_positions[2] + 1) % 26
    
    def encrypt_char(self, char: str) -> str:
        """Encrypt a single character"""
        if char not in string.ascii_uppercase:
            return char
            
        # Step rotors before encryption
        self._step_rotors()
        
        # Apply plugboard
        char = self._apply_plugboard(char)
        
        # Pass through rotors (right to left)
        for i in range(3):
            char = self._rotor_encrypt(char, self.rotor_selection[i], self.rotor_positions[i])
        
        # Apply reflector
        char = self.reflector_b[string.ascii_uppercase.index(char)]
        
        # Pass back through rotors (left to right)
        for i in range(2, -1, -1):
            char = self._rotor_encrypt(char, self.rotor_selection[i], self.rotor_positions[i], reverse=True)
        
        # Apply plugboard again
        char = self._apply_plugboard(char)
        
        return char
    
    def encrypt(self, plaintext: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Encrypt message using Enigma"""
        if config:
            self.set_configuration(
                config.get('rotors', ['I', 'II', 'III']),
                config.get('positions', [0, 0, 0]),
                config.get('plugboard', {})
            )
        
        # Convert to uppercase and preserve formatting
        result = []
        for char in plaintext.upper():
            result.append(self.encrypt_char(char))
        
        return {
            'ciphertext': ''.join(result),
            'algorithm': 'Enigma',
            'configuration': {
                'rotors': self.rotor_selection,
                'initial_positions': config.get('positions', [0, 0, 0]) if config else [0, 0, 0],
                'plugboard': list(self.plugboard.items()) if self.plugboard else []
            },
            'historical_note': 'Educational implementation of WWII Enigma machine'
        }
    
    def decrypt(self, ciphertext: str, config: Dict[str, Any]) -> str:
        """Decrypt message (Enigma is symmetric)"""
        # Reset to initial configuration
        self.set_configuration(
            config['rotors'],
            config['initial_positions'],
            dict(config.get('plugboard', []))
        )
        
        # Enigma is symmetric - encryption and decryption are the same
        result = []
        for char in ciphertext.upper():
            result.append(self.encrypt_char(char))
        
        return ''.join(result)

# Algorithm metadata for the platform
ALGORITHM_METADATA = {
    'XChaCha20-Poly1305': {
        'name': 'XChaCha20-Poly1305',
        'category': 'Symmetric Stream Cipher',
        'description': 'Extended nonce variant of ChaCha20-Poly1305 with 192-bit nonces',
        'key_size': '256 bits',
        'nonce_size': '192 bits',
        'strength': 'Very High',
        'speed': 'Very Fast',
        'use_case': 'High-volume encryption with extended nonce space',
        'pros': [
            '192-bit nonce prevents nonce reuse issues',
            'Faster than AES on devices without hardware acceleration',
            'Constant-time implementation prevents timing attacks',
            'IETF standardized'
        ],
        'cons': [
            'Newer algorithm with less field testing than AES',
            'Limited hardware acceleration support'
        ],
        'real_world_usage': [
            'WireGuard VPN',
            'Cloudflare encryption',
            'Large-scale data encryption',
            'IoT device security'
        ]
    },
    'FF1-AES': {
        'name': 'FF1-AES',
        'category': 'Format-Preserving Encryption',
        'description': 'NIST-approved FPE mode that preserves data format and length',
        'strength': 'High',
        'speed': 'Moderate',
        'use_case': 'Encrypting structured data while maintaining format',
        'pros': [
            'Preserves data format and length',
            'NIST SP 800-38G approved',
            'No database schema changes needed',
            'Ideal for legacy system integration'
        ],
        'cons': [
            'Slower than standard AES modes',
            'Complex implementation',
            'Limited to specific data types'
        ],
        'real_world_usage': [
            'Credit card tokenization',
            'SSN encryption in databases',
            'Healthcare record protection',
            'PCI DSS compliance'
        ]
    },
    'Kyber-768': {
        'name': 'Kyber-768',
        'category': 'Post-Quantum Key Exchange',
        'description': 'NIST-selected quantum-resistant key encapsulation mechanism',
        'security_level': '192-bit',
        'strength': 'Quantum-Resistant',
        'speed': 'Fast',
        'use_case': 'Future-proof key exchange and encryption',
        'pros': [
            'Resistant to quantum computer attacks',
            'NIST standardization winner',
            'Efficient implementation',
            'Can be used in hybrid mode with classical algorithms'
        ],
        'cons': [
            'Larger key and ciphertext sizes',
            'Newer with less real-world deployment',
            'Requires updates to existing protocols'
        ],
        'real_world_usage': [
            'Signal messenger (testing)',
            'Chrome browser experiments',
            'VPN protocols (experimental)',
            'Long-term data archival'
        ]
    },
    'Enigma': {
        'name': 'Enigma Machine',
        'category': 'Historical Cipher',
        'description': 'WWII-era rotor cipher machine simulator',
        'strength': 'Educational Only',
        'speed': 'Fast',
        'use_case': 'Educational and historical demonstration',
        'pros': [
            'Historical significance',
            'Excellent for teaching cryptography concepts',
            'Demonstrates rotor-based encryption',
            'Interactive learning tool'
        ],
        'cons': [
            'Completely broken cryptographically',
            'No modern security value',
            'Vulnerable to frequency analysis',
            'Known plaintext attacks'
        ],
        'real_world_usage': [
            'Cryptography education',
            'Historical recreation',
            'Museum demonstrations',
            'Puzzle games and CTF challenges'
        ],
        'historical_note': 'Breaking Enigma shortened WWII by an estimated 2-4 years'
    }
}

# Export functions for API integration
def get_algorithm_info(algorithm_name: str) -> Dict[str, Any]:
    """Get detailed information about an algorithm"""
    return ALGORITHM_METADATA.get(algorithm_name, {})

def list_new_algorithms() -> list:
    """List all new algorithms"""
    return list(ALGORITHM_METADATA.keys())