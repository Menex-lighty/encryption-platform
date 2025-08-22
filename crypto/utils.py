"""
Cryptographic Utilities
Key derivation, random generation, and common crypto operations
Fixed version with proper Argon2 handling
"""

import os
import hashlib
import secrets
import base64
from typing import Union, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# Try to import Argon2 from argon2-cffi instead of cryptography
try:
    from argon2 import PasswordHasher
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

import logging

logger = logging.getLogger(__name__)

def generate_salt(length: int = 32) -> bytes:
    """
    Generate cryptographically secure random salt
    
    Args:
        length: Salt length in bytes (default: 32)
    
    Returns:
        Random salt bytes
    """
    return secrets.token_bytes(length)

def generate_secure_random(length: int = 32) -> bytes:
    """Generate cryptographically secure random bytes"""
    return secrets.token_bytes(length)

def derive_key(password: Union[str, bytes], 
               salt: bytes, 
               length: int = 32,
               algorithm: str = 'PBKDF2',
               iterations: int = 100000) -> bytes:
    """
    Derive encryption key from password using various KDFs
    
    Args:
        password: User password
        salt: Random salt
        length: Key length in bytes
        algorithm: KDF algorithm ('PBKDF2', 'Scrypt', 'Argon2')
        iterations: Number of iterations (for PBKDF2)
    
    Returns:
        Derived key bytes
    """
    try:
        # Convert password to bytes if needed
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        backend = default_backend()
        
        if algorithm == 'PBKDF2':
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                iterations=iterations,
                backend=backend
            )
            key = kdf.derive(password)
            
        elif algorithm == 'Scrypt':
            kdf = Scrypt(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                n=2**14,  # CPU/memory cost parameter
                r=8,      # Block size
                p=1,      # Parallelization parameter
                backend=backend
            )
            key = kdf.derive(password)
            
        elif algorithm == 'Argon2':
            if ARGON2_AVAILABLE:
                # Use argon2-cffi library
                key = hash_secret_raw(
                    secret=password,
                    salt=salt,
                    time_cost=2,
                    memory_cost=65536,
                    parallelism=1,
                    hash_len=length,
                    type=Type.ID
                )
            else:
                # Fallback to PBKDF2 with warning
                logger.warning("Argon2 not available, falling back to PBKDF2 with higher iterations")
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=length,
                    salt=salt,
                    iterations=iterations * 2,  # Double iterations for fallback
                    backend=backend
                )
                key = kdf.derive(password)
        else:
            raise ValueError(f"Unsupported KDF algorithm: {algorithm}")
        
        logger.info(f"Key derived using {algorithm}, length: {length} bytes")
        return key
        
    except Exception as e:
        logger.error(f"Key derivation failed: {str(e)}")
        raise

def hash_data(data: Union[str, bytes], algorithm: str = 'SHA256') -> bytes:
    """
    Hash data using various algorithms
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm ('SHA256', 'SHA512', 'SHA3-256', 'BLAKE2b')
    
    Returns:
        Hash digest bytes
    """
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if algorithm == 'SHA256':
            return hashlib.sha256(data).digest()
        elif algorithm == 'SHA512':
            return hashlib.sha512(data).digest()
        elif algorithm == 'SHA3-256':
            return hashlib.sha3_256(data).digest()
        elif algorithm == 'SHA3-512':
            return hashlib.sha3_512(data).digest()
        elif algorithm == 'BLAKE2b':
            return hashlib.blake2b(data).digest()
        elif algorithm == 'MD5':  # Not recommended for security
            return hashlib.md5(data).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
    except Exception as e:
        logger.error(f"Hashing failed: {str(e)}")
        raise

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks
    """
    return secrets.compare_digest(a, b)

def secure_zero(data: bytearray) -> None:
    """
    Securely zero out sensitive data in memory
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0

class SecureBytes:
    """
    Context manager for handling sensitive bytes securely
    """
    
    def __init__(self, data: bytes):
        self._data = bytearray(data)
    
    def __enter__(self):
        return bytes(self._data)
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        secure_zero(self._data)

# Encoding utilities
def encode_base64(data: bytes) -> str:
    """Encode bytes to base64 string"""
    return base64.b64encode(data).decode('utf-8')

def decode_base64(data: str) -> bytes:
    """Decode base64 string to bytes"""
    return base64.b64decode(data.encode('utf-8'))

def encode_hex(data: bytes) -> str:
    """Encode bytes to hexadecimal string"""
    return data.hex()

def decode_hex(data: str) -> bytes:
    """Decode hexadecimal string to bytes"""
    return bytes.fromhex(data)

# Key strength validation
def validate_password_strength(password: str) -> dict:
    """
    Validate password strength
    
    Returns:
        Dictionary with strength analysis
    """
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long")
    
    # Character variety
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    variety_score = sum([has_lower, has_upper, has_digit, has_special])
    score += variety_score
    
    if not has_lower:
        feedback.append("Add lowercase letters")
    if not has_upper:
        feedback.append("Add uppercase letters")
    if not has_digit:
        feedback.append("Add numbers")
    if not has_special:
        feedback.append("Add special characters")
    
    # Common patterns
    if password.lower() in ['password', '123456', 'qwerty', 'abc123']:
        score -= 3
        feedback.append("Avoid common passwords")
    
    # Determine strength level
    if score >= 6:
        strength = "Strong"
    elif score >= 4:
        strength = "Medium"
    elif score >= 2:
        strength = "Weak"
    else:
        strength = "Very Weak"
    
    return {
        'strength': strength,
        'score': max(0, score),
        'max_score': 6,
        'feedback': feedback
    }

def generate_secure_password(length: int = 16, 
                           include_symbols: bool = True) -> str:
    """
    Generate cryptographically secure password
    
    Args:
        length: Password length
        include_symbols: Include special characters
    
    Returns:
        Secure random password
    """
    import string
    
    chars = string.ascii_letters + string.digits
    if include_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    password = ''.join(secrets.choice(chars) for _ in range(length))
    
    # Ensure at least one character from each category
    if length >= 4:
        password = list(password)
        password[0] = secrets.choice(string.ascii_lowercase)
        password[1] = secrets.choice(string.ascii_uppercase)
        password[2] = secrets.choice(string.digits)
        if include_symbols and length > 4:
            password[3] = secrets.choice("!@#$%^&*")
        
        # Shuffle to randomize positions
        for i in range(len(password)):
            j = secrets.randbelow(len(password))
            password[i], password[j] = password[j], password[i]
        
        password = ''.join(password)
    
    return password

# File utilities for crypto operations
def secure_file_wipe(filepath: str, passes: int = 3) -> bool:
    """
    Securely wipe file by overwriting with random data
    
    Args:
        filepath: Path to file to wipe
        passes: Number of overwrite passes
    
    Returns:
        True if successful
    """
    try:
        import os
        
        if not os.path.exists(filepath):
            return False
        
        filesize = os.path.getsize(filepath)
        
        with open(filepath, 'r+b') as file:
            for _ in range(passes):
                file.seek(0)
                file.write(os.urandom(filesize))
                file.flush()
                os.fsync(file.fileno())
        
        os.remove(filepath)
        logger.info(f"File securely wiped: {filepath}")
        return True
        
    except Exception as e:
        logger.error(f"Secure file wipe failed: {str(e)}")
        return False

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data
    
    Returns:
        Entropy value (0-8 bits per byte)
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    
    for count in frequencies.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * (probability.bit_length() - 1)
    
    return entropy

def format_bytes(num_bytes: int) -> str:
    """Format byte count as human-readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"

def timing_safe_equal(a: str, b: str) -> bool:
    """Timing-safe string comparison"""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y
    
    return result == 0

# Metadata for algorithms
ALGORITHM_METADATA = {
    'AES-256-GCM': {
        'key_size': 32,
        'iv_size': 12,
        'tag_size': 16,
        'block_size': 16,
        'mode': 'Authenticated Encryption',
        'security_level': 'Very High',
        'performance': 'Fast'
    },
    'ChaCha20-Poly1305': {
        'key_size': 32,
        'nonce_size': 12,
        'tag_size': 16,
        'block_size': 64,
        'mode': 'Stream Cipher',
        'security_level': 'Very High',
        'performance': 'Very Fast'
    },
    'AES-256-CBC': {
        'key_size': 32,
        'iv_size': 16,
        'tag_size': 0,
        'block_size': 16,
        'mode': 'Block Cipher',
        'security_level': 'Very High',
        'performance': 'Fast'
    },
    'RSA-4096': {
        'key_size': 4096,
        'max_plaintext': 446,  # For OAEP padding
        'mode': 'Asymmetric',
        'security_level': 'Very High',
        'performance': 'Slow'
    },
    'Caesar': {
        'key_size': 'variable',
        'mode': 'Classical',
        'security_level': 'Educational',
        'performance': 'Very Fast'
    }
}

def get_algorithm_info(algorithm: str) -> dict:
    """Get metadata for encryption algorithm"""
    return ALGORITHM_METADATA.get(algorithm, {
        'mode': 'Unknown',
        'security_level': 'Unknown',
        'performance': 'Unknown'
    })