"""
Symmetric Encryption Implementations
AES-256-GCM, ChaCha20-Poly1305, and other symmetric algorithms
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import logging

logger = logging.getLogger(__name__)

class AESCrypto:
    """AES encryption implementation with multiple modes"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def encrypt_gcm(self, plaintext: bytes, key: bytes) -> dict:
        """
        Encrypt using AES-256-GCM (Galois Counter Mode)
        Provides both encryption and authentication
        """
        try:
            # Generate random 96-bit IV for GCM
            iv = os.urandom(12)
            
            # Create AESGCM cipher
            aesgcm = AESGCM(key)
            
            # Encrypt and authenticate
            ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
            
            # Extract ciphertext and tag
            ciphertext = ciphertext_with_tag[:-16]  # All but last 16 bytes
            tag = ciphertext_with_tag[-16:]         # Last 16 bytes is the tag
            
            logger.info(f"AES-GCM encryption successful, plaintext: {len(plaintext)} bytes")
            
            return {
                'ciphertext': ciphertext,
                'iv': iv,
                'tag': tag
            }
            
        except Exception as e:
            logger.error(f"AES-GCM encryption failed: {str(e)}")
            raise
    
    def decrypt_gcm(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Decrypt using AES-256-GCM
        Automatically verifies authentication tag
        """
        try:
            # Create AESGCM cipher
            aesgcm = AESGCM(key)
            
            # Combine ciphertext and tag
            ciphertext_with_tag = ciphertext + tag
            
            # Decrypt and verify
            plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
            
            logger.info(f"AES-GCM decryption successful, plaintext: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            logger.error(f"AES-GCM decryption failed: {str(e)}")
            raise ValueError("Decryption failed - invalid key, IV, or corrupted data")
    
    def encrypt_cbc(self, plaintext: bytes, key: bytes) -> dict:
        """
        Encrypt using AES-256-CBC (Cipher Block Chaining)
        Suitable for large data like images and files
        """
        try:
            # Generate random IV
            iv = os.urandom(16)  # AES block size is 16 bytes
            
            # Add PKCS7 padding
            padded_plaintext = self._add_padding(plaintext, 16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            
            # Encrypt
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
            
            logger.info(f"AES-CBC encryption successful, plaintext: {len(plaintext)} bytes")
            
            return {
                'ciphertext': ciphertext,
                'iv': iv
            }
            
        except Exception as e:
            logger.error(f"AES-CBC encryption failed: {str(e)}")
            raise
    
    def decrypt_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt using AES-256-CBC"""
        try:
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            plaintext = self._remove_padding(padded_plaintext)
            
            logger.info(f"AES-CBC decryption successful, plaintext: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            logger.error(f"AES-CBC decryption failed: {str(e)}")
            raise ValueError("Decryption failed - invalid key, IV, or corrupted data")
    
    def encrypt_xts(self, plaintext: bytes, key: bytes, sector_id: int = 0) -> dict:
        """
        Encrypt using AES-256-XTS (XEX-based tweaked-codebook mode)
        Used for full disk encryption
        """
        try:
            # XTS requires 512-bit key (64 bytes) for AES-256
            if len(key) != 64:
                raise ValueError("XTS mode requires 512-bit (64-byte) key for AES-256")
            
            # Create tweak (sector identifier)
            tweak = sector_id.to_bytes(16, byteorder='little')
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key[:32]),  # First half of key
                modes.XTS(key[32:]),       # Second half as tweak key
                backend=self.backend
            )
            
            # XTS requires plaintext to be multiple of 16 bytes
            if len(plaintext) % 16 != 0:
                plaintext = self._add_padding(plaintext, 16)
            
            # Encrypt
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            logger.info(f"AES-XTS encryption successful, plaintext: {len(plaintext)} bytes")
            
            return {
                'ciphertext': ciphertext,
                'sector_id': sector_id
            }
            
        except Exception as e:
            logger.error(f"AES-XTS encryption failed: {str(e)}")
            raise
    
    def decrypt_xts(self, ciphertext: bytes, key: bytes, sector_id: int = 0) -> bytes:
        """Decrypt using AES-256-XTS"""
        try:
            if len(key) != 64:
                raise ValueError("XTS mode requires 512-bit (64-byte) key for AES-256")
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key[:32]),
                modes.XTS(key[32:]),
                backend=self.backend
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding if present
            try:
                plaintext = self._remove_padding(plaintext)
            except:
                # If padding removal fails, return as-is
                pass
            
            logger.info(f"AES-XTS decryption successful, plaintext: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            logger.error(f"AES-XTS decryption failed: {str(e)}")
            raise ValueError("Decryption failed - invalid key or corrupted data")
    
    def _add_padding(self, data: bytes, block_size: int) -> bytes:
        """Add PKCS7 padding"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _remove_padding(self, data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        if not data:
            raise ValueError("No data to unpad")
        
        padding_length = data[-1]
        if padding_length > len(data):
            raise ValueError("Invalid padding")
        
        return data[:-padding_length]


class ChaCha20Crypto:
    """ChaCha20-Poly1305 encryption implementation"""
    
    def encrypt(self, plaintext: bytes, key: bytes) -> dict:
        """
        Encrypt using ChaCha20-Poly1305
        Modern stream cipher with authentication
        """
        try:
            # Generate random 96-bit nonce
            nonce = os.urandom(12)
            
            # Create ChaCha20Poly1305 cipher
            cipher = ChaCha20Poly1305(key)
            
            # Encrypt and authenticate
            ciphertext_with_tag = cipher.encrypt(nonce, plaintext, None)
            
            # Extract ciphertext and tag
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]
            
            logger.info(f"ChaCha20 encryption successful, plaintext: {len(plaintext)} bytes")
            
            return {
                'ciphertext': ciphertext,
                'nonce': nonce,
                'tag': tag
            }
            
        except Exception as e:
            logger.error(f"ChaCha20 encryption failed: {str(e)}")
            raise
    
    def decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        try:
            # Create cipher
            cipher = ChaCha20Poly1305(key)
            
            # Combine ciphertext and tag
            ciphertext_with_tag = ciphertext + tag
            
            # Decrypt and verify
            plaintext = cipher.decrypt(nonce, ciphertext_with_tag, None)
            
            logger.info(f"ChaCha20 decryption successful, plaintext: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            logger.error(f"ChaCha20 decryption failed: {str(e)}")
            raise ValueError("Decryption failed - invalid key, nonce, or corrupted data")


class BlowfishCrypto:
    """Blowfish encryption implementation"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def encrypt_cbc(self, plaintext: bytes, key: bytes) -> dict:
        """Encrypt using Blowfish-CBC"""
        try:
            # Generate random IV
            iv = os.urandom(8)  # Blowfish block size is 8 bytes
            
            # Add padding
            padded_plaintext = self._add_padding(plaintext, 8)
            
            # Create cipher
            cipher = Cipher(
                algorithms.Blowfish(key),
                modes.CBC(iv),
                backend=self.backend
            )
            
            # Encrypt
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
            
            logger.info(f"Blowfish encryption successful, plaintext: {len(plaintext)} bytes")
            
            return {
                'ciphertext': ciphertext,
                'iv': iv
            }
            
        except Exception as e:
            logger.error(f"Blowfish encryption failed: {str(e)}")
            raise
    
    def decrypt_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt using Blowfish-CBC"""
        try:
            # Create cipher
            cipher = Cipher(
                algorithms.Blowfish(key),
                modes.CBC(iv),
                backend=self.backend
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            plaintext = self._remove_padding(padded_plaintext)
            
            logger.info(f"Blowfish decryption successful, plaintext: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            logger.error(f"Blowfish decryption failed: {str(e)}")
            raise ValueError("Decryption failed - invalid key, IV, or corrupted data")
    
    def _add_padding(self, data: bytes, block_size: int) -> bytes:
        """Add PKCS7 padding"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _remove_padding(self, data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        if not data:
            raise ValueError("No data to unpad")
        
        padding_length = data[-1]
        if padding_length > len(data):
            raise ValueError("Invalid padding")
        
        return data[:-padding_length]


# Utility functions for key derivation and management
def generate_key(algorithm: str = 'AES-256') -> bytes:
    """Generate a random key for the specified algorithm"""
    key_sizes = {
        'AES-128': 16,
        'AES-192': 24,
        'AES-256': 32,
        'ChaCha20': 32,
        'Blowfish': 32  # Variable, but 32 is good default
    }
    
    size = key_sizes.get(algorithm, 32)
    return os.urandom(size)

def generate_iv(algorithm: str = 'AES') -> bytes:
    """Generate a random IV for the specified algorithm"""
    iv_sizes = {
        'AES': 16,
        'Blowfish': 8,
        'ChaCha20': 12  # Nonce size
    }
    
    size = iv_sizes.get(algorithm, 16)
    return os.urandom(size)