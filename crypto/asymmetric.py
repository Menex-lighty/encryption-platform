"""
Asymmetric Encryption Implementations
RSA, ECC, and other public key cryptography algorithms
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

class RSACrypto:
    """RSA encryption implementation with multiple key sizes"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_keypair(self, key_size: int = 4096) -> tuple:
        """
        Generate RSA key pair
        
        Args:
            key_size: Key size in bits (2048, 3072, 4096)
        
        Returns:
            Tuple of (private_key, public_key)
        """
        try:
            if key_size not in [2048, 3072, 4096]:
                raise ValueError("Key size must be 2048, 3072, or 4096 bits")
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=self.backend
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            logger.info(f"RSA key pair generated: {key_size} bits")
            return private_key, public_key
            
        except Exception as e:
            logger.error(f"RSA key generation failed: {str(e)}")
            raise
    
    def encrypt(self, plaintext: bytes, public_key) -> bytes:
        """
        Encrypt data using RSA public key with OAEP padding
        
        Note: RSA can only encrypt data smaller than key size
        For larger data, use hybrid encryption (RSA + AES)
        """
        try:
            # Calculate maximum plaintext size
            key_size = public_key.key_size // 8  # Convert bits to bytes
            max_plaintext_size = key_size - 2 * (hashes.SHA256().digest_size) - 2
            
            if len(plaintext) > max_plaintext_size:
                raise ValueError(f"Plaintext too large. Maximum size: {max_plaintext_size} bytes")
            
            # Encrypt with OAEP padding
            ciphertext = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            logger.info(f"RSA encryption successful, plaintext: {len(plaintext)} bytes")
            return ciphertext
            
        except Exception as e:
            logger.error(f"RSA encryption failed: {str(e)}")
            raise
    
    def decrypt(self, ciphertext: bytes, private_key) -> bytes:
        """Decrypt data using RSA private key"""
        try:
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            logger.info(f"RSA decryption successful, plaintext: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            logger.error(f"RSA decryption failed: {str(e)}")
            raise ValueError("Decryption failed - invalid private key or corrupted data")
    
    def sign(self, message: bytes, private_key) -> bytes:
        """Create digital signature using RSA private key"""
        try:
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            logger.info(f"RSA signature created for message: {len(message)} bytes")
            return signature
            
        except Exception as e:
            logger.error(f"RSA signing failed: {str(e)}")
            raise
    
    def verify(self, message: bytes, signature: bytes, public_key) -> bool:
        """Verify digital signature using RSA public key"""
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            logger.info(f"RSA signature verification successful")
            return True
            
        except Exception as e:
            logger.error(f"RSA signature verification failed: {str(e)}")
            return False
    
    def serialize_private_key(self, private_key, password: bytes = None) -> str:
        """Serialize private key to PEM format"""
        try:
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password)
            else:
                encryption_algorithm = serialization.NoEncryption()
            
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            
            return pem.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Private key serialization failed: {str(e)}")
            raise
    
    def serialize_public_key(self, public_key) -> str:
        """Serialize public key to PEM format"""
        try:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return pem.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Public key serialization failed: {str(e)}")
            raise
    
    def deserialize_private_key(self, pem_data: str, password: bytes = None):
        """Deserialize private key from PEM format"""
        try:
            private_key = serialization.load_pem_private_key(
                pem_data.encode('utf-8'),
                password=password,
                backend=self.backend
            )
            
            return private_key
            
        except Exception as e:
            logger.error(f"Private key deserialization failed: {str(e)}")
            raise
    
    def deserialize_public_key(self, pem_data: str):
        """Deserialize public key from PEM format"""
        try:
            public_key = serialization.load_pem_public_key(
                pem_data.encode('utf-8'),
                backend=self.backend
            )
            
            return public_key
            
        except Exception as e:
            logger.error(f"Public key deserialization failed: {str(e)}")
            raise


class ECCCrypto:
    """Elliptic Curve Cryptography implementation"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_keypair(self, curve_name: str = 'P-256') -> tuple:
        """
        Generate ECC key pair
        
        Args:
            curve_name: Curve name ('P-256', 'P-384', 'P-521')
        
        Returns:
            Tuple of (private_key, public_key)
        """
        try:
            # Map curve names to cryptography curves
            curves = {
                'P-256': ec.SECP256R1(),
                'P-384': ec.SECP384R1(),
                'P-521': ec.SECP521R1(),
                'secp256k1': ec.SECP256K1()  # Bitcoin curve
            }
            
            if curve_name not in curves:
                raise ValueError(f"Unsupported curve: {curve_name}")
            
            # Generate private key
            private_key = ec.generate_private_key(
                curves[curve_name],
                backend=self.backend
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            logger.info(f"ECC key pair generated: {curve_name}")
            return private_key, public_key
            
        except Exception as e:
            logger.error(f"ECC key generation failed: {str(e)}")
            raise
    
    def sign(self, message: bytes, private_key) -> bytes:
        """Create ECDSA signature"""
        try:
            signature = private_key.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
            
            logger.info(f"ECDSA signature created for message: {len(message)} bytes")
            return signature
            
        except Exception as e:
            logger.error(f"ECDSA signing failed: {str(e)}")
            raise
    
    def verify(self, message: bytes, signature: bytes, public_key) -> bool:
        """Verify ECDSA signature"""
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            
            logger.info(f"ECDSA signature verification successful")
            return True
            
        except Exception as e:
            logger.error(f"ECDSA signature verification failed: {str(e)}")
            return False
    
    def perform_ecdh(self, private_key, peer_public_key) -> bytes:
        """Perform Elliptic Curve Diffie-Hellman key exchange"""
        try:
            shared_key = private_key.exchange(
                ec.ECDH(),
                peer_public_key
            )
            
            logger.info(f"ECDH key exchange successful")
            return shared_key
            
        except Exception as e:
            logger.error(f"ECDH key exchange failed: {str(e)}")
            raise
    
    def serialize_private_key(self, private_key, password: bytes = None) -> str:
        """Serialize ECC private key to PEM format"""
        try:
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password)
            else:
                encryption_algorithm = serialization.NoEncryption()
            
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            
            return pem.decode('utf-8')
            
        except Exception as e:
            logger.error(f"ECC private key serialization failed: {str(e)}")
            raise
    
    def serialize_public_key(self, public_key) -> str:
        """Serialize ECC public key to PEM format"""
        try:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return pem.decode('utf-8')
            
        except Exception as e:
            logger.error(f"ECC public key serialization failed: {str(e)}")
            raise


class HybridCrypto:
    """
    Hybrid encryption combining RSA/ECC with symmetric encryption
    For encrypting large data with public key cryptography
    """
    
    def __init__(self):
        self.rsa = RSACrypto()
        from .symmetric import AESCrypto
        self.aes = AESCrypto()
    
    def encrypt_with_rsa(self, plaintext: bytes, public_key) -> dict:
        """
        Hybrid encryption: Generate AES key, encrypt data with AES,
        encrypt AES key with RSA
        """
        try:
            # Generate random AES key
            aes_key = os.urandom(32)  # 256-bit key
            
            # Encrypt data with AES-GCM
            aes_result = self.aes.encrypt_gcm(plaintext, aes_key)
            
            # Encrypt AES key with RSA
            encrypted_key = self.rsa.encrypt(aes_key, public_key)
            
            logger.info(f"Hybrid RSA+AES encryption successful, plaintext: {len(plaintext)} bytes")
            
            return {
                'encrypted_data': aes_result,
                'encrypted_key': encrypted_key,
                'algorithm': 'RSA+AES-GCM'
            }
            
        except Exception as e:
            logger.error(f"Hybrid encryption failed: {str(e)}")
            raise
    
    def decrypt_with_rsa(self, encrypted_data: dict, encrypted_key: bytes, private_key) -> bytes:
        """Hybrid decryption: Decrypt AES key with RSA, then decrypt data with AES"""
        try:
            # Decrypt AES key with RSA
            aes_key = self.rsa.decrypt(encrypted_key, private_key)
            
            # Decrypt data with AES-GCM
            plaintext = self.aes.decrypt_gcm(
                encrypted_data['ciphertext'],
                aes_key,
                encrypted_data['iv'],
                encrypted_data['tag']
            )
            
            logger.info(f"Hybrid RSA+AES decryption successful, plaintext: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            logger.error(f"Hybrid decryption failed: {str(e)}")
            raise ValueError("Hybrid decryption failed - invalid key or corrupted data")


# Utility functions
def get_key_info(key) -> dict:
    """Get information about a cryptographic key"""
    try:
        if hasattr(key, 'key_size'):
            # RSA key
            return {
                'type': 'RSA',
                'size': key.key_size,
                'public_numbers': str(key.public_key().public_numbers().n)[:20] + "..."
            }
        elif hasattr(key, 'curve'):
            # ECC key
            return {
                'type': 'ECC',
                'curve': key.curve.name,
                'key_size': key.curve.key_size
            }
        else:
            return {'type': 'Unknown'}
    except Exception:
        return {'type': 'Error parsing key'}