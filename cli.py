#!/usr/bin/env python3
"""
Universal Encryption Platform - CLI Testing Tool
Command-line interface for testing encryption algorithms directly
"""

import sys
import argparse
import getpass
import json
import base64
from pathlib import Path
from typing import Dict, Any

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from crypto.symmetric import AESCrypto, ChaCha20Crypto
from crypto.asymmetric import RSACrypto
from crypto.classical import CaesarCipher, VigenereCipher, ROTCipher, AtbashCipher
from crypto.utils import generate_salt, derive_key, validate_password_strength

class EncryptionCLI:
    """Command-line interface for encryption operations"""
    
    def __init__(self):
        self.aes = AESCrypto()
        self.chacha20 = ChaCha20Crypto()
        self.rsa = RSACrypto()
        self.caesar = CaesarCipher()
        self.vigenere = VigenereCipher()
        self.rot = ROTCipher()
        self.atbash = AtbashCipher()
    
    def print_banner(self):
        """Print CLI banner"""
        print("""
🔐 Universal Encryption Platform - CLI Tool
===========================================
Test encryption algorithms directly from command line
        """)
    
    def list_algorithms(self):
        """List all available algorithms"""
        algorithms = {
            'Modern Symmetric': [
                'AES-256-GCM - Industry standard with authentication',
                'ChaCha20-Poly1305 - Modern stream cipher for mobile/IoT'
            ],
            'Asymmetric': [
                'RSA-4096 - Public key encryption for key exchange'
            ],
            'Classical/Educational': [
                'Caesar - Simple shift cipher for learning',
                'Vigenere - Polyalphabetic cipher with keyword',
                'ROT13 - Simple letter rotation (13 positions)',
                'Atbash - Hebrew alphabet reversal cipher'
            ]
        }
        
        print("\n📋 Available Algorithms:")
        for category, algos in algorithms.items():
            print(f"\n{category}:")
            for algo in algos:
                print(f"  • {algo}")
        print()
    
    def get_password(self, confirm=False):
        """Get password from user with optional confirmation"""
        password = getpass.getpass("Enter password: ")
        
        if confirm:
            confirm_password = getpass.getpass("Confirm password: ")
            if password != confirm_password:
                print("❌ Passwords don't match!")
                return None
        
        # Check password strength
        strength = validate_password_strength(password)
        print(f"Password strength: {strength['strength']} (score: {strength['score']}/6)")
        
        if strength['feedback']:
            print("Suggestions:")
            for suggestion in strength['feedback']:
                print(f"  • {suggestion}")
        
        return password
    
    def encrypt_aes_gcm(self, data: str, password: str) -> Dict[str, Any]:
        """Encrypt using AES-256-GCM"""
        try:
            # Convert to bytes
            data_bytes = data.encode('utf-8')
            
            # Generate salt and derive key
            salt = generate_salt()
            key = derive_key(password, salt, length=32)
            
            # Encrypt
            result = self.aes.encrypt_gcm(data_bytes, key)
            
            return {
                'success': True,
                'algorithm': 'AES-256-GCM',
                'encrypted_data': base64.b64encode(result['ciphertext']).decode(),
                'metadata': {
                    'iv': base64.b64encode(result['iv']).decode(),
                    'tag': base64.b64encode(result['tag']).decode(),
                    'salt': base64.b64encode(salt).decode()
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decrypt_aes_gcm(self, encrypted_data: str, password: str, metadata: Dict[str, str]) -> Dict[str, Any]:
        """Decrypt AES-256-GCM data"""
        try:
            # Decode data
            ciphertext = base64.b64decode(encrypted_data)
            iv = base64.b64decode(metadata['iv'])
            tag = base64.b64decode(metadata['tag'])
            salt = base64.b64decode(metadata['salt'])
            
            # Derive key
            key = derive_key(password, salt, length=32)
            
            # Decrypt
            plaintext = self.aes.decrypt_gcm(ciphertext, key, iv, tag)
            
            return {
                'success': True,
                'decrypted_data': plaintext.decode('utf-8')
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def encrypt_chacha20(self, data: str, password: str) -> Dict[str, Any]:
        """Encrypt using ChaCha20-Poly1305"""
        try:
            data_bytes = data.encode('utf-8')
            salt = generate_salt()
            key = derive_key(password, salt, length=32)
            
            result = self.chacha20.encrypt(data_bytes, key)
            
            return {
                'success': True,
                'algorithm': 'ChaCha20-Poly1305',
                'encrypted_data': base64.b64encode(result['ciphertext']).decode(),
                'metadata': {
                    'nonce': base64.b64encode(result['nonce']).decode(),
                    'tag': base64.b64encode(result['tag']).decode(),
                    'salt': base64.b64encode(salt).decode()
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def encrypt_rsa(self, data: str) -> Dict[str, Any]:
        """Encrypt using RSA-4096"""
        try:
            data_bytes = data.encode('utf-8')
            
            # Generate key pair
            print("🔑 Generating RSA-4096 key pair...")
            private_key, public_key = self.rsa.generate_keypair(4096)
            
            # Encrypt
            ciphertext = self.rsa.encrypt(data_bytes, public_key)
            
            return {
                'success': True,
                'algorithm': 'RSA-4096',
                'encrypted_data': base64.b64encode(ciphertext).decode(),
                'metadata': {
                    'public_key': self.rsa.serialize_public_key(public_key),
                    'private_key': self.rsa.serialize_private_key(private_key)
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def encrypt_caesar(self, data: str, shift: int = 3) -> Dict[str, Any]:
        """Encrypt using Caesar cipher"""
        try:
            encrypted = self.caesar.encrypt(data, shift)
            
            return {
                'success': True,
                'algorithm': 'Caesar',
                'encrypted_data': encrypted,
                'metadata': {
                    'shift': shift
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def encrypt_vigenere(self, data: str, keyword: str) -> Dict[str, Any]:
        """Encrypt using Vigenère cipher"""
        try:
            encrypted = self.vigenere.encrypt(data, keyword)
            
            return {
                'success': True,
                'algorithm': 'Vigenere',
                'encrypted_data': encrypted,
                'metadata': {
                    'keyword': keyword
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def encrypt_rot13(self, data: str) -> Dict[str, Any]:
        """Encrypt using ROT13"""
        try:
            encrypted = self.rot.rot13(data)
            
            return {
                'success': True,
                'algorithm': 'ROT13',
                'encrypted_data': encrypted,
                'metadata': {}
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def encrypt_atbash(self, data: str) -> Dict[str, Any]:
        """Encrypt using Atbash cipher"""
        try:
            encrypted = self.atbash.encrypt(data)
            
            return {
                'success': True,
                'algorithm': 'Atbash',
                'encrypted_data': encrypted,
                'metadata': {}
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def save_result(self, result: Dict[str, Any], filename: str):
        """Save encryption result to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"✅ Result saved to {filename}")
        except Exception as e:
            print(f"❌ Failed to save result: {e}")
    
    def load_result(self, filename: str) -> Dict[str, Any]:
        """Load encryption result from file"""
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Failed to load result: {e}")
            return None
    
    def run_interactive(self):
        """Run interactive encryption session"""
        self.print_banner()
        
        while True:
            print("\n🔐 Choose operation:")
            print("1. Encrypt data")
            print("2. Decrypt data") 
            print("3. List algorithms")
            print("4. Algorithm demo")
            print("5. Exit")
            
            choice = input("\nEnter choice (1-5): ").strip()
            
            if choice == '1':
                self.interactive_encrypt()
            elif choice == '2':
                self.interactive_decrypt()
            elif choice == '3':
                self.list_algorithms()
            elif choice == '4':
                self.algorithm_demo()
            elif choice == '5':
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please enter 1-5.")
    
    def interactive_encrypt(self):
        """Interactive encryption workflow"""
        print("\n🔒 Encryption Mode")
        
        # Get data
        data = input("Enter data to encrypt: ").strip()
        if not data:
            print("❌ No data provided!")
            return
        
        # Choose algorithm
        print("\nAvailable algorithms:")
        print("1. AES-256-GCM (Recommended)")
        print("2. ChaCha20-Poly1305")
        print("3. RSA-4096")
        print("4. Caesar Cipher")
        print("5. Vigenère Cipher")
        print("6. ROT13")
        print("7. Atbash")
        
        algo_choice = input("Choose algorithm (1-7): ").strip()
        
        # Encrypt based on choice
        result = None
        
        if algo_choice == '1':
            password = self.get_password()
            if password:
                result = self.encrypt_aes_gcm(data, password)
        
        elif algo_choice == '2':
            password = self.get_password()
            if password:
                result = self.encrypt_chacha20(data, password)
        
        elif algo_choice == '3':
            result = self.encrypt_rsa(data)
        
        elif algo_choice == '4':
            shift = input("Enter shift value (default 3): ").strip()
            shift = int(shift) if shift else 3
            result = self.encrypt_caesar(data, shift)
        
        elif algo_choice == '5':
            keyword = input("Enter keyword: ").strip()
            if keyword:
                result = self.encrypt_vigenere(data, keyword)
        
        elif algo_choice == '6':
            result = self.encrypt_rot13(data)
        
        elif algo_choice == '7':
            result = self.encrypt_atbash(data)
        
        else:
            print("❌ Invalid algorithm choice!")
            return
        
        # Display result
        if result and result['success']:
            print(f"\n✅ Encryption successful!")
            print(f"Algorithm: {result['algorithm']}")
            print(f"Encrypted data: {result['encrypted_data']}")
            
            if result['metadata']:
                print("Metadata:")
                for key, value in result['metadata'].items():
                    print(f"  {key}: {value}")
            
            # Ask to save
            save = input("\nSave result to file? (y/n): ").strip().lower()
            if save == 'y':
                filename = input("Enter filename (default: result.json): ").strip()
                filename = filename if filename else "result.json"
                self.save_result(result, filename)
        
        elif result:
            print(f"❌ Encryption failed: {result['error']}")
        else:
            print("❌ No result generated!")
    
    def interactive_decrypt(self):
        """Interactive decryption workflow"""
        print("\n🔓 Decryption Mode")
        
        # Load from file or input manually
        load_choice = input("Load from file? (y/n): ").strip().lower()
        
        if load_choice == 'y':
            filename = input("Enter filename: ").strip()
            data = self.load_result(filename)
            if not data:
                return
            
            encrypted_data = data.get('encrypted_data')
            algorithm = data.get('algorithm')
            metadata = data.get('metadata', {})
        else:
            encrypted_data = input("Enter encrypted data: ").strip()
            algorithm = input("Enter algorithm: ").strip()
            # Would need to input metadata manually - simplified for now
            metadata = {}
        
        # Decrypt based on algorithm
        if algorithm == 'AES-256-GCM':
            password = self.get_password()
            if password and metadata:
                result = self.decrypt_aes_gcm(encrypted_data, password, metadata)
                if result['success']:
                    print(f"✅ Decrypted: {result['decrypted_data']}")
                else:
                    print(f"❌ Decryption failed: {result['error']}")
        
        elif algorithm in ['Caesar', 'ROT13', 'Atbash']:
            # These are reversible
            if algorithm == 'Caesar':
                shift = metadata.get('shift', 3)
                decrypted = self.caesar.decrypt(encrypted_data, shift)
            elif algorithm == 'ROT13':
                decrypted = self.rot.rot13(encrypted_data)
            elif algorithm == 'Atbash':
                decrypted = self.atbash.decrypt(encrypted_data)
            
            print(f"✅ Decrypted: {decrypted}")
        
        else:
            print(f"❌ Decryption not implemented for {algorithm} in CLI")
    
    def algorithm_demo(self):
        """Demo different algorithms with same data"""
        print("\n🎯 Algorithm Demo")
        
        # Test data
        test_data = "Hello World! This is a test message."
        test_password = "demo_password_123"
        
        print(f"Test data: {test_data}")
        print(f"Test password: {test_password}")
        
        algorithms = [
            ('AES-256-GCM', lambda: self.encrypt_aes_gcm(test_data, test_password)),
            ('ChaCha20-Poly1305', lambda: self.encrypt_chacha20(test_data, test_password)),
            ('Caesar (shift 3)', lambda: self.encrypt_caesar(test_data, 3)),
            ('ROT13', lambda: self.encrypt_rot13(test_data)),
            ('Atbash', lambda: self.encrypt_atbash(test_data))
        ]
        
        print("\n🔄 Running encryption with different algorithms...")
        
        for name, encrypt_func in algorithms:
            try:
                result = encrypt_func()
                if result['success']:
                    encrypted = result['encrypted_data']
                    # Truncate long outputs
                    if len(encrypted) > 100:
                        encrypted = encrypted[:100] + "..."
                    print(f"✅ {name}: {encrypted}")
                else:
                    print(f"❌ {name}: {result['error']}")
            except Exception as e:
                print(f"❌ {name}: Error - {e}")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Universal Encryption Platform CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py                                    # Interactive mode
  python cli.py --list                            # List algorithms
  python cli.py --demo                            # Algorithm demo
  python cli.py --encrypt "Hello" --algo caesar   # Quick encrypt
        """
    )
    
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Run in interactive mode (default)')
    
    parser.add_argument('--list', '-l', action='store_true',
                       help='List available algorithms')
    
    parser.add_argument('--demo', '-d', action='store_true',
                       help='Run algorithm demonstration')
    
    parser.add_argument('--encrypt', '-e', type=str,
                       help='Data to encrypt (quick mode)')
    
    parser.add_argument('--algorithm', '--algo', '-a', type=str,
                       help='Algorithm to use (quick mode)')
    
    parser.add_argument('--password', '-p', type=str,
                       help='Password for encryption (quick mode)')
    
    parser.add_argument('--output', '-o', type=str,
                       help='Output file for results')
    
    args = parser.parse_args()
    
    cli = EncryptionCLI()
    
    # Handle command line options
    if args.list:
        cli.list_algorithms()
    
    elif args.demo:
        cli.algorithm_demo()
    
    elif args.encrypt:
        # Quick encryption mode
        data = args.encrypt
        algorithm = args.algorithm or 'caesar'
        password = args.password
        
        print(f"🔒 Quick encrypt: {data}")
        print(f"Algorithm: {algorithm}")
        
        if algorithm.lower() == 'caesar':
            result = cli.encrypt_caesar(data, 3)
        elif algorithm.lower() == 'rot13':
            result = cli.encrypt_rot13(data)
        elif algorithm.lower() == 'atbash':
            result = cli.encrypt_atbash(data)
        elif algorithm.lower() in ['aes', 'aes-256-gcm']:
            if not password:
                password = getpass.getpass("Password: ")
            result = cli.encrypt_aes_gcm(data, password)
        else:
            print(f"❌ Algorithm {algorithm} not supported in quick mode")
            return
        
        if result['success']:
            print(f"✅ Encrypted: {result['encrypted_data']}")
            
            if args.output:
                cli.save_result(result, args.output)
        else:
            print(f"❌ Encryption failed: {result['error']}")
    
    else:
        # Default to interactive mode
        cli.run_interactive()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 CLI stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        sys.exit(1)