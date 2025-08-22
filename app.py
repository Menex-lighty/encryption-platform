"""
Universal Encryption Platform - Flask Backend
Phase 1: Core Foundation with AES-256-GCM encryption
Updated with all missing routes and templates
"""

from flask import Flask, request, jsonify, render_template, send_file, make_response
from flask_cors import CORS
import os
import base64
import json
from datetime import datetime
import logging
import io

# Import our crypto modules
from crypto.symmetric import AESCrypto, ChaCha20Crypto
from crypto.asymmetric import RSACrypto
from crypto.classical import CaesarCipher
from crypto.utils import generate_salt, derive_key
from crypto.extended_algorithms import (
    XChaCha20Poly1305Cipher, FF1AESCipher, Kyber768, EnigmaMachine,
    get_algorithm_info, list_new_algorithms
)
from utils.validators import validate_encryption_request
from utils.formatters import format_response
from utils.file_handlers import handle_file_upload, get_file_for_download, list_uploaded_files, delete_uploaded_file
# from routes.extended_routes import extended_bp  # Not needed - algorithms integrated directly

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    # Enable CORS for cross-platform compatibility
    CORS(app, origins=['http://localhost:3000', 'http://localhost:8080'])
    
    # Supported algorithms registry
    ALGORITHMS = {
        'text': ['AES-256-GCM', 'ChaCha20-Poly1305', 'XChaCha20-Poly1305', 'RSA-4096', 'FF1-AES', 'Caesar', 'Enigma'],
        'image': ['AES-256-CBC', 'LSB-Steganography'],
        'file': ['AES-256-XTS', 'AES-256-GCM', 'XChaCha20-Poly1305'],
        'postquantum': ['Kyber-768']
    }
    
    # ================================
    # WEB PAGES
    # ================================
    
    @app.route('/')
    def home():
        """Web demo homepage"""
        try:
            return render_template('index.html', algorithms=ALGORITHMS)
        except Exception as e:
            logger.error(f"Home page error: {str(e)}")
            return f"<h1>Universal Encryption Platform</h1><p>Backend running but template missing. Error: {str(e)}</p>", 200
    
    @app.route('/demo')
    def demo():
        """Interactive encryption demo page"""
        try:
            return render_template('demo.html', algorithms=ALGORITHMS)
        except Exception as e:
            logger.error(f"Demo page error: {str(e)}")
            return f"<h1>Demo Page Error</h1><p>Error loading demo template: {str(e)}</p><p><a href='/'>← Back to Home</a></p>", 200
    
    @app.route('/docs')
    def docs():
        """API documentation"""
        try:
            return render_template('docs.html')
        except Exception as e:
            logger.error(f"Docs page error: {str(e)}")
            return f"<h1>API Documentation</h1><p>Error loading docs template: {str(e)}</p><p><a href='/'>← Back to Home</a></p>", 200
    
    # ================================
    # CORE API ENDPOINTS
    # ================================
    
    @app.route('/api/encrypt', methods=['POST'])
    def encrypt_data():
        """
        Core encryption endpoint
        Supports text, image, and file encryption with multiple algorithms
        """
        try:
            # Validate request
            try:
                data = request.get_json(force=True)
            except Exception as json_error:
                return jsonify({'success': False, 'error': 'Invalid JSON format'}), 400
                
            if not data:
                return jsonify({'success': False, 'error': 'No JSON data provided'}), 400
            
            # Validate required fields
            validation_result = validate_encryption_request(data)
            if not validation_result['valid']:
                return jsonify({'success': False, 'error': validation_result['message']}), 400
            
            # Extract parameters
            plain_data = data.get('data')
            data_type = data.get('data_type', 'text')
            algorithm = data.get('algorithm')
            password = data.get('password')
            options = data.get('options', {})
            
            logger.info(f"Encryption request: {algorithm} for {data_type}")
            
            # Route to appropriate encryption function
            if algorithm == 'AES-256-GCM':
                result = encrypt_aes_gcm(plain_data, password, options)
            elif algorithm == 'ChaCha20-Poly1305':
                result = encrypt_chacha20(plain_data, password, options)
            elif algorithm == 'XChaCha20-Poly1305':
                result = encrypt_xchacha20(plain_data, password, options)
            elif algorithm == 'RSA-4096':
                result = encrypt_rsa(plain_data, options)
            elif algorithm == 'FF1-AES':
                result = encrypt_ff1_aes(plain_data, password, options)
            elif algorithm == 'Caesar':
                result = encrypt_caesar(plain_data, options)
            elif algorithm == 'Enigma':
                result = encrypt_enigma(plain_data, options)
            elif algorithm == 'Kyber-768':
                result = encrypt_kyber768(plain_data, options)
            else:
                return jsonify({'success': False, 'error': f'Algorithm {algorithm} not implemented'}), 400
            
            # Format response
            response = format_response(result, algorithm, data_type, options)
            return jsonify(response)
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            return jsonify({'success': False, 'error': 'Internal server error'}), 500
    
    @app.route('/api/decrypt', methods=['POST'])
    def decrypt_data():
        """
        Core decryption endpoint - FIXED VERSION
        """
        try:
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'No JSON data provided'}), 400
            
            # Extract parameters
            encrypted_data = data.get('encrypted_data')
            algorithm = data.get('algorithm')
            password = data.get('password')
            metadata = data.get('metadata', {})
            
            # Validate required fields
            if not encrypted_data:
                return jsonify({'success': False, 'error': 'encrypted_data is required'}), 400
            if not algorithm:
                return jsonify({'success': False, 'error': 'algorithm is required'}), 400
            
            # Only some algorithms require passwords
            password_required_algorithms = ['AES-256-GCM', 'ChaCha20-Poly1305', 'XChaCha20-Poly1305', 'FF1-AES']
            if algorithm in password_required_algorithms and not password:
                return jsonify({'success': False, 'error': 'password is required for this algorithm'}), 400
            
            logger.info(f"Decryption request: {algorithm}")
            logger.debug(f"Metadata keys: {list(metadata.keys())}")
            
            # Route to appropriate decryption function
            if algorithm == 'AES-256-GCM':
                # Validate AES-GCM specific metadata
                required_fields = ['iv', 'tag', 'salt']
                missing_fields = [field for field in required_fields if field not in metadata]
                if missing_fields:
                    return jsonify({
                        'success': False, 
                        'error': f'Missing required metadata fields: {missing_fields}',
                        'required_fields': required_fields,
                        'provided_fields': list(metadata.keys())
                    }), 400
                
                result = decrypt_aes_gcm(encrypted_data, password, metadata)
                
            elif algorithm == 'ChaCha20-Poly1305':
                # Validate ChaCha20 specific metadata
                required_fields = ['nonce', 'tag', 'salt']
                missing_fields = [field for field in required_fields if field not in metadata]
                if missing_fields:
                    return jsonify({
                        'success': False, 
                        'error': f'Missing required metadata fields: {missing_fields}',
                        'required_fields': required_fields,
                        'provided_fields': list(metadata.keys())
                    }), 400
                
                result = decrypt_chacha20(encrypted_data, password, metadata)
                
            elif algorithm == 'XChaCha20-Poly1305':
                # Validate XChaCha20 specific metadata
                required_fields = ['nonce', 'salt']
                missing_fields = [field for field in required_fields if field not in metadata]
                if missing_fields:
                    return jsonify({
                        'success': False, 
                        'error': f'Missing required metadata fields: {missing_fields}',
                        'required_fields': required_fields,
                        'provided_fields': list(metadata.keys())
                    }), 400
                
                result = decrypt_xchacha20(encrypted_data, password, metadata)
                
            elif algorithm == 'RSA-4096':
                required_fields = ['private_key']
                missing_fields = [field for field in required_fields if field not in metadata]
                if missing_fields:
                    return jsonify({
                        'success': False, 
                        'error': f'Missing required metadata fields: {missing_fields}',
                        'required_fields': required_fields
                    }), 400
                
                result = decrypt_rsa(encrypted_data, metadata)
                
            elif algorithm == 'FF1-AES':
                required_fields = ['format', 'salt']
                missing_fields = [field for field in required_fields if field not in metadata]
                if missing_fields:
                    return jsonify({
                        'success': False, 
                        'error': f'Missing required metadata fields: {missing_fields}',
                        'required_fields': required_fields
                    }), 400
                
                result = decrypt_ff1_aes(encrypted_data, password, metadata)
                
            elif algorithm == 'Caesar':
                required_fields = ['shift']
                missing_fields = [field for field in required_fields if field not in metadata]
                if missing_fields:
                    return jsonify({
                        'success': False, 
                        'error': f'Missing required metadata fields: {missing_fields}',
                        'required_fields': required_fields
                    }), 400
                
                result = decrypt_caesar(encrypted_data, metadata)
                
            elif algorithm == 'Enigma':
                required_fields = ['configuration']
                missing_fields = [field for field in required_fields if field not in metadata]
                if missing_fields:
                    return jsonify({
                        'success': False, 
                        'error': f'Missing required metadata fields: {missing_fields}',
                        'required_fields': required_fields
                    }), 400
                
                result = decrypt_enigma(encrypted_data, metadata)
                
            elif algorithm == 'Kyber-768':
                required_fields = ['private_key', 'ciphertext']
                missing_fields = [field for field in required_fields if field not in metadata]
                if missing_fields:
                    return jsonify({
                        'success': False, 
                        'error': f'Missing required metadata fields: {missing_fields}',
                        'required_fields': required_fields
                    }), 400
                
                result = decrypt_kyber768(encrypted_data, metadata)
                
            else:
                return jsonify({'success': False, 'error': f'Algorithm {algorithm} not implemented'}), 400
            
            return jsonify({
                'success': True,
                'decrypted_data': result,
                'algorithm': algorithm
            })
            
        except ValueError as ve:
            logger.error(f"Decryption validation error: {str(ve)}")
            return jsonify({
                'success': False, 
                'error': 'Decryption failed - invalid data or password',
                'details': str(ve)
            }), 400
            
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            return jsonify({
                'success': False, 
                'error': 'Decryption failed',
                'details': str(e)
            }), 500
    
    # ================================
    # ALGORITHM INFORMATION API
    # ================================
    
    @app.route('/api/algorithms', methods=['GET'])
    def get_algorithms():
        """Get all available algorithms with metadata"""
        algorithm_info = {
            'algorithms': {
                'text': [
                    {
                        'name': 'AES-256-GCM',
                        'category': 'symmetric',
                        'security_level': 'very_high',
                        'speed': 'fast',
                        'description': 'Advanced Encryption Standard with authentication',
                        'use_cases': ['secure messaging', 'file encryption'],
                        'key_size': 256,
                        'block_size': 128,
                        'recommended': True
                    },
                    {
                        'name': 'ChaCha20-Poly1305',
                        'category': 'symmetric',
                        'security_level': 'very_high',
                        'speed': 'very_fast',
                        'description': 'Modern stream cipher with authentication',
                        'use_cases': ['mobile apps', 'IoT devices'],
                        'key_size': 256,
                        'block_size': 64,
                        'recommended': False
                    },
                    {
                        'name': 'XChaCha20-Poly1305',
                        'category': 'symmetric',
                        'security_level': 'very_high',
                        'speed': 'very_fast',
                        'description': 'Extended nonce ChaCha20 with authentication',
                        'use_cases': ['high-volume encryption', 'long sessions'],
                        'key_size': 256,
                        'nonce_size': 192,
                        'recommended': True
                    },
                    {
                        'name': 'RSA-4096',
                        'category': 'asymmetric',
                        'security_level': 'very_high',
                        'speed': 'slow',
                        'description': 'Public key encryption for key exchange',
                        'use_cases': ['key exchange', 'digital signatures'],
                        'key_size': 4096,
                        'block_size': 'variable',
                        'recommended': False
                    },
                    {
                        'name': 'FF1-AES',
                        'category': 'format_preserving',
                        'security_level': 'high',
                        'speed': 'moderate',
                        'description': 'Format-preserving encryption with AES',
                        'use_cases': ['structured data', 'database encryption'],
                        'key_size': 256,
                        'special_feature': 'preserves_format',
                        'recommended': False
                    },
                    {
                        'name': 'Caesar',
                        'category': 'classical',
                        'security_level': 'educational',
                        'speed': 'very_fast',
                        'description': 'Simple substitution cipher for learning',
                        'use_cases': ['education', 'demonstrations'],
                        'key_size': 'single_shift',
                        'block_size': 'character',
                        'recommended': False
                    },
                    {
                        'name': 'Enigma',
                        'category': 'historical',
                        'security_level': 'educational',
                        'speed': 'fast',
                        'description': 'WWII-era rotor machine simulator',
                        'use_cases': ['education', 'historical demonstration'],
                        'key_size': 'rotor_configuration',
                        'historical_significance': True,
                        'recommended': False
                    }
                ],
                'postquantum': [
                    {
                        'name': 'Kyber-768',
                        'category': 'post_quantum',
                        'security_level': 'quantum_resistant',
                        'speed': 'fast',
                        'description': 'NIST-approved quantum-resistant key exchange',
                        'use_cases': ['future-proof encryption', 'quantum resistance'],
                        'key_size': 768,
                        'quantum_resistant': True,
                        'recommended': True
                    }
                ],
                'image': [
                    {
                        'name': 'AES-256-CBC',
                        'category': 'symmetric',
                        'security_level': 'very_high',
                        'speed': 'fast',
                        'description': 'AES in CBC mode for binary data',
                        'use_cases': ['image encryption', 'file encryption'],
                        'recommended': True
                    }
                ],
                'file': [
                    {
                        'name': 'AES-256-XTS',
                        'category': 'symmetric',
                        'security_level': 'very_high',
                        'speed': 'fast',
                        'description': 'Full disk encryption standard',
                        'use_cases': ['file encryption', 'disk encryption'],
                        'recommended': True
                    }
                ]
            }
        }
        return jsonify(algorithm_info)
    
    @app.route('/api/algorithms/<data_type>', methods=['GET'])
    def get_algorithms_by_type(data_type):
        """Get algorithms applicable to specific data type"""
        all_algorithms = get_algorithms().get_json()
        
        if data_type not in all_algorithms['algorithms']:
            return jsonify({'success': False, 'error': 'Invalid data type'}), 400
        
        return jsonify({
            'data_type': data_type,
            'algorithms': all_algorithms['algorithms'][data_type]
        })

    # ================================
    # MISSING API ENDPOINTS
    # ================================

    @app.route('/api/algorithms/compare', methods=['POST'])
    def compare_algorithms():
        """Compare multiple algorithms across different metrics"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'No JSON data provided'}), 400
            
            algorithms = data.get('algorithms', [])
            data_type = data.get('data_type', 'text')
            
            if not algorithms:
                return jsonify({'success': False, 'error': 'No algorithms provided for comparison'}), 400
            
            if len(algorithms) < 2:
                return jsonify({'success': False, 'error': 'At least 2 algorithms required for comparison'}), 400
            
            # Generate comparison data
            comparison = {
                'success': True,
                'data_type': data_type,
                'algorithms': algorithms,
                'comparison': {
                    'security': {},
                    'performance': {},
                    'use_cases': {},
                    'characteristics': {}
                }
            }
            
            # Mock comparison data for each algorithm
            for algo in algorithms:
                if algo == 'AES-256-GCM':
                    comparison['comparison']['security'][algo] = 95
                    comparison['comparison']['performance'][algo] = 90
                    comparison['comparison']['use_cases'][algo] = ['High-speed encryption', 'Authenticated encryption']
                    comparison['comparison']['characteristics'][algo] = {
                        'type': 'Symmetric',
                        'key_size': '256 bits',
                        'recommended': True
                    }
                elif algo == 'ChaCha20-Poly1305':
                    comparison['comparison']['security'][algo] = 96
                    comparison['comparison']['performance'][algo] = 95
                    comparison['comparison']['use_cases'][algo] = ['Mobile devices', 'Streaming data']
                    comparison['comparison']['characteristics'][algo] = {
                        'type': 'Stream Cipher',
                        'key_size': '256 bits',
                        'recommended': True
                    }
                elif algo == 'XChaCha20-Poly1305':
                    comparison['comparison']['security'][algo] = 97
                    comparison['comparison']['performance'][algo] = 95
                    comparison['comparison']['use_cases'][algo] = ['High-volume encryption', 'Extended nonce space']
                    comparison['comparison']['characteristics'][algo] = {
                        'type': 'Extended Stream Cipher',
                        'key_size': '256 bits',
                        'nonce_size': '192 bits',
                        'recommended': True
                    }
                elif algo == 'RSA-4096':
                    comparison['comparison']['security'][algo] = 98
                    comparison['comparison']['performance'][algo] = 40
                    comparison['comparison']['use_cases'][algo] = ['Key exchange', 'Digital signatures']
                    comparison['comparison']['characteristics'][algo] = {
                        'type': 'Asymmetric',
                        'key_size': '4096 bits',
                        'recommended': False
                    }
                elif algo == 'FF1-AES':
                    comparison['comparison']['security'][algo] = 88
                    comparison['comparison']['performance'][algo] = 75
                    comparison['comparison']['use_cases'][algo] = ['Format-preserving encryption', 'Database encryption']
                    comparison['comparison']['characteristics'][algo] = {
                        'type': 'Format-Preserving',
                        'key_size': '256 bits',
                        'special_feature': 'Preserves format',
                        'recommended': False
                    }
                elif algo == 'Caesar':
                    comparison['comparison']['security'][algo] = 10
                    comparison['comparison']['performance'][algo] = 100
                    comparison['comparison']['use_cases'][algo] = ['Education', 'Demonstrations']
                    comparison['comparison']['characteristics'][algo] = {
                        'type': 'Classical',
                        'key_size': 'Variable',
                        'recommended': False
                    }
                elif algo == 'Enigma':
                    comparison['comparison']['security'][algo] = 15
                    comparison['comparison']['performance'][algo] = 95
                    comparison['comparison']['use_cases'][algo] = ['Historical education', 'Cryptography learning']
                    comparison['comparison']['characteristics'][algo] = {
                        'type': 'Historical Rotor Machine',
                        'key_size': 'Rotor configuration',
                        'historical_significance': True,
                        'recommended': False
                    }
                elif algo == 'Kyber-768':
                    comparison['comparison']['security'][algo] = 99
                    comparison['comparison']['performance'][algo] = 85
                    comparison['comparison']['use_cases'][algo] = ['Post-quantum security', 'Future-proof encryption']
                    comparison['comparison']['characteristics'][algo] = {
                        'type': 'Post-Quantum KEM',
                        'key_size': '768 bits',
                        'quantum_resistant': True,
                        'recommended': True
                    }
            
            return jsonify(comparison)
            
        except Exception as e:
            logger.error(f"Algorithm comparison error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Comparison failed',
                'details': str(e)
            }), 500

    @app.route('/api/algorithms/recommend', methods=['POST'])
    def recommend_algorithm():
        """Get algorithm recommendations based on requirements"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'No JSON data provided'}), 400
            
            data_type = data.get('data_type', 'text')
            security_level = data.get('security_level', 'high')
            performance_priority = data.get('performance_priority', 'balanced')
            use_case = data.get('use_case', 'general')
            
            # Generate recommendations based on criteria
            recommendations = []
            
            if data_type == 'text':
                if security_level in ['very_high', 'high']:
                    recommendations.append({
                        'algorithm': 'AES-256-GCM',
                        'score': 95,
                        'reason': 'Industry standard with authentication',
                        'pros': ['Hardware accelerated', 'Proven security', 'Wide support'],
                        'cons': ['IV management required']
                    })
                    
                    recommendations.append({
                        'algorithm': 'XChaCha20-Poly1305',
                        'score': 94,
                        'reason': 'Extended nonce space prevents reuse issues',
                        'pros': ['192-bit nonce', 'Software optimized', 'Modern design'],
                        'cons': ['Less mature than AES', 'Limited hardware support']
                    })
                
                if performance_priority == 'high':
                    recommendations.append({
                        'algorithm': 'ChaCha20-Poly1305',
                        'score': 90,
                        'reason': 'Optimized for high performance',
                        'pros': ['Software optimized', 'Mobile friendly', 'Constant time'],
                        'cons': ['Newer algorithm', 'Less hardware support']
                    })
                
                if use_case == 'database' or 'format' in use_case:
                    recommendations.append({
                        'algorithm': 'FF1-AES',
                        'score': 82,
                        'reason': 'Preserves data format for database compatibility',
                        'pros': ['Format preserving', 'NIST approved', 'Database friendly'],
                        'cons': ['Slower than standard AES', 'Complex implementation']
                    })
                    
                if security_level == 'educational':
                    recommendations.append({
                        'algorithm': 'Caesar',
                        'score': 60,
                        'reason': 'Simple for learning cryptography',
                        'pros': ['Easy to understand', 'Fast computation'],
                        'cons': ['No real security', 'Easily broken']
                    })
                    
                    recommendations.append({
                        'algorithm': 'Enigma',
                        'score': 65,
                        'reason': 'Historical significance and rotor mechanism education',
                        'pros': ['Historical value', 'Complex mechanism', 'Educational'],
                        'cons': ['Completely broken', 'No modern security']
                    })
            
            elif data_type == 'postquantum' or 'quantum' in use_case:
                recommendations.append({
                    'algorithm': 'Kyber-768',
                    'score': 98,
                    'reason': 'NIST-approved post-quantum security',
                    'pros': ['Quantum resistant', 'NIST standardized', 'Future-proof'],
                    'cons': ['Larger key sizes', 'Limited deployment']
                })
            
            elif data_type == 'file':
                if security_level in ['very_high', 'high']:
                    recommendations.append({
                        'algorithm': 'AES-256-GCM',
                        'score': 96,
                        'reason': 'Excellent for file encryption with integrity',
                        'pros': ['Built-in authentication', 'Hardware accelerated', 'Streaming capable'],
                        'cons': ['IV management critical for files']
                    })
                    
                    recommendations.append({
                        'algorithm': 'XChaCha20-Poly1305',
                        'score': 94,
                        'reason': 'Large nonce space ideal for many files',
                        'pros': ['192-bit nonce prevents collisions', 'Fast streaming', 'Modern design'],
                        'cons': ['Less hardware acceleration']
                    })
                    
                    recommendations.append({
                        'algorithm': 'AES-256-XTS',
                        'score': 90,
                        'reason': 'Designed specifically for storage encryption',
                        'pros': ['Sector-based encryption', 'No size expansion', 'IEEE standard'],
                        'cons': ['No built-in authentication', 'Complex implementation']
                    })
                
                if performance_priority == 'high':
                    recommendations.append({
                        'algorithm': 'ChaCha20-Poly1305',
                        'score': 88,
                        'reason': 'High performance file streaming',
                        'pros': ['Software optimized', 'Parallel processing', 'Low memory'],
                        'cons': ['Limited hardware support']
                    })
            
            elif data_type == 'image':
                recommendations.append({
                    'algorithm': 'AES-256-GCM',
                    'score': 95,
                    'reason': 'Best for image files with authentication',
                    'pros': ['Preserves image quality', 'Fast processing', 'Authenticated'],
                    'cons': ['Slight size increase']
                })
                
                recommendations.append({
                    'algorithm': 'AES-256-CBC',
                    'score': 85,
                    'reason': 'Traditional choice for image encryption',
                    'pros': ['Wide support', 'Efficient for large images', 'Deterministic size'],
                    'cons': ['No authentication', 'Padding required']
                })
                
                recommendations.append({
                    'algorithm': 'ChaCha20-Poly1305',
                    'score': 90,
                    'reason': 'Modern stream cipher for images',
                    'pros': ['Software optimized', 'Stream processing', 'No padding'],
                    'cons': ['Less common for images']
                })
            
            else:
                # Default recommendations for unknown data types
                recommendations.append({
                    'algorithm': 'AES-256-GCM',
                    'score': 90,
                    'reason': 'Versatile choice for any data type',
                    'pros': ['Universal support', 'Hardware acceleration', 'Authenticated'],
                    'cons': ['IV management required']
                })
                
                recommendations.append({
                    'algorithm': 'ChaCha20-Poly1305',
                    'score': 85,
                    'reason': 'Modern alternative for any data',
                    'pros': ['Software optimized', 'Simple nonce handling', 'Authenticated'],
                    'cons': ['Less hardware support']
                })
            
            # Sort by score
            recommendations.sort(key=lambda x: x['score'], reverse=True)
            
            return jsonify({
                'success': True,
                'data_type': data_type,
                'requirements': {
                    'security_level': security_level,
                    'performance_priority': performance_priority,
                    'use_case': use_case
                },
                'recommendations': recommendations,
                'top_recommendation': recommendations[0] if recommendations else None
            })
            
        except Exception as e:
            logger.error(f"Recommendation error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Failed to generate recommendations',
                'details': str(e)
            }), 500

    @app.route('/api/algorithms/<algorithm_name>/details', methods=['GET'])
    def algorithm_details(algorithm_name):
        """Get detailed information about specific algorithm"""
        try:
            # Algorithm information database
            algorithm_info = {
                'AES-256-GCM': {
                    'full_name': 'Advanced Encryption Standard 256-bit Galois Counter Mode',
                    'category': 'Symmetric Block Cipher',
                    'security_level': 'Very High',
                    'description': 'Industry standard encryption with built-in authentication',
                    'key_size': '256 bits',
                    'block_size': '128 bits',
                    'strengths': ['Hardware acceleration', 'Authenticated encryption', 'Government approved'],
                    'weaknesses': ['IV reuse vulnerabilities', 'Complex implementation'],
                    'use_cases': ['HTTPS/TLS', 'VPNs', 'File encryption'],
                    'recommended': True
                },
                'ChaCha20-Poly1305': {
                    'full_name': 'ChaCha20 Stream Cipher with Poly1305 Authentication',
                    'category': 'Stream Cipher',
                    'security_level': 'Very High',
                    'description': 'Modern stream cipher optimized for software',
                    'key_size': '256 bits',
                    'block_size': '64 bytes',
                    'strengths': ['Software optimized', 'Constant time', 'Mobile friendly'],
                    'weaknesses': ['Less hardware support', 'Newer algorithm'],
                    'use_cases': ['Mobile apps', 'IoT devices', 'Real-time communication'],
                    'recommended': True
                },
                'RSA-4096': {
                    'full_name': 'Rivest-Shamir-Adleman 4096-bit',
                    'category': 'Asymmetric Encryption',
                    'security_level': 'Very High',
                    'description': 'Public key encryption for secure key exchange',
                    'key_size': '4096 bits',
                    'block_size': 'Variable',
                    'strengths': ['Public key cryptography', 'Digital signatures', 'Key exchange'],
                    'weaknesses': ['Slow performance', 'Large key sizes', 'Quantum vulnerable'],
                    'use_cases': ['SSL certificates', 'Email encryption', 'Code signing'],
                    'recommended': False
                },
                'Caesar': {
                    'full_name': 'Caesar Substitution Cipher',
                    'category': 'Classical Cipher',
                    'security_level': 'Educational',
                    'description': 'Simple substitution cipher for learning',
                    'key_size': '5 bits (shift value)',
                    'block_size': 'Character',
                    'strengths': ['Easy to understand', 'Fast computation', 'Historical significance'],
                    'weaknesses': ['No security', 'Frequency analysis', 'Only 25 keys'],
                    'use_cases': ['Education', 'Puzzles', 'Historical recreation'],
                    'recommended': False
                },
                'XChaCha20-Poly1305': {
                    'full_name': 'Extended ChaCha20 with Poly1305 Authentication',
                    'category': 'Stream Cipher',
                    'security_level': 'Very High',
                    'description': 'Extended nonce version of ChaCha20-Poly1305',
                    'key_size': '256 bits',
                    'nonce_size': '192 bits',
                    'strengths': ['Extended nonce space', 'Software optimized', 'Authenticated encryption'],
                    'weaknesses': ['Less hardware support', 'Newer algorithm'],
                    'use_cases': ['High-volume encryption', 'Long sessions', 'IoT devices'],
                    'recommended': True
                },
                'FF1-AES': {
                    'full_name': 'FF1 Format-Preserving Encryption with AES',
                    'category': 'Format-Preserving Encryption',
                    'security_level': 'High',
                    'description': 'NIST-approved format-preserving encryption',
                    'key_size': '256 bits',
                    'special_feature': 'Format preservation',
                    'strengths': ['Preserves data format', 'NIST approved', 'Database friendly'],
                    'weaknesses': ['Slower than standard AES', 'Complex implementation'],
                    'use_cases': ['Database encryption', 'Credit card tokenization', 'Legacy systems'],
                    'recommended': False
                },
                'Enigma': {
                    'full_name': 'Enigma Machine Simulator',
                    'category': 'Historical Cipher',
                    'security_level': 'Educational',
                    'description': 'WWII-era rotor cipher machine',
                    'key_size': 'Rotor configuration',
                    'historical_significance': 'Breaking it shortened WWII by 2-4 years',
                    'strengths': ['Historical value', 'Complex mechanism', 'Educational insight'],
                    'weaknesses': ['Completely broken', 'Vulnerable to frequency analysis', 'Known plaintext attacks'],
                    'use_cases': ['Cryptography education', 'Historical demonstration', 'Museum exhibits'],
                    'recommended': False
                },
                'Kyber-768': {
                    'full_name': 'Kyber-768 Post-Quantum Key Encapsulation',
                    'category': 'Post-Quantum Cryptography',
                    'security_level': 'Quantum Resistant',
                    'description': 'NIST-selected quantum-resistant key exchange',
                    'key_size': '768 bits',
                    'security_level_bits': '192 bits',
                    'strengths': ['Quantum resistant', 'NIST standardized', 'Lattice-based security'],
                    'weaknesses': ['Larger key sizes', 'Limited real-world deployment', 'Newer technology'],
                    'use_cases': ['Future-proof encryption', 'Long-term data protection', 'Hybrid protocols'],
                    'recommended': True
                }
            }
            
            if algorithm_name not in algorithm_info:
                return jsonify({
                    'success': False,
                    'error': f'Algorithm {algorithm_name} not found',
                    'available_algorithms': list(algorithm_info.keys())
                }), 404
            
            details = algorithm_info[algorithm_name]
            details['algorithm'] = algorithm_name
            
            return jsonify({
                'success': True,
                'details': details
            })
            
        except Exception as e:
            logger.error(f"Algorithm details error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Failed to get algorithm details',
                'details': str(e)
            }), 500

    @app.route('/api/system/status', methods=['GET'])
    def system_status():
        """Get detailed system status"""
        try:
            import psutil
            import platform
            
            # System information
            system_info = {
                'platform': platform.system(),
                'python_version': platform.python_version(),
                'cpu_count': psutil.cpu_count() if hasattr(psutil, 'cpu_count') else 'Unknown',
                'memory_available': f"{psutil.virtual_memory().available // (1024**3)} GB" if hasattr(psutil, 'virtual_memory') else 'Unknown'
            }
            
            # Application statistics
            total_algorithms = (len(ALGORITHMS['text']) + len(ALGORITHMS['image']) + 
                              len(ALGORITHMS['file']) + len(ALGORITHMS.get('postquantum', [])))
            app_stats = {
                'algorithms_available': total_algorithms,
                'algorithm_categories': list(ALGORITHMS.keys()),
                'status': 'Running',
                'version': '1.0.0',
                'extended_algorithms': True
            }
            
            return jsonify({
                'success': True,
                'status': 'healthy',
                'system': system_info,
                'application': app_stats,
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"System status error: {str(e)}")
            return jsonify({
                'success': True,  # Still return success with basic info
                'status': 'healthy',
                'system': {'platform': 'Unknown'},
                'application': {'status': 'Running'},
                'error': 'Could not gather detailed system info',
                'timestamp': datetime.utcnow().isoformat()
            })
    
    # ================================
    # FILE UPLOAD API
    # ================================
    
    @app.route('/api/encrypt/file', methods=['POST'])
    def encrypt_file():
        """Handle file upload and encryption"""
        try:
            if 'file' not in request.files:
                return jsonify({'success': False, 'error': 'No file provided'}), 400
            
            file = request.files['file']
            algorithm = request.form.get('algorithm', 'AES-256-GCM')
            password = request.form.get('password')
            
            if not password:
                return jsonify({'success': False, 'error': 'Password required for file encryption'}), 400
            
            # Handle file upload and encryption
            result = handle_file_upload(file, algorithm, password)
            return jsonify(result)
            
        except Exception as e:
            logger.error(f"File encryption error: {str(e)}")
            return jsonify({'success': False, 'error': 'File encryption failed'}), 500
    
    @app.route('/api/download/<file_id>', methods=['GET'])
    def download_file(file_id):
        """Download and decrypt uploaded file"""
        try:
            # Get password from query parameter or header
            password = request.args.get('password') or request.headers.get('X-Decrypt-Password')
            
            if not password:
                return jsonify({
                    'success': False,
                    'error': 'Password required for file decryption',
                    'details': 'Provide password as query parameter (?password=...) or X-Decrypt-Password header'
                }), 400
            
            # Retrieve and decrypt file
            decrypted_content, filename, mime_type = get_file_for_download(file_id, password)
            
            if decrypted_content is None:
                return jsonify({
                    'success': False,
                    'error': 'File not found or invalid password',
                    'file_id': file_id
                }), 404
            
            # Create file-like object
            file_obj = io.BytesIO(decrypted_content)
            
            # Prepare response
            response = make_response(send_file(
                file_obj,
                as_attachment=True,
                download_name=filename,
                mimetype=mime_type
            ))
            
            # Add security headers
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Download-Options'] = 'noopen'
            
            logger.info(f"File downloaded: {filename} ({file_id})")
            return response
            
        except Exception as e:
            logger.error(f"File download error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Download failed',
                'details': str(e)
            }), 500
    
    @app.route('/api/files', methods=['GET'])
    def list_files():
        """List uploaded files (metadata only)"""
        try:
            # Get pagination parameters
            page = int(request.args.get('page', 1))
            per_page = min(int(request.args.get('per_page', 50)), 100)
            
            # Calculate offset
            offset = (page - 1) * per_page
            
            # Get files list
            all_files = list_uploaded_files(offset + per_page)
            files = all_files[offset:offset + per_page]
            
            return jsonify({
                'success': True,
                'files': files,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': len(all_files),
                    'has_next': len(all_files) > offset + per_page,
                    'has_prev': page > 1
                },
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"File listing error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Failed to list files',
                'details': str(e)
            }), 500
    
    @app.route('/api/files/<file_id>', methods=['DELETE'])
    def delete_file(file_id):
        """Delete uploaded file"""
        try:
            success = delete_uploaded_file(file_id)
            
            if success:
                return jsonify({
                    'success': True,
                    'message': f'File {file_id} deleted successfully',
                    'file_id': file_id
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'File not found or deletion failed',
                    'file_id': file_id
                }), 404
                
        except Exception as e:
            logger.error(f"File deletion error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Deletion failed',
                'details': str(e)
            }), 500
    
    # ================================
    # UTILITY ENDPOINTS
    # ================================
    
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'algorithms_loaded': len(ALGORITHMS['text']) + len(ALGORITHMS['image']) + len(ALGORITHMS['file'])
        })
    
    @app.route('/api/test/encryption', methods=['POST'])
    def test_encryption():
        """Test encryption with sample data"""
        try:
            data = request.get_json() or {}
            algorithm = data.get('algorithm', 'AES-256-GCM')
            
            # Test data
            test_message = "Hello World! This is a test message for encryption verification."
            test_password = "test123"
            
            # Encrypt
            if algorithm == 'AES-256-GCM':
                encrypted_result = encrypt_aes_gcm(test_message, test_password, {})
                decrypted_result = decrypt_aes_gcm(
                    encrypted_result['ciphertext'], 
                    test_password, 
                    encrypted_result
                )
            elif algorithm == 'ChaCha20-Poly1305':
                encrypted_result = encrypt_chacha20(test_message, test_password, {})
                decrypted_result = decrypt_chacha20(
                    encrypted_result['ciphertext'], 
                    test_password, 
                    encrypted_result
                )
            elif algorithm == 'XChaCha20-Poly1305':
                encrypted_result = encrypt_xchacha20(test_message, test_password, {})
                decrypted_result = decrypt_xchacha20(
                    encrypted_result['ciphertext'], 
                    test_password, 
                    encrypted_result
                )
            elif algorithm == 'RSA-4096':
                encrypted_result = encrypt_rsa4096(test_message, {})
                decrypted_result = decrypt_rsa4096(
                    encrypted_result['ciphertext'], 
                    encrypted_result
                )
            elif algorithm == 'FF1-AES':
                # FF1 needs numeric input for credit card format
                ff1_test_data = '1234567890123456'
                encrypted_result = encrypt_ff1_aes(ff1_test_data, test_password, {})
                decrypted_result = decrypt_ff1_aes(
                    encrypted_result['ciphertext'], 
                    test_password, 
                    encrypted_result
                )
                # Update test message for FF1 verification
                test_message = ff1_test_data
            elif algorithm == 'Caesar':
                encrypted_result = encrypt_caesar(test_message, {'shift': 3})
                decrypted_result = decrypt_caesar(encrypted_result['ciphertext'], {'shift': 3})
            elif algorithm == 'Enigma':
                try:
                    encrypted_result = encrypt_enigma(test_message, {})
                    decrypted_result = decrypt_enigma(encrypted_result['ciphertext'], encrypted_result)
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'algorithm': algorithm,
                        'test_message': test_message,
                        'encryption_successful': False,
                        'decryption_successful': False,
                        'round_trip_successful': False,
                        'error': f'Enigma test failed: {str(e)}',
                        'timestamp': datetime.utcnow().isoformat()
                    })
            elif algorithm == 'Kyber-768':
                encrypted_result = encrypt_kyber768(test_message, {})
                decrypted_result = decrypt_kyber768(encrypted_result['ciphertext'], encrypted_result)
            else:
                return jsonify({
                    'success': False,
                    'error': f'Test not implemented for {algorithm}'
                }), 400
            
            # Verify
            success = decrypted_result == test_message
            
            return jsonify({
                'success': success,
                'algorithm': algorithm,
                'test_message': test_message,
                'encryption_successful': True,
                'decryption_successful': success,
                'round_trip_successful': success,
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Encryption test error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Encryption test failed',
                'details': str(e)
            }), 500
    
    @app.errorhandler(413)
    def too_large(e):
        return jsonify({'success': False, 'error': 'File too large. Maximum size: 16MB'}), 413
    
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'success': False, 'error': 'Endpoint not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    
    return app

# ================================
# ENCRYPTION IMPLEMENTATIONS
# ================================

def encrypt_aes_gcm(data, password, options):
    """Encrypt data using AES-256-GCM"""
    crypto = AESCrypto()
    
    # Convert string data to bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Generate salt and derive key
    salt = generate_salt()
    key = derive_key(password, salt)
    
    # Encrypt data
    result = crypto.encrypt_gcm(data, key)
    
    return {
        'ciphertext': base64.b64encode(result['ciphertext']).decode('utf-8'),
        'iv': base64.b64encode(result['iv']).decode('utf-8'),
        'tag': base64.b64encode(result['tag']).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8')
    }

def decrypt_aes_gcm(encrypted_data, password, metadata):
    """Decrypt AES-256-GCM encrypted data"""
    crypto = AESCrypto()
    
    # Decode base64 data
    ciphertext = base64.b64decode(encrypted_data)
    iv = base64.b64decode(metadata['iv'])
    tag = base64.b64decode(metadata['tag'])
    salt = base64.b64decode(metadata['salt'])
    
    # Derive key
    key = derive_key(password, salt)
    
    # Decrypt
    result = crypto.decrypt_gcm(ciphertext, key, iv, tag)
    return result.decode('utf-8')

def encrypt_chacha20(data, password, options):
    """Encrypt data using ChaCha20-Poly1305"""
    crypto = ChaCha20Crypto()
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    salt = generate_salt()
    key = derive_key(password, salt, length=32)  # ChaCha20 uses 32-byte key
    
    result = crypto.encrypt(data, key)
    
    return {
        'ciphertext': base64.b64encode(result['ciphertext']).decode('utf-8'),
        'nonce': base64.b64encode(result['nonce']).decode('utf-8'),
        'tag': base64.b64encode(result['tag']).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8')
    }

def decrypt_chacha20(encrypted_data, password, metadata):
    """Decrypt ChaCha20-Poly1305 encrypted data"""
    crypto = ChaCha20Crypto()
    
    ciphertext = base64.b64decode(encrypted_data)
    nonce = base64.b64decode(metadata['nonce'])
    tag = base64.b64decode(metadata['tag'])
    salt = base64.b64decode(metadata['salt'])
    
    key = derive_key(password, salt, length=32)
    
    result = crypto.decrypt(ciphertext, key, nonce, tag)
    return result.decode('utf-8')

def encrypt_rsa(data, options):
    """Encrypt data using RSA-4096"""
    crypto = RSACrypto()
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Generate key pair
    private_key, public_key = crypto.generate_keypair(4096)
    
    # Encrypt with public key
    ciphertext = crypto.encrypt(data, public_key)
    
    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'public_key': crypto.serialize_public_key(public_key),
        'private_key': crypto.serialize_private_key(private_key)  # In real app, store securely
    }

def decrypt_rsa(encrypted_data, metadata):
    """Decrypt RSA encrypted data"""
    crypto = RSACrypto()
    
    ciphertext = base64.b64decode(encrypted_data)
    private_key = crypto.deserialize_private_key(metadata['private_key'])
    
    result = crypto.decrypt(ciphertext, private_key)
    return result.decode('utf-8')

def encrypt_caesar(data, options):
    """Encrypt data using Caesar cipher"""
    cipher = CaesarCipher()
    shift = options.get('shift', 3)
    
    result = cipher.encrypt(data, shift)
    
    return {
        'ciphertext': result,
        'shift': shift
    }

def decrypt_caesar(encrypted_data, metadata):
    """Decrypt Caesar cipher"""
    cipher = CaesarCipher()
    shift = metadata.get('shift', 3)
    
    return cipher.decrypt(encrypted_data, shift)

# ================================
# EXTENDED ALGORITHM IMPLEMENTATIONS
# ================================

def encrypt_xchacha20(data, password, options):
    """Encrypt data using XChaCha20-Poly1305"""
    cipher = XChaCha20Poly1305Cipher()
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Generate salt and derive key
    salt = generate_salt()
    key = derive_key(password, salt, length=32)
    
    result = cipher.encrypt(data, key)
    
    return {
        'ciphertext': result['ciphertext'],
        'nonce': result['nonce'],
        'algorithm': result['algorithm'],
        'salt': base64.b64encode(salt).decode('utf-8')
    }

def decrypt_xchacha20(encrypted_data, password, metadata):
    """Decrypt XChaCha20-Poly1305 encrypted data"""
    cipher = XChaCha20Poly1305Cipher()
    
    # Derive key
    salt = base64.b64decode(metadata['salt'])
    key = derive_key(password, salt, length=32)
    
    # Decrypt
    result = cipher.decrypt(encrypted_data, key, metadata['nonce'])
    return result.decode('utf-8')

def encrypt_ff1_aes(data, password, options):
    """Encrypt data using FF1-AES format-preserving encryption"""
    cipher = FF1AESCipher()
    
    # Generate salt and derive key
    salt = generate_salt()
    key = derive_key(password, salt, length=32)
    
    # Use tweak from options or generate one
    tweak = options.get('tweak', b'')
    if isinstance(tweak, str):
        tweak = tweak.encode('utf-8')
    
    result = cipher.encrypt(data, key, tweak)
    
    return {
        'ciphertext': result['ciphertext'],
        'format': result['format'],
        'algorithm': result['algorithm'],
        'tweak': result['tweak'],
        'salt': base64.b64encode(salt).decode('utf-8')
    }

def decrypt_ff1_aes(encrypted_data, password, metadata):
    """Decrypt FF1-AES encrypted data"""
    cipher = FF1AESCipher()
    
    # Derive key
    salt = base64.b64decode(metadata['salt'])
    key = derive_key(password, salt, length=32)
    
    # Get tweak
    tweak = base64.b64decode(metadata.get('tweak', '')) if metadata.get('tweak') else b''
    
    # Decrypt
    result = cipher.decrypt(encrypted_data, key, tweak)
    return result

def encrypt_enigma(data, options):
    """Encrypt data using Enigma machine"""
    enigma = EnigmaMachine()
    
    # Get configuration from options
    config = options.get('enigma_config', {
        'rotors': ['I', 'II', 'III'],
        'positions': [0, 0, 0],
        'plugboard': {}
    })
    
    result = enigma.encrypt(data, config)
    
    return {
        'ciphertext': result['ciphertext'],
        'algorithm': result['algorithm'],
        'configuration': result['configuration'],
        'historical_note': result['historical_note']
    }

def decrypt_enigma(encrypted_data, metadata):
    """Decrypt Enigma encrypted data"""
    enigma = EnigmaMachine()
    
    # Get configuration from metadata
    config = metadata['configuration']
    
    result = enigma.decrypt(encrypted_data, config)
    return result

def encrypt_kyber768(data, options):
    """Encrypt data using Kyber-768 (key encapsulation)"""
    kyber = Kyber768()
    
    # Generate keypair
    private_key, public_key = kyber.generate_keypair()
    
    # Encapsulate to get shared secret
    shared_secret, ciphertext = kyber.encapsulate(public_key)
    
    # Use shared secret to encrypt data with AES
    aes_crypto = AESCrypto()
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    aes_result = aes_crypto.encrypt_gcm(data, shared_secret)
    
    return {
        'ciphertext': base64.b64encode(aes_result['ciphertext']).decode('utf-8'),
        'kyber_ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'public_key': base64.b64encode(public_key).decode('utf-8'),
        'private_key': base64.b64encode(private_key).decode('utf-8'),  # Store securely in production
        'aes_iv': base64.b64encode(aes_result['iv']).decode('utf-8'),
        'aes_tag': base64.b64encode(aes_result['tag']).decode('utf-8'),
        'algorithm': 'Kyber-768'
    }

def decrypt_kyber768(encrypted_data, metadata):
    """Decrypt Kyber-768 encrypted data"""
    kyber = Kyber768()
    
    # Get components
    private_key = base64.b64decode(metadata['private_key'])
    kyber_ciphertext = base64.b64decode(metadata['kyber_ciphertext'])
    
    # Decapsulate to recover shared secret
    shared_secret = kyber.decapsulate(kyber_ciphertext, private_key)
    
    # Decrypt data with AES using shared secret
    aes_crypto = AESCrypto()
    ciphertext = base64.b64decode(encrypted_data)
    iv = base64.b64decode(metadata['aes_iv'])
    tag = base64.b64decode(metadata['aes_tag'])
    
    result = aes_crypto.decrypt_gcm(ciphertext, shared_secret, iv, tag)
    return result.decode('utf-8')

# ================================
# APPLICATION ENTRY POINT
# ================================

if __name__ == '__main__':
    app = create_app()
    
    # Development configuration
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    port = int(os.environ.get('PORT', 5000))
    
    print(f"""
Universal Encryption Platform Backend
=====================================
Phase 1: Core Foundation with Extended Algorithms

Web Demo: http://localhost:{port}
Interactive Demo: http://localhost:{port}/demo
API Docs: http://localhost:{port}/docs
Health Check: http://localhost:{port}/api/health

Available Algorithms:
* AES-256-GCM (Recommended)
* ChaCha20-Poly1305  
* XChaCha20-Poly1305 (Extended nonce)
* FF1-AES (Format-preserving)
* RSA-4096
* Kyber-768 (Post-quantum)
* Caesar Cipher (Educational)
* Enigma Machine (Historical)
""")
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode)