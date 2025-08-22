"""
Response Formatting Utilities
Format API responses consistently across all endpoints
"""

import base64
from datetime import datetime
from typing import Dict, Any, Optional
from crypto.utils import get_algorithm_info, format_bytes
import logging

logger = logging.getLogger(__name__)

def format_response(encryption_result: Dict[str, Any], 
                   algorithm: str = None, 
                   data_type: str = None, 
                   options: Dict[str, Any] = None,
                   success: bool = None) -> Dict[str, Any]:
    """
    Format response with consistent structure
    
    Args:
        encryption_result: Raw encryption result or response data
        algorithm: Algorithm used (optional)
        data_type: Type of data encrypted (optional)
        options: Encryption options (optional)
        success: Success flag for simple responses (optional)
    
    Returns:
        Formatted response dictionary
    """
    try:
        # Handle simple case where only data and success are provided
        if algorithm is None and data_type is None and success is not None:
            response = {'success': success}
            response.update(encryption_result)
            return response
            
        # Ensure defaults for required parameters
        if options is None:
            options = {}
            
        # Get algorithm metadata
        algo_info = get_algorithm_info(algorithm)
        
        # Base response structure
        response = {
            'success': True,
            'encrypted_data': None,
            'metadata': {
                'algorithm': algorithm,
                'data_type': data_type,
                'timestamp': datetime.utcnow().isoformat(),
                'algorithm_info': algo_info
            }
        }
        
        # Format encrypted data based on output format
        output_format = options.get('output_format', 'base64')
        
        if algorithm in ['AES-256-GCM', 'ChaCha20-Poly1305']:
            # Authenticated encryption
            response['encrypted_data'] = encryption_result['ciphertext']
            response['metadata'].update({
                'iv': encryption_result.get('iv'),
                'nonce': encryption_result.get('nonce'),
                'tag': encryption_result['tag'],
                'salt': encryption_result['salt'],
                'key_derivation': 'PBKDF2',
                'iterations': 100000
            })
            
        elif algorithm in ['AES-256-CBC', 'AES-256-XTS']:
            # Block cipher modes
            response['encrypted_data'] = encryption_result['ciphertext']
            response['metadata'].update({
                'iv': encryption_result.get('iv'),
                'salt': encryption_result['salt'],
                'key_derivation': 'PBKDF2'
            })
            
        elif algorithm == 'RSA-4096':
            # Asymmetric encryption
            response['encrypted_data'] = encryption_result['ciphertext']
            response['metadata'].update({
                'public_key': encryption_result['public_key'],
                'private_key': encryption_result['private_key'],  # Handle securely in production
                'key_size': 4096
            })
            
        elif algorithm == 'XChaCha20-Poly1305':
            # Extended ChaCha20 with Poly1305 authentication
            response['encrypted_data'] = encryption_result['ciphertext']
            response['metadata'].update({
                'nonce': encryption_result['nonce'],
                'salt': encryption_result['salt']
            })
        
        elif algorithm == 'FF1-AES':
            # Format-preserving encryption
            response['encrypted_data'] = encryption_result['ciphertext']
            response['metadata'].update({
                'format': encryption_result['format'],
                'tweak': encryption_result['tweak'],
                'salt': encryption_result['salt']
            })
        
        elif algorithm == 'Enigma':
            # Historical Enigma machine
            response['encrypted_data'] = encryption_result['ciphertext']
            if 'configuration' in encryption_result:
                response['metadata']['configuration'] = encryption_result['configuration']
            if 'rotor_settings' in encryption_result:
                response['metadata']['rotor_settings'] = encryption_result['rotor_settings']
        
        elif algorithm in ['Caesar', 'Vigenere', 'ROT13', 'Atbash', 'Playfair']:
            # Classical ciphers
            response['encrypted_data'] = encryption_result['ciphertext']
            if 'shift' in encryption_result:
                response['metadata']['shift'] = encryption_result['shift']
            if 'keyword' in encryption_result:
                response['metadata']['keyword'] = encryption_result['keyword']
        
        # Add file information if available
        if 'file_info' in options:
            file_info = options['file_info']
            response['file_info'] = {
                'original_name': file_info.get('filename'),
                'original_size': file_info.get('size'),
                'original_type': file_info.get('mime_type'),
                'encrypted_size': len(response['encrypted_data']) if isinstance(response['encrypted_data'], str) else 0,
                'size_formatted': format_bytes(file_info.get('size', 0))
            }
        
        # Add performance metrics if requested
        if options.get('include_metrics', False):
            response['metrics'] = {
                'algorithm_speed': algo_info.get('performance', 'Unknown'),
                'security_level': algo_info.get('security_level', 'Unknown'),
                'recommended_use': get_algorithm_recommendations(algorithm, data_type)
            }
        
        logger.info(f"Response formatted for {algorithm} on {data_type}")
        return response
        
    except Exception as e:
        logger.error(f"Response formatting error: {str(e)}")
        return format_error_response(str(e))

def format_error_response(error_message: str, 
                         error_code: Optional[str] = None) -> Dict[str, Any]:
    """
    Format error response consistently
    
    Args:
        error_message: Error description
        error_code: Optional error code
    
    Returns:
        Formatted error response
    """
    response = {
        'success': False,
        'error': error_message,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    if error_code:
        response['error_code'] = error_code
    
    return response

def format_algorithm_list_response(algorithms: Dict[str, list], 
                                 data_type: Optional[str] = None) -> Dict[str, Any]:
    """
    Format algorithm list response with detailed information
    
    Args:
        algorithms: Algorithm dictionary
        data_type: Specific data type filter
    
    Returns:
        Formatted algorithm list
    """
    try:
        response = {
            'success': True,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if data_type:
            # Single data type
            if data_type not in algorithms:
                return format_error_response(f"Unsupported data type: {data_type}")
            
            response['data_type'] = data_type
            response['algorithms'] = [
                format_algorithm_info(algo, data_type) 
                for algo in algorithms[data_type]
            ]
        else:
            # All data types
            response['algorithms'] = {}
            for dtype, algo_list in algorithms.items():
                response['algorithms'][dtype] = [
                    format_algorithm_info(algo, dtype) 
                    for algo in algo_list
                ]
        
        return response
        
    except Exception as e:
        logger.error(f"Algorithm list formatting error: {str(e)}")
        return format_error_response(str(e))

def format_algorithm_info(algorithm, data_type: str = None) -> Dict[str, Any]:
    """
    Format detailed algorithm information
    
    Args:
        algorithm: Algorithm name or algorithm data dict
        data_type: Data type context (optional)
    
    Returns:
        Formatted algorithm info
    """
    try:
        # Handle case where algorithm is already formatted data
        if isinstance(algorithm, dict):
            return algorithm
        
        # Handle case where algorithm is a string name
        base_info = get_algorithm_info(algorithm)
        
        # Enhanced algorithm information
        algorithm_details = {
            'name': algorithm,
            'category': base_info.get('mode', 'Unknown'),
            'security_level': base_info.get('security_level', 'Unknown'),
            'speed': base_info.get('performance', 'Unknown'),
            'description': get_algorithm_description(algorithm),
            'use_cases': get_algorithm_use_cases(algorithm),
            'pros': get_algorithm_pros(algorithm),
            'cons': get_algorithm_cons(algorithm),
            'recommended': is_algorithm_recommended(algorithm, data_type),
            'complexity': get_algorithm_complexity(algorithm),
            'educational_value': get_educational_value(algorithm)
        }
        
        # Add technical specifications
        if 'key_size' in base_info:
            algorithm_details['key_size'] = f"{base_info['key_size']} bits"
        if 'block_size' in base_info:
            algorithm_details['block_size'] = f"{base_info['block_size']} bits"
        
        return algorithm_details
        
    except Exception as e:
        logger.error(f"Algorithm info formatting error: {str(e)}")
        return {
            'name': str(algorithm),
            'error': str(e),
            'security_level': 'Unknown'
        }

def format_comparison_response(algorithms: list, data_type: str) -> Dict[str, Any]:
    """
    Format algorithm comparison response
    
    Args:
        algorithms: List of algorithms to compare
        data_type: Data type context
    
    Returns:
        Formatted comparison data
    """
    try:
        response = {
            'success': True,
            'comparison_type': data_type,
            'algorithms': algorithms,
            'timestamp': datetime.utcnow().isoformat(),
            'comparison': {
                'security': {},
                'performance': {},
                'complexity': {},
                'use_cases': {},
                'recommendations': {}
            }
        }
        
        # Security comparison (1-100 scale)
        security_scores = {
            'AES-256-GCM': 95,
            'ChaCha20-Poly1305': 96,
            'RSA-4096': 98,
            'AES-256-CBC': 90,
            'AES-256-XTS': 92,
            'Caesar': 5,
            'Vigenere': 15,
            'ROT13': 1,
            'Atbash': 3,
            'Playfair': 25
        }
        
        # Performance comparison (1-100 scale)
        performance_scores = {
            'AES-256-GCM': 90,
            'ChaCha20-Poly1305': 95,
            'RSA-4096': 40,
            'AES-256-CBC': 88,
            'AES-256-XTS': 85,
            'Caesar': 100,
            'Vigenere': 95,
            'ROT13': 100,
            'Atbash': 100,
            'Playfair': 80
        }
        
        for algo in algorithms:
            response['comparison']['security'][algo] = security_scores.get(algo, 50)
            response['comparison']['performance'][algo] = performance_scores.get(algo, 50)
            response['comparison']['complexity'][algo] = get_complexity_score(algo)
            response['comparison']['use_cases'][algo] = get_algorithm_use_cases(algo)
            response['comparison']['recommendations'][algo] = get_algorithm_recommendations(algo, data_type)
        
        return response
        
    except Exception as e:
        logger.error(f"Comparison formatting error: {str(e)}")
        return format_error_response(str(e))

def format_file_info(file_data: Dict[str, Any]) -> Dict[str, Any]:
    """Format file information for responses"""
    return {
        'filename': file_data.get('filename', 'unknown'),
        'size': file_data.get('size', 0),
        'size_formatted': format_bytes(file_data.get('size', 0)),
        'mime_type': file_data.get('mime_type', 'unknown'),
        'data_type': file_data.get('data_type', 'file'),
        'last_modified': file_data.get('last_modified', datetime.utcnow().isoformat())
    }

# Helper functions for algorithm metadata

def get_algorithm_description(algorithm: str) -> str:
    """Get human-readable algorithm description"""
    descriptions = {
        'AES-256-GCM': 'Advanced Encryption Standard with Galois Counter Mode - industry standard with built-in authentication',
        'ChaCha20-Poly1305': 'Modern stream cipher with Poly1305 authentication - optimized for mobile and embedded devices',
        'RSA-4096': 'Rivest-Shamir-Adleman public key encryption with 4096-bit keys - used for key exchange and digital signatures',
        'AES-256-CBC': 'AES in Cipher Block Chaining mode - suitable for large files and image encryption',
        'AES-256-XTS': 'AES in XEX-based tweaked-codebook mode - designed for full disk encryption',
        'Caesar': 'Simple substitution cipher with fixed shift - educational cipher from ancient Rome',
        'Vigenere': 'Polyalphabetic substitution cipher using keyword - historical "unbreakable" cipher',
        'ROT13': 'Simple letter substitution with 13-position rotation - commonly used for text obfuscation',
        'Atbash': 'Monoalphabetic substitution using reversed alphabet - ancient Hebrew cipher',
        'Playfair': 'Digraph substitution cipher using 5x5 key square - used in WWI and WWII'
    }
    return descriptions.get(algorithm, 'Unknown encryption algorithm')

def get_algorithm_use_cases(algorithm: str) -> list:
    """Get typical use cases for algorithm"""
    use_cases = {
        'AES-256-GCM': ['Secure messaging', 'File encryption', 'Network protocols', 'Cloud storage'],
        'ChaCha20-Poly1305': ['Mobile applications', 'IoT devices', 'Real-time communication', 'VPN protocols'],
        'RSA-4096': ['Key exchange', 'Digital signatures', 'Certificate authorities', 'Email encryption'],
        'AES-256-CBC': ['File encryption', 'Database encryption', 'Backup systems', 'Image protection'],
        'AES-256-XTS': ['Full disk encryption', 'USB drive protection', 'SSD encryption', 'Enterprise storage'],
        'Caesar': ['Educational purposes', 'Basic obfuscation', 'Historical study', 'Coding exercises'],
        'Vigenere': ['Cryptography education', 'Historical analysis', 'Puzzle games', 'Academic study'],
        'ROT13': ['Forum moderation', 'Spoiler protection', 'Text obfuscation', 'Simple encoding'],
        'Atbash': ['Historical research', 'Educational examples', 'Simple puzzles', 'Biblical studies'],
        'Playfair': ['Cryptography courses', 'Historical study', 'Military history', 'Cipher analysis']
    }
    return use_cases.get(algorithm, ['General purpose encryption'])

def get_algorithm_pros(algorithm: str) -> list:
    """Get algorithm advantages"""
    pros = {
        'AES-256-GCM': ['Hardware acceleration', 'Built-in authentication', 'Industry standard', 'Government approved'],
        'ChaCha20-Poly1305': ['Software optimized', 'Constant-time implementation', 'Mobile friendly', 'Modern design'],
        'RSA-4096': ['Public key system', 'Digital signatures', 'Key exchange', 'Mathematically proven'],
        'AES-256-CBC': ['Fast encryption', 'Simple implementation', 'Wide support', 'Proven security'],
        'AES-256-XTS': ['Sector-based encryption', 'No data expansion', 'Parallel processing', 'IEEE standard'],
        'Caesar': ['Very simple', 'Fast processing', 'Educational value', 'Historical significance'],
        'Vigenere': ['Keyword based', 'Variable key length', 'Historical importance', 'Pattern resistance'],
        'ROT13': ['Self-inverse', 'Instant decryption', 'No key needed', 'Universal standard'],
        'Atbash': ['Self-inverse', 'No key required', 'Ancient origin', 'Simple to understand'],
        'Playfair': ['Digraph encryption', 'Key-based', 'Manual implementation', 'Historical use']
    }
    return pros.get(algorithm, ['Encryption capability'])

def get_algorithm_cons(algorithm: str) -> list:
    """Get algorithm disadvantages"""
    cons = {
        'AES-256-GCM': ['IV management required', 'Authenticated mode only', 'Complex implementation'],
        'ChaCha20-Poly1305': ['Newer algorithm', 'Less hardware support', 'Limited adoption'],
        'RSA-4096': ['Very slow', 'Large key size', 'Complex math', 'Quantum vulnerable'],
        'AES-256-CBC': ['Padding required', 'IV reuse vulnerable', 'No authentication'],
        'AES-256-XTS': ['Requires 512-bit key', 'Sector-based only', 'Complex implementation'],
        'Caesar': ['Trivially broken', 'No real security', 'Pattern visible', 'Only 25 keys'],
        'Vigenere': ['Frequency analysis', 'Keyword patterns', 'Historically broken', 'Limited security'],
        'ROT13': ['No security', 'Obvious pattern', 'Single transformation', 'Easily recognized'],
        'Atbash': ['No security', 'Single key', 'Pattern obvious', 'Frequency vulnerable'],
        'Playfair': ['Manual intensive', 'Limited alphabet', 'Pattern vulnerable', 'Complex rules']
    }
    return cons.get(algorithm, ['Unknown limitations'])

def is_algorithm_recommended(algorithm: str, data_type: str) -> bool:
    """Determine if algorithm is recommended for data type"""
    recommendations = {
        'text': ['AES-256-GCM'],
        'image': ['AES-256-CBC'],
        'video': ['AES-256-CTR'],
        'file': ['AES-256-XTS', 'AES-256-GCM']
    }
    return algorithm in recommendations.get(data_type, [])

def get_algorithm_complexity(algorithm: str) -> str:
    """Get algorithm implementation complexity"""
    complexity = {
        'AES-256-GCM': 'Medium',
        'ChaCha20-Poly1305': 'Medium',
        'RSA-4096': 'High',
        'AES-256-CBC': 'Medium',
        'AES-256-XTS': 'High',
        'Caesar': 'Very Low',
        'Vigenere': 'Low',
        'ROT13': 'Very Low',
        'Atbash': 'Very Low',
        'Playfair': 'Medium'
    }
    return complexity.get(algorithm, 'Unknown')

def get_educational_value(algorithm: str) -> str:
    """Get educational value rating"""
    educational = {
        'AES-256-GCM': 'High',
        'ChaCha20-Poly1305': 'Medium',
        'RSA-4096': 'Very High',
        'AES-256-CBC': 'High',
        'AES-256-XTS': 'Medium',
        'Caesar': 'Very High',
        'Vigenere': 'Very High',
        'ROT13': 'High',
        'Atbash': 'High',
        'Playfair': 'Very High'
    }
    return educational.get(algorithm, 'Medium')

def get_complexity_score(algorithm: str) -> int:
    """Get complexity as numeric score (1-100)"""
    scores = {
        'Caesar': 10,
        'ROT13': 5,
        'Atbash': 8,
        'Vigenere': 25,
        'Playfair': 40,
        'AES-256-CBC': 60,
        'AES-256-GCM': 65,
        'ChaCha20-Poly1305': 62,
        'AES-256-XTS': 75,
        'RSA-4096': 90
    }
    return scores.get(algorithm, 50)

def get_algorithm_recommendations(algorithm: str, data_type: str) -> str:
    """Get specific recommendations for algorithm use"""
    recommendations = {
        ('AES-256-GCM', 'text'): 'Perfect for secure messaging and text encryption',
        ('AES-256-CBC', 'image'): 'Ideal for image and binary file encryption',
        ('ChaCha20-Poly1305', 'text'): 'Excellent for mobile and IoT applications',
        ('RSA-4096', 'text'): 'Use for key exchange, not direct data encryption',
        ('Caesar', 'text'): 'Educational use only - no real security'
    }
    
    key = (algorithm, data_type)
    return recommendations.get(key, f'Suitable for {data_type} encryption with appropriate security considerations')