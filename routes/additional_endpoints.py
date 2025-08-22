"""
Additional API Endpoints for Universal Encryption Platform
File download, algorithm comparison, system utilities
"""

from flask import Blueprint, request, jsonify, send_file, make_response
import os
import tempfile
import logging
from datetime import datetime
from utils.file_handlers import get_file_for_download, list_uploaded_files, delete_uploaded_file, cleanup_old_files, get_file_stats
from utils.formatters import format_comparison_response, format_error_response
from crypto.utils import get_algorithm_info
import io

logger = logging.getLogger(__name__)

# Create blueprint
additional_api = Blueprint('additional_api', __name__)

# ================================
# FILE MANAGEMENT ENDPOINTS
# ================================

@additional_api.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    """
    Download and decrypt uploaded file
    """
    try:
        # Get password from query parameter or header
        password = request.args.get('password') or request.headers.get('X-Decrypt-Password')
        
        if not password:
            return jsonify({
                'error': 'Password required for file decryption',
                'details': 'Provide password as query parameter (?password=...) or X-Decrypt-Password header'
            }), 400
        
        # Retrieve and decrypt file
        decrypted_content, filename, mime_type = get_file_for_download(file_id, password)
        
        if decrypted_content is None:
            return jsonify({
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
            'error': 'Download failed',
            'details': str(e)
        }), 500

@additional_api.route('/api/files', methods=['GET'])
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
            'error': 'Failed to list files',
            'details': str(e)
        }), 500

@additional_api.route('/api/files/<file_id>', methods=['DELETE'])
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
                'error': 'File not found or deletion failed',
                'file_id': file_id
            }), 404
            
    except Exception as e:
        logger.error(f"File deletion error: {str(e)}")
        return jsonify({
            'error': 'Deletion failed',
            'details': str(e)
        }), 500

@additional_api.route('/api/files/cleanup', methods=['POST'])
def cleanup_files():
    """Clean up expired files"""
    try:
        cleaned_count = cleanup_old_files()
        
        return jsonify({
            'success': True,
            'message': f'Cleaned up {cleaned_count} expired files',
            'files_removed': cleaned_count,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Cleanup error: {str(e)}")
        return jsonify({
            'error': 'Cleanup failed',
            'details': str(e)
        }), 500

@additional_api.route('/api/files/stats', methods=['GET'])
def file_statistics():
    """Get file upload statistics"""
    try:
        stats = get_file_stats()
        return jsonify({
            'success': True,
            'statistics': stats,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({
            'error': 'Failed to get statistics',
            'details': str(e)
        }), 500

# ================================
# ALGORITHM COMPARISON ENDPOINTS
# ================================

@additional_api.route('/api/algorithms/compare', methods=['POST'])
def compare_algorithms():
    """
    Compare multiple algorithms across different metrics
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        algorithms = data.get('algorithms', [])
        data_type = data.get('data_type', 'text')
        
        if not algorithms:
            return jsonify({'error': 'No algorithms provided for comparison'}), 400
        
        if len(algorithms) < 2:
            return jsonify({'error': 'At least 2 algorithms required for comparison'}), 400
        
        if len(algorithms) > 5:
            return jsonify({'error': 'Maximum 5 algorithms can be compared'}), 400
        
        # Generate comparison
        comparison = format_comparison_response(algorithms, data_type)
        return jsonify(comparison)
        
    except Exception as e:
        logger.error(f"Algorithm comparison error: {str(e)}")
        return jsonify({
            'error': 'Comparison failed',
            'details': str(e)
        }), 500

@additional_api.route('/api/algorithms/<algorithm_name>/details', methods=['GET'])
def algorithm_details(algorithm_name):
    """
    Get detailed information about specific algorithm
    """
    try:
        # Get algorithm information
        algo_info = get_algorithm_info(algorithm_name)
        
        if not algo_info or algo_info.get('mode') == 'Unknown':
            return jsonify({
                'error': f'Algorithm {algorithm_name} not found',
                'available_algorithms': get_available_algorithms()
            }), 404
        
        # Enhanced algorithm details
        details = {
            'algorithm': algorithm_name,
            'full_name': get_full_algorithm_name(algorithm_name),
            'category': algo_info.get('mode', 'Unknown'),
            'security_level': algo_info.get('security_level', 'Unknown'),
            'performance': algo_info.get('performance', 'Unknown'),
            'description': get_algorithm_description(algorithm_name),
            'history': get_algorithm_history(algorithm_name),
            'how_it_works': get_algorithm_explanation(algorithm_name),
            'strengths': get_algorithm_strengths(algorithm_name),
            'weaknesses': get_algorithm_weaknesses(algorithm_name),
            'real_world_usage': get_real_world_usage(algorithm_name),
            'implementation_notes': get_implementation_notes(algorithm_name),
            'recommended_for': get_recommended_use_cases(algorithm_name),
            'technical_specs': {
                'key_size': algo_info.get('key_size'),
                'block_size': algo_info.get('block_size'),
                'iv_size': algo_info.get('iv_size'),
                'tag_size': algo_info.get('tag_size')
            },
            'educational_content': {
                'difficulty_level': get_difficulty_level(algorithm_name),
                'learning_resources': get_learning_resources(algorithm_name),
                'practice_exercises': get_practice_exercises(algorithm_name)
            }
        }
        
        return jsonify({
            'success': True,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Algorithm details error: {str(e)}")
        return jsonify({
            'error': 'Failed to get algorithm details',
            'details': str(e)
        }), 500

@additional_api.route('/api/algorithms/recommend', methods=['POST'])
def recommend_algorithm():
    """
    Get algorithm recommendations based on requirements
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        data_type = data.get('data_type', 'text')
        security_level = data.get('security_level', 'high')
        performance_priority = data.get('performance_priority', 'balanced')
        use_case = data.get('use_case', 'general')
        
        recommendations = generate_recommendations(data_type, security_level, performance_priority, use_case)
        
        return jsonify({
            'success': True,
            'data_type': data_type,
            'requirements': {
                'security_level': security_level,
                'performance_priority': performance_priority,
                'use_case': use_case
            },
            'recommendations': recommendations,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Recommendation error: {str(e)}")
        return jsonify({
            'error': 'Failed to generate recommendations',
            'details': str(e)
        }), 500

# ================================
# SYSTEM UTILITY ENDPOINTS
# ================================

@additional_api.route('/api/system/status', methods=['GET'])
def system_status():
    """Get detailed system status"""
    try:
        import psutil
        import platform
        
        # System information
        system_info = {
            'platform': platform.system(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'disk_usage': {
                'total': psutil.disk_usage('/').total,
                'free': psutil.disk_usage('/').free
            }
        }
        
        # Application statistics
        app_stats = {
            'uptime': get_uptime(),
            'files_uploaded': len(list_uploaded_files(1000)),
            'algorithms_available': get_algorithm_count(),
            'last_cleanup': get_last_cleanup_time()
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
            'error': 'Failed to get system status',
            'details': str(e)
        }), 500

@additional_api.route('/api/system/metrics', methods=['GET'])
def system_metrics():
    """Get system performance metrics"""
    try:
        import psutil
        
        metrics = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
            'network_io': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {},
            'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None,
            'process_count': len(psutil.pids())
        }
        
        return jsonify({
            'success': True,
            'metrics': metrics,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Metrics error: {str(e)}")
        return jsonify({
            'error': 'Failed to get metrics',
            'details': str(e)
        }), 500

@additional_api.route('/api/test/encryption', methods=['POST'])
def test_encryption():
    """Test encryption with sample data"""
    try:
        data = request.get_json() or {}
        algorithm = data.get('algorithm', 'AES-256-GCM')
        
        # Test data
        test_message = "Hello World! This is a test message for encryption verification."
        test_password = "test123"
        
        # Import encryption function from main app
        from app import encrypt_aes_gcm, decrypt_aes_gcm
        
        # Encrypt
        encrypted_result = encrypt_aes_gcm(test_message, test_password, {})
        
        # Decrypt
        decrypted_result = decrypt_aes_gcm(
            encrypted_result['ciphertext'], 
            test_password, 
            encrypted_result
        )
        
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

# ================================
# HELPER FUNCTIONS
# ================================

def get_available_algorithms():
    """Get list of all available algorithms"""
    return [
        'AES-256-GCM', 'ChaCha20-Poly1305', 'RSA-4096', 'AES-256-CBC',
        'AES-256-XTS', 'Caesar', 'Vigenere', 'ROT13', 'Atbash', 'Playfair'
    ]

def get_full_algorithm_name(algorithm):
    """Get full descriptive name for algorithm"""
    names = {
        'AES-256-GCM': 'Advanced Encryption Standard 256-bit Galois Counter Mode',
        'ChaCha20-Poly1305': 'ChaCha20 Stream Cipher with Poly1305 Authentication',
        'RSA-4096': 'Rivest-Shamir-Adleman 4096-bit Public Key Encryption',
        'AES-256-CBC': 'Advanced Encryption Standard 256-bit Cipher Block Chaining',
        'AES-256-XTS': 'Advanced Encryption Standard 256-bit XEX-based Tweaked Codebook',
        'Caesar': 'Caesar Substitution Cipher',
        'Vigenere': 'Vigenère Polyalphabetic Cipher'
    }
    return names.get(algorithm, algorithm)

def get_algorithm_description(algorithm):
    """Get detailed algorithm description"""
    descriptions = {
        'AES-256-GCM': 'A symmetric block cipher that provides both encryption and authentication in a single operation. Uses 256-bit keys and Galois Counter Mode for authenticated encryption.',
        'ChaCha20-Poly1305': 'A modern stream cipher combined with Poly1305 for authentication. Designed for high performance on software platforms and mobile devices.',
        'RSA-4096': 'An asymmetric encryption algorithm based on the mathematical difficulty of factoring large composite numbers. Uses 4096-bit keys for enhanced security.'
    }
    return descriptions.get(algorithm, 'Encryption algorithm for data protection.')

def get_algorithm_history(algorithm):
    """Get historical background of algorithm"""
    history = {
        'AES-256-GCM': 'Developed from Rijndael cipher, standardized by NIST in 2001. GCM mode added in 2007 for authenticated encryption.',
        'ChaCha20-Poly1305': 'ChaCha20 designed by Daniel J. Bernstein in 2008. Combined with Poly1305 MAC for RFC 7539 in 2015.',
        'RSA-4096': 'RSA algorithm published in 1977 by Rivest, Shamir, and Adleman. 4096-bit keys recommended for long-term security.',
        'Caesar': 'Named after Julius Caesar who used it around 50 BC. One of the simplest and most well-known encryption techniques.'
    }
    return history.get(algorithm, 'Historical encryption method.')

def get_algorithm_explanation(algorithm):
    """Get how the algorithm works"""
    explanations = {
        'AES-256-GCM': 'Operates on 128-bit blocks using a series of substitution and permutation operations. GCM mode combines counter mode encryption with Galois field multiplication for authentication.',
        'Caesar': 'Each letter in the plaintext is shifted a certain number of places down or up the alphabet. For example, with a shift of 3, A becomes D, B becomes E, etc.'
    }
    return explanations.get(algorithm, 'Complex mathematical operations ensure data security.')

def get_algorithm_strengths(algorithm):
    """Get algorithm advantages"""
    strengths = {
        'AES-256-GCM': ['Hardware acceleration available', 'Built-in authentication', 'Proven security', 'Government approved'],
        'ChaCha20-Poly1305': ['Excellent software performance', 'Constant-time implementation', 'Resistant to timing attacks', 'Modern design'],
        'Caesar': ['Simple to understand', 'Fast to compute', 'Educational value', 'Historical significance']
    }
    return strengths.get(algorithm, ['Provides data encryption'])

def get_algorithm_weaknesses(algorithm):
    """Get algorithm limitations"""
    weaknesses = {
        'AES-256-GCM': ['IV reuse is catastrophic', 'Complex implementation', 'Requires proper key management'],
        'ChaCha20-Poly1305': ['Newer algorithm with less analysis', 'Limited hardware acceleration'],
        'Caesar': ['Trivially broken', 'Only 25 possible keys', 'Frequency analysis reveals patterns', 'No real security']
    }
    return weaknesses.get(algorithm, ['Potential security limitations'])

def get_real_world_usage(algorithm):
    """Get real-world applications"""
    usage = {
        'AES-256-GCM': ['TLS 1.3 encryption', 'IPSec VPNs', 'Disk encryption', 'Banking systems'],
        'ChaCha20-Poly1305': ['HTTPS connections', 'Signal messenger', 'OpenVPN', 'Tor browser'],
        'RSA-4096': ['SSL certificates', 'Email encryption', 'Digital signatures', 'Code signing'],
        'Caesar': ['Puzzle games', 'Educational exercises', 'Historical recreation', 'ROT13 text encoding']
    }
    return usage.get(algorithm, ['General encryption applications'])

def get_implementation_notes(algorithm):
    """Get implementation best practices"""
    notes = {
        'AES-256-GCM': 'Always use unique IVs. Never reuse IV with same key. Verify authentication tag before processing decrypted data.',
        'ChaCha20-Poly1305': 'Nonce must be unique for each encryption. Consider using random nonces with 96-bit size for safety.',
        'Caesar': 'For educational purposes only. Use random shift values and explain frequency analysis vulnerabilities.'
    }
    return notes.get(algorithm, 'Follow cryptographic best practices for implementation.')

def get_recommended_use_cases(algorithm):
    """Get recommended use cases"""
    use_cases = {
        'AES-256-GCM': ['High-security applications', 'Real-time communication', 'File encryption', 'Database encryption'],
        'ChaCha20-Poly1305': ['Mobile applications', 'IoT devices', 'High-performance systems', 'Privacy tools'],
        'RSA-4096': ['Key exchange', 'Digital signatures', 'Certificate authorities', 'Long-term security'],
        'Caesar': ['Cryptography education', 'Programming exercises', 'Historical study', 'Simple obfuscation']
    }
    return use_cases.get(algorithm, ['General encryption needs'])

def get_difficulty_level(algorithm):
    """Get learning difficulty level"""
    levels = {
        'Caesar': 'Beginner',
        'Vigenere': 'Beginner',
        'AES-256-GCM': 'Intermediate',
        'ChaCha20-Poly1305': 'Intermediate',
        'RSA-4096': 'Advanced'
    }
    return levels.get(algorithm, 'Intermediate')

def get_learning_resources(algorithm):
    """Get educational resources"""
    return [
        'Algorithm specification documents',
        'Interactive tutorials',
        'Academic papers',
        'Implementation examples'
    ]

def get_practice_exercises(algorithm):
    """Get practice exercises"""
    return [
        'Manual encryption/decryption',
        'Implementation challenges',
        'Security analysis',
        'Performance optimization'
    ]

def generate_recommendations(data_type, security_level, performance_priority, use_case):
    """Generate algorithm recommendations based on criteria"""
    recommendations = []
    
    if data_type == 'text':
        if security_level == 'very_high':
            recommendations.append({
                'algorithm': 'AES-256-GCM',
                'score': 95,
                'reason': 'Industry standard with authentication'
            })
        if performance_priority == 'high':
            recommendations.append({
                'algorithm': 'ChaCha20-Poly1305',
                'score': 90,
                'reason': 'Optimized for high performance'
            })
    
    return recommendations

def get_uptime():
    """Get application uptime"""
    # This would be implemented with a global start time
    return "N/A"

def get_algorithm_count():
    """Get total number of available algorithms"""
    return len(get_available_algorithms())

def get_last_cleanup_time():
    """Get last file cleanup time"""
    # This would be tracked in application state
    return "N/A"