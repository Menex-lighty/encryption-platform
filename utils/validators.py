"""
Input Validation Utilities
Validate encryption requests, file types, and security parameters
Robust version with multiple file type detection methods
"""

import re
import base64
import mimetypes
import os
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

# Initialize file type detection methods in order of preference
FILE_TYPE_METHODS = []

# Method 1: Try python-magic (most accurate)
try:
    import magic
    FILE_TYPE_METHODS.append('magic')
    logger.info("File type detection: python-magic available")
except ImportError as e:
    logger.warning(f"python-magic not available: {e}")

# Method 2: Try filetype library (pure Python, reliable)
try:
    import filetype
    FILE_TYPE_METHODS.append('filetype')
    logger.info("File type detection: filetype library available")
except ImportError:
    logger.warning("filetype library not available")

# Method 3: Use built-in mimetypes (always available, less accurate)
FILE_TYPE_METHODS.append('mimetypes')
logger.info("File type detection: mimetypes (built-in) available")

# Supported algorithms by data type
SUPPORTED_ALGORITHMS = {
    'text': [
        'AES-256-GCM', 
        'ChaCha20-Poly1305', 
        'XChaCha20-Poly1305',
        'RSA-4096', 
        'FF1-AES',
        'Caesar',
        'Enigma',
        'Vigenere',
        'ROT13',
        'ROT47',
        'Atbash',
        'Playfair'
    ],
    'image': [
        'AES-256-CBC', 
        'AES-256-GCM',
        'Visual-Cryptography',
        'LSB-Steganography',
        'Pixel-Shuffling'
    ],
    'video': [
        'AES-256-CTR',
        'AES-256-GCM', 
        'Format-Preserving',
        'Selective-Encryption'
    ],
    'file': [
        'AES-256-XTS', 
        'AES-256-GCM',
        'XChaCha20-Poly1305',
        'GPG-Style',
        'ZIP-Encryption'
    ],
    'postquantum': [
        'Kyber-768'
    ]
}

# File type validation
ALLOWED_FILE_TYPES = {
    'image': [
        'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 
        'image/tiff', 'image/webp', 'image/svg+xml'
    ],
    'video': [
        'video/mp4', 'video/avi', 'video/mov', 'video/mkv',
        'video/webm', 'video/flv', 'video/wmv'
    ],
    'document': [
        'application/pdf', 'text/plain', 'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ],
    'archive': [
        'application/zip', 'application/x-rar-compressed',
        'application/x-7z-compressed', 'application/x-tar'
    ]
}

# File extension to MIME type mapping (fallback)
EXTENSION_MIME_MAP = {
    # Images
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
    '.gif': 'image/gif', '.bmp': 'image/bmp', '.tiff': 'image/tiff',
    '.webp': 'image/webp', '.svg': 'image/svg+xml',
    
    # Videos
    '.mp4': 'video/mp4', '.avi': 'video/avi', '.mov': 'video/mov',
    '.mkv': 'video/mkv', '.webm': 'video/webm', '.flv': 'video/flv',
    '.wmv': 'video/wmv',
    
    # Documents
    '.pdf': 'application/pdf', '.txt': 'text/plain',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    
    # Archives
    '.zip': 'application/zip', '.rar': 'application/x-rar-compressed',
    '.7z': 'application/x-7z-compressed', '.tar': 'application/x-tar'
}

# Security constraints
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB
MAX_TEXT_LENGTH = 1024 * 1024     # 1 MB text
MIN_PASSWORD_LENGTH = 4
MAX_PASSWORD_LENGTH = 256

def detect_file_type(file_obj, filename: str = None) -> str:
    """
    Detect file MIME type using multiple methods
    
    Args:
        file_obj: File object or file path
        filename: Optional filename for extension-based detection
    
    Returns:
        MIME type string
    """
    mime_type = 'application/octet-stream'  # Default fallback
    
    for method in FILE_TYPE_METHODS:
        try:
            if method == 'magic':
                mime_type = _detect_with_magic(file_obj)
                if mime_type != 'application/octet-stream':
                    logger.debug(f"File type detected with magic: {mime_type}")
                    return mime_type
                    
            elif method == 'filetype':
                mime_type = _detect_with_filetype(file_obj)
                if mime_type != 'application/octet-stream':
                    logger.debug(f"File type detected with filetype: {mime_type}")
                    return mime_type
                    
            elif method == 'mimetypes':
                mime_type = _detect_with_mimetypes(filename)
                if mime_type != 'application/octet-stream':
                    logger.debug(f"File type detected with mimetypes: {mime_type}")
                    return mime_type
                    
        except Exception as e:
            logger.warning(f"File type detection method '{method}' failed: {e}")
            continue
    
    # Final fallback to extension mapping
    if filename:
        ext = os.path.splitext(filename.lower())[1]
        mime_type = EXTENSION_MIME_MAP.get(ext, 'application/octet-stream')
        logger.debug(f"File type detected with extension mapping: {mime_type}")
    
    return mime_type

def _detect_with_magic(file_obj) -> str:
    """Detect file type using python-magic"""
    try:
        if hasattr(file_obj, 'read'):
            # File-like object
            file_obj.seek(0)
            file_content = file_obj.read(1024)  # Read first 1KB
            file_obj.seek(0)  # Reset position
            return magic.from_buffer(file_content, mime=True)
        else:
            # File path
            return magic.from_file(str(file_obj), mime=True)
    except Exception as e:
        logger.warning(f"Magic detection failed: {e}")
        return 'application/octet-stream'

def _detect_with_filetype(file_obj) -> str:
    """Detect file type using filetype library"""
    try:
        if hasattr(file_obj, 'read'):
            # File-like object
            file_obj.seek(0)
            file_content = file_obj.read(1024)  # Read first 1KB
            file_obj.seek(0)  # Reset position
        else:
            # File path
            with open(file_obj, 'rb') as f:
                file_content = f.read(1024)
        
        kind = filetype.guess(file_content)
        if kind:
            return kind.mime
        return 'application/octet-stream'
    except Exception as e:
        logger.warning(f"Filetype detection failed: {e}")
        return 'application/octet-stream'

def _detect_with_mimetypes(filename: str) -> str:
    """Detect file type using built-in mimetypes"""
    if not filename:
        return 'application/octet-stream'
    
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type or 'application/octet-stream'

def validate_encryption_request(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate encryption request data
    
    Args:
        data: Request data dictionary
    
    Returns:
        Validation result with 'valid' boolean and 'message'
    """
    try:
        # Required fields
        required_fields = ['data', 'algorithm']
        for field in required_fields:
            if field not in data:
                return {
                    'valid': False,
                    'message': f'Missing required field: {field}'
                }
        
        # Validate data type
        data_type = data.get('data_type', 'text')
        if data_type not in SUPPORTED_ALGORITHMS:
            return {
                'valid': False,
                'message': f'Unsupported data type: {data_type}'
            }
        
        # Validate algorithm
        algorithm = data.get('algorithm')
        if algorithm not in SUPPORTED_ALGORITHMS[data_type]:
            return {
                'valid': False,
                'message': f'Algorithm {algorithm} not supported for {data_type}'
            }
        
        # Validate data content
        data_content = data.get('data')
        if not data_content:
            return {
                'valid': False,
                'message': 'Data content cannot be empty'
            }
        
        # Text-specific validation
        if data_type == 'text':
            if isinstance(data_content, str):
                if len(data_content) > MAX_TEXT_LENGTH:
                    return {
                        'valid': False,
                        'message': f'Text too long. Maximum: {MAX_TEXT_LENGTH} characters'
                    }
            else:
                return {
                    'valid': False,
                    'message': 'Text data must be a string'
                }
        
        # Password validation (for algorithms that require it)
        password_required_algorithms = [
            'AES-256-GCM', 'ChaCha20-Poly1305', 'XChaCha20-Poly1305', 'AES-256-CBC',
            'AES-256-CTR', 'AES-256-XTS', 'FF1-AES', 'Vigenere', 'Playfair'
        ]
        
        if algorithm in password_required_algorithms:
            password = data.get('password')
            if not password:
                return {
                    'valid': False,
                    'message': f'Password required for {algorithm}'
                }
            
            password_validation = validate_password(password)
            if not password_validation['valid']:
                return password_validation
        
        # Options validation
        options = data.get('options', {})
        if not isinstance(options, dict):
            return {
                'valid': False,
                'message': 'Options must be a dictionary'
            }
        
        # Algorithm-specific validation
        algorithm_validation = validate_algorithm_options(algorithm, options)
        if not algorithm_validation['valid']:
            return algorithm_validation
        
        logger.info(f"Validation successful for {algorithm} on {data_type}")
        return {'valid': True, 'message': 'Validation successful'}
        
    except Exception as e:
        logger.error(f"Validation error: {str(e)}")
        return {
            'valid': False,
            'message': f'Validation error: {str(e)}'
        }

def validate_password(password: str) -> Dict[str, Any]:
    """
    Validate password strength and format
    
    Args:
        password: Password string
    
    Returns:
        Validation result
    """
    try:
        if not isinstance(password, str):
            return {
                'valid': False,
                'message': 'Password must be a string'
            }
        
        if len(password) < MIN_PASSWORD_LENGTH:
            return {
                'valid': False,
                'message': f'Password too short. Minimum: {MIN_PASSWORD_LENGTH} characters'
            }
        
        if len(password) > MAX_PASSWORD_LENGTH:
            return {
                'valid': False,
                'message': f'Password too long. Maximum: {MAX_PASSWORD_LENGTH} characters'
            }
        
        # Basic strength check
        if len(password) < 8:
            logger.warning("Weak password detected")
        
        return {'valid': True, 'message': 'Password valid'}
        
    except Exception as e:
        return {
            'valid': False,
            'message': f'Password validation error: {str(e)}'
        }

def validate_algorithm_options(algorithm: str, options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate algorithm-specific options
    
    Args:
        algorithm: Encryption algorithm name
        options: Algorithm options dictionary
    
    Returns:
        Validation result
    """
    try:
        # Caesar cipher validation
        if algorithm == 'Caesar':
            shift = options.get('shift', 3)
            if not isinstance(shift, int):
                return {
                    'valid': False,
                    'message': 'Caesar shift must be an integer'
                }
            if not (1 <= shift <= 25):
                return {
                    'valid': False,
                    'message': 'Caesar shift must be between 1 and 25'
                }
        
        # Vigenère cipher validation
        elif algorithm == 'Vigenere':
            keyword = options.get('keyword')
            if not keyword:
                return {
                    'valid': False,
                    'message': 'Vigenère cipher requires keyword'
                }
            if not isinstance(keyword, str):
                return {
                    'valid': False,
                    'message': 'Vigenère keyword must be a string'
                }
            if not keyword.isalpha():
                return {
                    'valid': False,
                    'message': 'Vigenère keyword must contain only letters'
                }
        
        # Playfair cipher validation
        elif algorithm == 'Playfair':
            keyword = options.get('keyword')
            if not keyword:
                return {
                    'valid': False,
                    'message': 'Playfair cipher requires keyword'
                }
            if not isinstance(keyword, str):
                return {
                    'valid': False,
                    'message': 'Playfair keyword must be a string'
                }
            if not keyword.isalpha():
                return {
                    'valid': False,
                    'message': 'Playfair keyword must contain only letters'
                }
        
        # RSA key size validation
        elif algorithm == 'RSA-4096':
            key_size = options.get('key_size', 4096)
            if key_size not in [2048, 3072, 4096]:
                return {
                    'valid': False,
                    'message': 'RSA key size must be 2048, 3072, or 4096'
                }
        
        # Output format validation
        output_format = options.get('output_format', 'base64')
        if output_format not in ['base64', 'hex', 'binary']:
            return {
                'valid': False,
                'message': 'Output format must be base64, hex, or binary'
            }
        
        return {'valid': True, 'message': 'Algorithm options valid'}
        
    except Exception as e:
        return {
            'valid': False,
            'message': f'Algorithm options validation error: {str(e)}'
        }

def validate_file_upload(file) -> Dict[str, Any]:
    """
    Validate uploaded file
    
    Args:
        file: Flask uploaded file object
    
    Returns:
        Validation result with file info
    """
    try:
        if not file:
            return {
                'valid': False,
                'message': 'No file provided'
            }
        
        # Get filename (handle both Flask FileStorage and test objects)
        filename = getattr(file, 'filename', None) or getattr(file, 'name', 'test_file')
        
        if not filename or filename == 'test_file':
            # For BytesIO test objects, use the name attribute if available
            if hasattr(file, 'name') and file.name:
                filename = file.name
        
        # Check file size
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)     # Reset to beginning
        
        if file_size > MAX_FILE_SIZE:
            return {
                'valid': False,
                'message': f'File too large. Maximum: {MAX_FILE_SIZE / (1024*1024):.1f} MB'
            }
        
        if file_size == 0:
            return {
                'valid': False,
                'message': 'File is empty'
            }
        
        # Detect file type
        mime_type = detect_file_type(file, filename)
        data_type = get_data_type_from_mime(mime_type)
        
        logger.info(f"File validation successful: {filename}, {mime_type}, {file_size} bytes")
        
        return {
            'valid': True,
            'message': 'File valid',
            'file_info': {
                'filename': filename,
                'size': file_size,
                'mime_type': mime_type,
                'data_type': data_type
            }
        }
        
    except Exception as e:
        logger.error(f"File validation error: {str(e)}")
        return {
            'valid': False,
            'message': f'File validation error: {str(e)}'
        }

def get_data_type_from_mime(mime_type: str) -> str:
    """Determine data type from MIME type"""
    for data_type, mime_types in ALLOWED_FILE_TYPES.items():
        if mime_type in mime_types:
            return data_type
    return 'file'  # Default to generic file

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    
    # Ensure not empty
    if not filename:
        filename = 'unnamed_file'
    
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_length = 255 - len(ext) - 1 if ext else 255
        filename = name[:max_name_length] + ('.' + ext if ext else '')
    
    return filename

def validate_base64(data: str) -> bool:
    """Validate base64 encoded string"""
    try:
        if isinstance(data, str):
            # Add padding if necessary
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            base64.b64decode(data)
            return True
    except Exception:
        pass
    return False

def validate_hex(data: str) -> bool:
    """Validate hexadecimal string"""
    try:
        if isinstance(data, str):
            # Remove any whitespace
            data = data.replace(' ', '').replace('\n', '')
            # Check if all characters are hex digits
            int(data, 16)
            return True
    except Exception:
        pass
    return False

def validate_algorithm_choice(algorithm: str, data_type: str = 'text') -> bool:
    """
    Validate if an algorithm is supported for a given data type
    
    Args:
        algorithm: Encryption algorithm name
        data_type: Data type (text, image, video, file, postquantum)
    
    Returns:
        Boolean indicating if the algorithm is valid for the data type
    """
    try:
        if not algorithm or not isinstance(algorithm, str):
            return False
        
        if data_type not in SUPPORTED_ALGORITHMS:
            return False
        
        return algorithm in SUPPORTED_ALGORITHMS[data_type]
        
    except Exception as e:
        logger.error(f"Algorithm choice validation error: {str(e)}")
        return False

def validate_json_structure(data: Any, required_fields: List[str]) -> Dict[str, Any]:
    """Validate JSON structure has required fields"""
    try:
        if not isinstance(data, dict):
            return {
                'valid': False,
                'message': 'Data must be a JSON object'
            }
        
        missing_fields = []
        for field in required_fields:
            if field not in data:
                missing_fields.append(field)
        
        if missing_fields:
            return {
                'valid': False,
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }
        
        return {'valid': True, 'message': 'JSON structure valid'}
        
    except Exception as e:
        return {
            'valid': False,
            'message': f'JSON validation error: {str(e)}'
        }