"""
File Handling Utilities
Handle file uploads, processing, and secure storage
"""

import os
import uuid
import base64
import tempfile
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from werkzeug.utils import secure_filename
from utils.validators import validate_file_upload, sanitize_filename
from crypto.symmetric import AESCrypto
from crypto.utils import derive_key, generate_salt
import logging

logger = logging.getLogger(__name__)

# Configuration
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', './uploads')
TEMP_FOLDER = os.environ.get('TEMP_FOLDER', './temp')
MAX_FILE_AGE_HOURS = 24  # Auto-cleanup after 24 hours

# Ensure directories exist
for folder in [UPLOAD_FOLDER, TEMP_FOLDER]:
    os.makedirs(folder, exist_ok=True)

class FileManager:
    """Secure file management for encryption operations"""
    
    def __init__(self):
        self.aes = AESCrypto()
        self.upload_folder = UPLOAD_FOLDER
        self.temp_folder = TEMP_FOLDER
    
    def handle_file_upload(self, file, algorithm: str, password: str) -> Dict[str, Any]:
        """
        Handle file upload and encryption
        
        Args:
            file: Flask uploaded file object
            algorithm: Encryption algorithm
            password: Encryption password
        
        Returns:
            Result dictionary with file info and download URL
        """
        try:
            # Validate file
            validation = validate_file_upload(file)
            if not validation['valid']:
                return {
                    'success': False,
                    'error': validation['message']
                }
            
            file_info = validation['file_info']
            
            # Generate unique file ID
            file_id = str(uuid.uuid4())
            
            # Save original file temporarily
            temp_path = self._save_temp_file(file, file_id)
            
            try:
                # Read file content
                with open(temp_path, 'rb') as f:
                    file_content = f.read()
                
                # Encrypt file
                encrypted_result = self._encrypt_file_content(
                    file_content, algorithm, password
                )
                
                # Save encrypted file
                encrypted_path = self._save_encrypted_file(
                    encrypted_result, file_id, file_info['filename']
                )
                
                # Generate download URL
                download_url = f"/api/download/{file_id}"
                
                # Create file metadata
                metadata = {
                    'file_id': file_id,
                    'original_filename': file_info['filename'],
                    'original_size': file_info['size'],
                    'encrypted_size': len(encrypted_result['ciphertext']),
                    'mime_type': file_info['mime_type'],
                    'algorithm': algorithm,
                    'upload_time': datetime.utcnow().isoformat(),
                    'expires_at': (datetime.utcnow() + timedelta(hours=MAX_FILE_AGE_HOURS)).isoformat()
                }
                
                # Save metadata
                self._save_file_metadata(file_id, metadata, encrypted_result)
                
                logger.info(f"File uploaded and encrypted: {file_info['filename']}")
                
                return {
                    'success': True,
                    'file_id': file_id,
                    'download_url': download_url,
                    'metadata': metadata,
                    'expires_at': metadata['expires_at']
                }
                
            finally:
                # Clean up temp file
                self._cleanup_temp_file(temp_path)
                
        except Exception as e:
            logger.error(f"File upload error: {str(e)}")
            return {
                'success': False,
                'error': f'File upload failed: {str(e)}'
            }
    
    def get_encrypted_file(self, file_id: str, password: str) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
        """
        Retrieve and decrypt file
        
        Args:
            file_id: Unique file identifier
            password: Decryption password
        
        Returns:
            Tuple of (decrypted_content, filename, mime_type)
        """
        try:
            # Load metadata
            metadata, encrypted_data = self._load_file_metadata(file_id)
            if not metadata:
                return None, None, None
            
            # Check if file has expired
            expires_at = datetime.fromisoformat(metadata['expires_at'])
            if datetime.utcnow() > expires_at:
                self._cleanup_expired_file(file_id)
                return None, None, None
            
            # Decrypt file
            decrypted_content = self._decrypt_file_content(
                encrypted_data, metadata['algorithm'], password
            )
            
            logger.info(f"File retrieved and decrypted: {metadata['original_filename']}")
            
            return (
                decrypted_content,
                metadata['original_filename'],
                metadata['mime_type']
            )
            
        except Exception as e:
            logger.error(f"File retrieval error: {str(e)}")
            return None, None, None
    
    def list_files(self, limit: int = 50) -> list:
        """List uploaded files (metadata only)"""
        try:
            files = []
            metadata_dir = os.path.join(self.upload_folder, 'metadata')
            
            if not os.path.exists(metadata_dir):
                return files
            
            for filename in os.listdir(metadata_dir):
                if filename.endswith('.json'):
                    file_id = filename[:-5]  # Remove .json extension
                    
                    try:
                        metadata, _ = self._load_file_metadata(file_id)
                        if metadata:
                            # Check if expired
                            expires_at = datetime.fromisoformat(metadata['expires_at'])
                            if datetime.utcnow() > expires_at:
                                self._cleanup_expired_file(file_id)
                                continue
                            
                            files.append({
                                'file_id': file_id,
                                'filename': metadata['original_filename'],
                                'size': metadata['original_size'],
                                'upload_time': metadata['upload_time'],
                                'algorithm': metadata['algorithm']
                            })
                    except Exception:
                        continue  # Skip corrupted files
            
            # Sort by upload time (newest first)
            files.sort(key=lambda x: x['upload_time'], reverse=True)
            
            return files[:limit]
            
        except Exception as e:
            logger.error(f"File listing error: {str(e)}")
            return []
    
    def delete_file(self, file_id: str) -> bool:
        """Delete uploaded file and metadata"""
        try:
            self._cleanup_expired_file(file_id)
            logger.info(f"File deleted: {file_id}")
            return True
        except Exception as e:
            logger.error(f"File deletion error: {str(e)}")
            return False
    
    def cleanup_expired_files(self) -> int:
        """Clean up expired files and return count"""
        try:
            cleaned_count = 0
            metadata_dir = os.path.join(self.upload_folder, 'metadata')
            
            if not os.path.exists(metadata_dir):
                return 0
            
            current_time = datetime.utcnow()
            
            for filename in os.listdir(metadata_dir):
                if filename.endswith('.json'):
                    file_id = filename[:-5]
                    
                    try:
                        metadata, _ = self._load_file_metadata(file_id)
                        if metadata:
                            expires_at = datetime.fromisoformat(metadata['expires_at'])
                            if current_time > expires_at:
                                self._cleanup_expired_file(file_id)
                                cleaned_count += 1
                    except Exception:
                        # Clean up corrupted files too
                        self._cleanup_expired_file(file_id)
                        cleaned_count += 1
            
            logger.info(f"Cleaned up {cleaned_count} expired files")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")
            return 0
    
    # Private helper methods
    
    def _save_temp_file(self, file, file_id: str) -> str:
        """Save uploaded file to temp location"""
        filename = secure_filename(file.filename)
        temp_path = os.path.join(self.temp_folder, f"{file_id}_{filename}")
        file.save(temp_path)
        return temp_path
    
    def _cleanup_temp_file(self, temp_path: str) -> None:
        """Remove temporary file"""
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass  # Ignore cleanup errors
    
    def _encrypt_file_content(self, content: bytes, algorithm: str, password: str) -> Dict[str, Any]:
        """Encrypt file content using specified algorithm"""
        if algorithm in ['AES-256-GCM', 'AES-256-CBC']:
            # Generate salt and derive key
            salt = generate_salt()
            key = derive_key(password, salt)
            
            if algorithm == 'AES-256-GCM':
                result = self.aes.encrypt_gcm(content, key)
            else:  # AES-256-CBC
                result = self.aes.encrypt_cbc(content, key)
            
            result['salt'] = salt
            return result
        else:
            raise ValueError(f"File encryption not supported for {algorithm}")
    
    def _decrypt_file_content(self, encrypted_data: Dict[str, Any], algorithm: str, password: str) -> bytes:
        """Decrypt file content"""
        if algorithm in ['AES-256-GCM', 'AES-256-CBC']:
            # Derive key from password and salt
            salt = encrypted_data['salt']
            key = derive_key(password, salt)
            
            if algorithm == 'AES-256-GCM':
                return self.aes.decrypt_gcm(
                    encrypted_data['ciphertext'],
                    key,
                    encrypted_data['iv'],
                    encrypted_data['tag']
                )
            else:  # AES-256-CBC
                return self.aes.decrypt_cbc(
                    encrypted_data['ciphertext'],
                    key,
                    encrypted_data['iv']
                )
        else:
            raise ValueError(f"File decryption not supported for {algorithm}")
    
    def _save_encrypted_file(self, encrypted_result: Dict[str, Any], file_id: str, original_filename: str) -> str:
        """Save encrypted file to storage"""
        # Create encrypted files directory
        encrypted_dir = os.path.join(self.upload_folder, 'encrypted')
        os.makedirs(encrypted_dir, exist_ok=True)
        
        # Save encrypted content
        encrypted_path = os.path.join(encrypted_dir, f"{file_id}.enc")
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_result['ciphertext'])
        
        return encrypted_path
    
    def _save_file_metadata(self, file_id: str, metadata: Dict[str, Any], encrypted_data: Dict[str, Any]) -> None:
        """Save file metadata and encryption parameters"""
        import json
        
        # Create metadata directory
        metadata_dir = os.path.join(self.upload_folder, 'metadata')
        os.makedirs(metadata_dir, exist_ok=True)
        
        # Prepare complete metadata
        complete_metadata = metadata.copy()
        complete_metadata['encryption_params'] = {
            'iv': base64.b64encode(encrypted_data['iv']).decode('utf-8'),
            'salt': base64.b64encode(encrypted_data['salt']).decode('utf-8')
        }
        
        if 'tag' in encrypted_data:
            complete_metadata['encryption_params']['tag'] = base64.b64encode(encrypted_data['tag']).decode('utf-8')
        
        # Save metadata
        metadata_path = os.path.join(metadata_dir, f"{file_id}.json")
        with open(metadata_path, 'w') as f:
            json.dump(complete_metadata, f, indent=2)
    
    def _load_file_metadata(self, file_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Load file metadata and encryption parameters"""
        import json
        
        try:
            # Load metadata
            metadata_path = os.path.join(self.upload_folder, 'metadata', f"{file_id}.json")
            if not os.path.exists(metadata_path):
                return None, None
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Load encrypted file
            encrypted_path = os.path.join(self.upload_folder, 'encrypted', f"{file_id}.enc")
            if not os.path.exists(encrypted_path):
                return None, None
            
            with open(encrypted_path, 'rb') as f:
                ciphertext = f.read()
            
            # Reconstruct encryption data
            encryption_params = metadata['encryption_params']
            encrypted_data = {
                'ciphertext': ciphertext,
                'iv': base64.b64decode(encryption_params['iv']),
                'salt': base64.b64decode(encryption_params['salt'])
            }
            
            if 'tag' in encryption_params:
                encrypted_data['tag'] = base64.b64decode(encryption_params['tag'])
            
            return metadata, encrypted_data
            
        except Exception as e:
            logger.error(f"Metadata loading error: {str(e)}")
            return None, None
    
    def _cleanup_expired_file(self, file_id: str) -> None:
        """Remove all files associated with file_id"""
        try:
            # Remove encrypted file
            encrypted_path = os.path.join(self.upload_folder, 'encrypted', f"{file_id}.enc")
            if os.path.exists(encrypted_path):
                os.remove(encrypted_path)
            
            # Remove metadata
            metadata_path = os.path.join(self.upload_folder, 'metadata', f"{file_id}.json")
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
                
        except Exception as e:
            logger.error(f"File cleanup error: {str(e)}")

# Global file manager instance
file_manager = FileManager()

def handle_file_upload(file, algorithm: str, password: str) -> Dict[str, Any]:
    """Global function for file upload handling"""
    return file_manager.handle_file_upload(file, algorithm, password)

def get_file_for_download(file_id: str, password: str) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """Global function for file download"""
    return file_manager.get_encrypted_file(file_id, password)

def list_uploaded_files(limit: int = 50) -> list:
    """Global function for listing files"""
    return file_manager.list_files(limit)

def delete_uploaded_file(file_id: str) -> bool:
    """Global function for file deletion"""
    return file_manager.delete_file(file_id)

def cleanup_old_files() -> int:
    """Global function for cleanup"""
    return file_manager.cleanup_expired_files()

# Image-specific utilities
def process_image_file(file_path: str, algorithm: str = 'AES-256-CBC') -> Dict[str, Any]:
    """Process image file with specific algorithms"""
    try:
        from PIL import Image
        import numpy as np
        
        # Load image
        img = Image.open(file_path)
        img_array = np.array(img)
        
        # Convert to bytes
        img_bytes = img_array.tobytes()
        
        # Get image metadata
        metadata = {
            'format': img.format,
            'mode': img.mode,
            'size': img.size,
            'shape': img_array.shape
        }
        
        return {
            'success': True,
            'data': img_bytes,
            'metadata': metadata
        }
        
    except Exception as e:
        logger.error(f"Image processing error: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def reconstruct_image(data: bytes, metadata: Dict[str, Any], output_path: str) -> bool:
    """Reconstruct image from decrypted bytes"""
    try:
        from PIL import Image
        import numpy as np
        
        # Reconstruct array
        img_array = np.frombuffer(data, dtype=np.uint8)
        img_array = img_array.reshape(metadata['shape'])
        
        # Create image
        img = Image.fromarray(img_array, mode=metadata['mode'])
        
        # Save reconstructed image
        img.save(output_path, format=metadata['format'])
        
        return True
        
    except Exception as e:
        logger.error(f"Image reconstruction error: {str(e)}")
        return False

# File type detection utilities
def detect_file_type(file_path: str) -> str:
    """Detect file type from content"""
    try:
        import magic
        mime_type = magic.from_file(file_path, mime=True)
        return mime_type
    except ImportError:
        # Fallback to extension-based detection
        _, ext = os.path.splitext(file_path)
        ext_map = {
            '.txt': 'text/plain',
            '.jpg': 'image/jpeg',
            '.png': 'image/png',
            '.pdf': 'application/pdf',
            '.mp4': 'video/mp4'
        }
        return ext_map.get(ext.lower(), 'application/octet-stream')

def get_file_stats() -> Dict[str, Any]:
    """Get statistics about uploaded files"""
    try:
        stats = {
            'total_files': 0,
            'total_size': 0,
            'algorithms_used': {},
            'file_types': {},
            'oldest_file': None,
            'newest_file': None
        }
        
        files = list_uploaded_files(1000)  # Get more files for stats
        
        stats['total_files'] = len(files)
        
        for file_info in files:
            # Algorithm statistics
            algo = file_info['algorithm']
            stats['algorithms_used'][algo] = stats['algorithms_used'].get(algo, 0) + 1
            
            # Size statistics
            stats['total_size'] += file_info['size']
            
            # Track oldest and newest
            upload_time = file_info['upload_time']
            if not stats['oldest_file'] or upload_time < stats['oldest_file']:
                stats['oldest_file'] = upload_time
            if not stats['newest_file'] or upload_time > stats['newest_file']:
                stats['newest_file'] = upload_time
        
        return stats
        
    except Exception as e:
        logger.error(f"Stats generation error: {str(e)}")
        return {'error': str(e)}