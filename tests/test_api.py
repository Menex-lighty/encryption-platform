"""
Test Suite for API Endpoints
Tests for Flask routes and API functionality
"""

import pytest
import json
import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import app
from app import create_app

class TestAPIEndpoints:
    """Test main API endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        # Set testing environment
        os.environ['FLASK_ENV'] = 'testing'
        
        # Create app
        test_app = create_app()
        test_app.config['TESTING'] = True
        test_app.config['WTF_CSRF_ENABLED'] = False
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_home_page(self, client):
        """Test home page loads"""
        response = client.get('/')
        assert response.status_code == 200
        assert b'Universal Encryption Platform' in response.data
    
    def test_demo_page(self, client):
        """Test demo page loads"""
        response = client.get('/demo')
        assert response.status_code == 200
        assert b'Interactive Demo' in response.data
    
    def test_docs_page(self, client):
        """Test documentation page loads"""
        response = client.get('/docs')
        assert response.status_code == 200
        assert b'API Documentation' in response.data
    
    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get('/api/health')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
        assert 'algorithms_loaded' in data

class TestEncryptionAPI:
    """Test encryption/decryption endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_aes_text_encryption(self, client):
        """Test AES-256-GCM text encryption"""
        data = {
            'data': 'Hello World!',
            'data_type': 'text',
            'algorithm': 'AES-256-GCM',
            'password': 'test_password',
            'options': {
                'output_format': 'base64'
            }
        }
        
        response = client.post(
            '/api/encrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        result = json.loads(response.data)
        
        assert result['success'] is True
        assert 'encrypted_data' in result
        assert 'metadata' in result
        assert result['metadata']['algorithm'] == 'AES-256-GCM'
        assert 'iv' in result['metadata']
        assert 'tag' in result['metadata']
        assert 'salt' in result['metadata']
    
    def test_chacha20_text_encryption(self, client):
        """Test ChaCha20-Poly1305 text encryption"""
        data = {
            'data': 'Test message for ChaCha20',
            'algorithm': 'ChaCha20-Poly1305',
            'password': 'secure_password'
        }
        
        response = client.post(
            '/api/encrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        result = json.loads(response.data)
        
        assert result['success'] is True
        assert result['metadata']['algorithm'] == 'ChaCha20-Poly1305'
        assert 'nonce' in result['metadata']
    
    def test_caesar_encryption(self, client):
        """Test Caesar cipher encryption"""
        data = {
            'data': 'Hello Caesar',
            'algorithm': 'Caesar',
            'options': {
                'shift': 5
            }
        }
        
        response = client.post(
            '/api/encrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        result = json.loads(response.data)
        
        assert result['success'] is True
        assert result['metadata']['algorithm'] == 'Caesar'
        assert result['metadata']['shift'] == 5
    
    def test_decryption(self, client):
        """Test decryption endpoint"""
        # First encrypt some data
        encrypt_data = {
            'data': 'Decrypt this message',
            'algorithm': 'AES-256-GCM',
            'password': 'test_password'
        }
        
        encrypt_response = client.post(
            '/api/encrypt',
            data=json.dumps(encrypt_data),
            content_type='application/json'
        )
        
        assert encrypt_response.status_code == 200
        encrypt_result = json.loads(encrypt_response.data)
        
        # Now decrypt it
        decrypt_data = {
            'encrypted_data': encrypt_result['encrypted_data'],
            'algorithm': 'AES-256-GCM',
            'password': 'test_password',
            'metadata': encrypt_result['metadata']
        }
        
        decrypt_response = client.post(
            '/api/decrypt',
            data=json.dumps(decrypt_data),
            content_type='application/json'
        )
        
        assert decrypt_response.status_code == 200
        decrypt_result = json.loads(decrypt_response.data)
        
        assert decrypt_result['success'] is True
        assert decrypt_result['decrypted_data'] == 'Decrypt this message'
    
    def test_invalid_algorithm(self, client):
        """Test error handling for invalid algorithm"""
        data = {
            'data': 'Test data',
            'algorithm': 'INVALID_ALGORITHM',
            'password': 'password'
        }
        
        response = client.post(
            '/api/encrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert result['success'] is False
        assert 'error' in result
    
    def test_missing_password(self, client):
        """Test error handling for missing password"""
        data = {
            'data': 'Test data',
            'algorithm': 'AES-256-GCM'
            # Missing password
        }
        
        response = client.post(
            '/api/encrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert result['success'] is False
    
    def test_wrong_password_decrypt(self, client):
        """Test decryption with wrong password"""
        # Encrypt with one password
        encrypt_data = {
            'data': 'Secret message',
            'algorithm': 'AES-256-GCM',
            'password': 'correct_password'
        }
        
        encrypt_response = client.post(
            '/api/encrypt',
            data=json.dumps(encrypt_data),
            content_type='application/json'
        )
        
        encrypt_result = json.loads(encrypt_response.data)
        
        # Try to decrypt with wrong password
        decrypt_data = {
            'encrypted_data': encrypt_result['encrypted_data'],
            'algorithm': 'AES-256-GCM',
            'password': 'wrong_password',
            'metadata': encrypt_result['metadata']
        }
        
        decrypt_response = client.post(
            '/api/decrypt',
            data=json.dumps(decrypt_data),
            content_type='application/json'
        )
        
        assert decrypt_response.status_code == 400
        result = json.loads(decrypt_response.data)
        assert result['success'] is False

class TestAlgorithmAPI:
    """Test algorithm information endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_list_all_algorithms(self, client):
        """Test listing all algorithms"""
        response = client.get('/api/algorithms')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'algorithms' in data
        assert 'text' in data['algorithms']
        assert 'image' in data['algorithms']
        assert 'file' in data['algorithms']
        
        # Check for expected algorithms
        text_algorithms = [algo['name'] for algo in data['algorithms']['text']]
        assert 'AES-256-GCM' in text_algorithms
        assert 'ChaCha20-Poly1305' in text_algorithms
        assert 'Caesar' in text_algorithms
    
    def test_list_algorithms_by_type(self, client):
        """Test listing algorithms by data type"""
        response = client.get('/api/algorithms/text')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['data_type'] == 'text'
        assert 'algorithms' in data
        
        # Verify algorithm properties
        for algo in data['algorithms']:
            assert 'name' in algo
            assert 'security_level' in algo
            assert 'speed' in algo
            assert 'description' in algo
    
    def test_invalid_data_type(self, client):
        """Test invalid data type"""
        response = client.get('/api/algorithms/invalid_type')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data

class TestFileAPI:
    """Test file upload and management endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        test_app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_file_upload_encryption(self, client):
        """Test file upload and encryption"""
        # Create a test file
        test_content = b"This is test file content for encryption"
        
        data = {
            'algorithm': 'AES-256-GCM',
            'password': 'file_password'
        }
        
        # Simulate file upload
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as tmp_file:
            tmp_file.write(test_content)
            tmp_file.flush()
            
            with open(tmp_file.name, 'rb') as f:
                data['file'] = (f, 'test.txt')
                
                response = client.post(
                    '/api/encrypt/file',
                    data=data,
                    content_type='multipart/form-data'
                )
        
        # Clean up
        os.unlink(tmp_file.name)
        
        assert response.status_code == 200
        result = json.loads(response.data)
        
        assert result['success'] is True
        assert 'file_id' in result
        assert 'download_url' in result
        assert 'metadata' in result
    
    def test_file_list(self, client):
        """Test file listing endpoint"""
        response = client.get('/api/files')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'files' in data
        assert 'pagination' in data

class TestValidationAPI:
    """Test input validation"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_empty_data(self, client):
        """Test validation of empty data"""
        data = {
            'data': '',  # Empty data
            'algorithm': 'AES-256-GCM',
            'password': 'password'
        }
        
        response = client.post(
            '/api/encrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert result['success'] is False
    
    def test_invalid_json(self, client):
        """Test handling of invalid JSON"""
        response = client.post(
            '/api/encrypt',
            data='invalid json',
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_missing_required_fields(self, client):
        """Test handling of missing required fields"""
        data = {
            'algorithm': 'AES-256-GCM'
            # Missing data and password
        }
        
        response = client.post(
            '/api/encrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert result['success'] is False

class TestSystemAPI:
    """Test system utility endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_encryption_test(self, client):
        """Test encryption test endpoint"""
        data = {
            'algorithm': 'AES-256-GCM'
        }
        
        response = client.post(
            '/api/test/encryption',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        result = json.loads(response.data)
        
        assert result['success'] is True
        assert result['round_trip_successful'] is True
        assert result['algorithm'] == 'AES-256-GCM'

class TestCORSHeaders:
    """Test CORS configuration"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_cors_headers(self, client):
        """Test CORS headers are present"""
        response = client.get('/api/health')
        
        # Check for CORS headers
        assert 'Access-Control-Allow-Origin' in response.headers
    
    def test_options_request(self, client):
        """Test OPTIONS request for CORS preflight"""
        response = client.options('/api/encrypt')
        assert response.status_code == 200

class TestErrorHandling:
    """Test error handling across API"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_404_error(self, client):
        """Test 404 error handling"""
        response = client.get('/api/nonexistent')
        assert response.status_code == 404
    
    def test_method_not_allowed(self, client):
        """Test 405 error handling"""
        response = client.put('/api/health')  # Health endpoint only accepts GET
        assert response.status_code == 405
    
    def test_large_payload(self, client):
        """Test payload too large error"""
        # Create very large data
        large_data = {
            'data': 'A' * (20 * 1024 * 1024),  # 20MB
            'algorithm': 'AES-256-GCM',
            'password': 'password'
        }
        
        response = client.post(
            '/api/encrypt',
            data=json.dumps(large_data),
            content_type='application/json'
        )
        
        # Should return 413 or 400 depending on server configuration
        assert response.status_code in [400, 413]

if __name__ == '__main__':
    # Run tests if script is executed directly
    pytest.main([__file__, '-v', '--tb=short'])