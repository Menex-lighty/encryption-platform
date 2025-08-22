"""
Pytest Configuration and Shared Fixtures
Central configuration for all test modules
"""

import pytest
import os
import sys
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import patch

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import app

# Test configuration
def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance benchmarks"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security tests"
    )

def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically"""
    for item in items:
        # Add markers based on test file names
        if "test_performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
        elif "test_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        elif "test_crypto" in item.nodeid or "test_utils" in item.nodeid:
            item.add_marker(pytest.mark.unit)
        
        # Add slow marker for certain test patterns
        if any(pattern in item.nodeid for pattern in ["benchmark", "stress", "large_data"]):
            item.add_marker(pytest.mark.slow)

# Shared fixtures
@pytest.fixture(scope="session")
def test_config():
    """Provide test configuration"""
    return {
        'test_password': 'test_password_123',
        'test_data': {
            'small': b'Hello World!',
            'medium': b'A' * 1024,  # 1KB
            'large': b'A' * (100 * 1024),  # 100KB
        },
        'test_algorithms': [
            'AES-256-GCM',
            'ChaCha20-Poly1305',
            'Caesar',
            'RSA-4096'
        ],
        'test_files': {
            'text': ('test.txt', b'Test file content', 'text/plain'),
            'json': ('test.json', json.dumps({'test': 'data'}).encode(), 'application/json'),
            'binary': ('test.bin', bytes(range(256)), 'application/octet-stream')
        }
    }

@pytest.fixture(scope="function")
def temp_directory():
    """Provide a temporary directory for tests"""
    temp_dir = tempfile.mkdtemp(prefix="uep_test_")
    yield temp_dir
    # Cleanup
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except:
        pass

@pytest.fixture(scope="function")
def test_app():
    """Provide a Flask test application"""
    # Set testing environment
    os.environ['FLASK_ENV'] = 'testing'
    
    # Create app with test configuration
    test_app = app.create_app()
    test_app.config['TESTING'] = True
    test_app.config['WTF_CSRF_ENABLED'] = False
    test_app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()
    
    # Create application context
    with test_app.app_context():
        yield test_app
    
    # Cleanup upload folder
    try:
        shutil.rmtree(test_app.config['UPLOAD_FOLDER'], ignore_errors=True)
    except:
        pass

@pytest.fixture(scope="function")
def test_client(test_app):
    """Provide a Flask test client"""
    with test_app.test_client() as client:
        yield client

@pytest.fixture(scope="function")
def crypto_instances():
    """Provide crypto algorithm instances"""
    from crypto.symmetric import AESCrypto, ChaCha20Crypto
    from crypto.asymmetric import RSACrypto
    from crypto.classical import CaesarCipher, VigenereCipher
    
    return {
        'aes': AESCrypto(),
        'chacha20': ChaCha20Crypto(),
        'rsa': RSACrypto(),
        'caesar': CaesarCipher(),
        'vigenere': VigenereCipher()
    }

@pytest.fixture(scope="function")
def test_keys(test_config):
    """Provide test encryption keys"""
    from crypto.utils import generate_salt, derive_key
    
    password = test_config['test_password']
    salt = generate_salt()
    
    return {
        'password': password,
        'salt': salt,
        'aes_key': derive_key(password, salt, length=32),
        'chacha_key': os.urandom(32),
        'rsa_keys': None  # Will be generated when needed
    }

@pytest.fixture(scope="function")
def sample_files(temp_directory, test_config):
    """Create sample files for testing"""
    files = {}
    
    for file_type, (filename, content, mime_type) in test_config['test_files'].items():
        file_path = Path(temp_directory) / filename
        file_path.write_bytes(content)
        
        files[file_type] = {
            'path': str(file_path),
            'content': content,
            'mime_type': mime_type,
            'size': len(content)
        }
    
    return files

@pytest.fixture(scope="function")
def mock_file_upload():
    """Mock file upload for testing"""
    import io
    
    def create_mock_file(content, filename, content_type='text/plain'):
        """Create a mock file object"""
        file_obj = io.BytesIO(content)
        file_obj.name = filename
        file_obj.content_type = content_type
        return file_obj
    
    return create_mock_file

@pytest.fixture(scope="session")
def performance_tracker():
    """Track performance metrics across tests"""
    metrics = {
        'encryption_times': {},
        'memory_usage': {},
        'api_response_times': []
    }
    
    yield metrics
    
    # Optional: Save performance data
    performance_file = Path(__file__).parent / 'performance_results.json'
    try:
        with open(performance_file, 'w') as f:
            json.dump(metrics, f, indent=2, default=str)
    except:
        pass

@pytest.fixture(scope="function")
def memory_monitor():
    """Monitor memory usage during tests"""
    import psutil
    
    process = psutil.Process()
    initial_memory = process.memory_info().rss
    
    monitor = {
        'initial': initial_memory,
        'peak': initial_memory,
        'current': initial_memory
    }
    
    def update_memory():
        current = process.memory_info().rss
        monitor['current'] = current
        monitor['peak'] = max(monitor['peak'], current)
        return current
    
    monitor['update'] = update_memory
    
    yield monitor
    
    # Final update
    update_memory()

@pytest.fixture(scope="function")
def error_collector():
    """Collect errors and warnings during tests"""
    errors = []
    warnings = []
    
    collector = {
        'errors': errors,
        'warnings': warnings,
        'add_error': lambda e: errors.append(str(e)),
        'add_warning': lambda w: warnings.append(str(w))
    }
    
    yield collector

# Utility functions for tests
def create_test_data(size_kb=1):
    """Create test data of specified size"""
    return b'A' * (size_kb * 1024)

def assert_valid_encryption_result(result):
    """Assert that an encryption result has valid structure"""
    assert isinstance(result, dict)
    assert 'ciphertext' in result or 'encrypted_data' in result
    assert 'metadata' in result or any(key in result for key in ['iv', 'nonce', 'tag'])

def assert_api_response_valid(response, expected_status=200):
    """Assert that an API response is valid"""
    assert response.status_code == expected_status
    
    if response.content_type == 'application/json':
        data = json.loads(response.data)
        assert 'success' in data
        
        if data['success']:
            assert 'error' not in data or not data['error']
        else:
            assert 'error' in data

# Mock objects for testing
class MockAlgorithm:
    """Mock encryption algorithm for testing"""
    
    def __init__(self, name):
        self.name = name
    
    def encrypt(self, data, key):
        return {
            'ciphertext': f"encrypted_{data.decode()}".encode(),
            'iv': b'mock_iv',
            'tag': b'mock_tag'
        }
    
    def decrypt(self, ciphertext, key, iv, tag):
        return ciphertext.replace(b'encrypted_', b'')

class MockFileHandler:
    """Mock file handler for testing"""
    
    def __init__(self):
        self.files = {}
    
    def save_file(self, file_obj, filename):
        file_id = f"mock_{len(self.files)}"
        self.files[file_id] = {
            'filename': filename,
            'content': file_obj.read(),
            'size': len(file_obj.read())
        }
        return file_id
    
    def get_file(self, file_id):
        return self.files.get(file_id)

# Test data generators
def generate_test_passwords():
    """Generate various test passwords"""
    return [
        'simple',
        'Complex123!',
        'very_long_password_with_many_characters_123456789',
        'unicode_测试_🔐',
        'special!@#$%^&*()_+{}|:<>?[]\\;\'\".,/`~'
    ]

def generate_test_data_sizes():
    """Generate test data of various sizes"""
    sizes = {
        'empty': b'',
        'tiny': b'x',
        'small': b'x' * 100,
        'medium': b'x' * 10000,
        'large': b'x' * 1000000
    }
    return sizes

# Parameterized test data
ALGORITHM_PARAMS = [
    'AES-256-GCM',
    'ChaCha20-Poly1305',
    'Caesar',
]

DATA_SIZE_PARAMS = [
    ('tiny', 10),
    ('small', 1000),
    ('medium', 10000),
]

PASSWORD_PARAMS = [
    'simple_password',
    'Complex_P@ssw0rd_123!',
    'unicode_密码_🔐'
]

# Custom pytest markers
slow = pytest.mark.slow
performance = pytest.mark.performance
integration = pytest.mark.integration
unit = pytest.mark.unit
security = pytest.mark.security

# Skip conditions
skip_if_no_crypto = pytest.mark.skipif(
    not os.path.exists(Path(__file__).parent.parent / 'crypto'),
    reason="Crypto modules not available"
)

skip_if_no_app = pytest.mark.skipif(
    not os.path.exists(Path(__file__).parent.parent / 'app.py'),
    reason="Flask app not available"
)

# Environment-specific skips
skip_on_windows = pytest.mark.skipif(
    sys.platform.startswith('win'),
    reason="Test not compatible with Windows"
)

skip_on_ci = pytest.mark.skipif(
    os.environ.get('CI') == 'true',
    reason="Test not suitable for CI environment"
)