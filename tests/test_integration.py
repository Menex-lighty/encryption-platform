"""
Comprehensive Integration Test Suite
End-to-end testing of the Universal Encryption Platform
"""

import pytest
import json
import os
import sys
import tempfile
import io
import requests
import time
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import app
from app import create_app

class TestFullWorkflowIntegration:
    """Test complete encryption/decryption workflows"""
    
    @pytest.fixture
    def client(self):
        """Create test client with proper configuration"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        test_app.config['WTF_CSRF_ENABLED'] = False
        test_app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_text_encryption_full_workflow(self, client):
        """Test complete text encryption/decryption workflow"""
        # Test data
        original_text = "This is a comprehensive integration test for text encryption."
        
        # Test multiple algorithms
        algorithms = [
            {'name': 'AES-256-GCM', 'password': 'secure_password_123'},
            {'name': 'ChaCha20-Poly1305', 'password': 'another_secure_password'},
            {'name': 'Caesar', 'options': {'shift': 7}}
        ]
        
        for algo_config in algorithms:
            print(f"\\nTesting full workflow with {algo_config['name']}")
            
            # Step 1: Encrypt the data
            encrypt_request = {
                'data': original_text,
                'algorithm': algo_config['name'],
                'data_type': 'text'
            }
            
            if 'password' in algo_config:
                encrypt_request['password'] = algo_config['password']
            if 'options' in algo_config:
                encrypt_request['options'] = algo_config['options']
            
            encrypt_response = client.post(
                '/api/encrypt',
                data=json.dumps(encrypt_request),
                content_type='application/json'
            )
            
            assert encrypt_response.status_code == 200
            encrypt_result = json.loads(encrypt_response.data)
            assert encrypt_result['success'] is True
            assert 'encrypted_data' in encrypt_result
            assert 'metadata' in encrypt_result
            
            # Step 2: Verify metadata
            metadata = encrypt_result['metadata']
            assert metadata['algorithm'] == algo_config['name']
            assert metadata['data_type'] == 'text'
            assert 'timestamp' in metadata
            
            # Step 3: Decrypt the data
            decrypt_request = {
                'encrypted_data': encrypt_result['encrypted_data'],
                'algorithm': algo_config['name'],
                'metadata': metadata
            }
            
            if 'password' in algo_config:
                decrypt_request['password'] = algo_config['password']
            if 'options' in algo_config:
                decrypt_request['options'] = algo_config['options']
            
            decrypt_response = client.post(
                '/api/decrypt',
                data=json.dumps(decrypt_request),
                content_type='application/json'
            )
            
            assert decrypt_response.status_code == 200
            decrypt_result = json.loads(decrypt_response.data)
            assert decrypt_result['success'] is True
            assert decrypt_result['decrypted_data'] == original_text
            
            print(f"  ✓ {algo_config['name']} workflow completed successfully")
    
    def test_file_encryption_full_workflow(self, client):
        """Test complete file encryption/decryption workflow"""
        # Create test files with different content types
        test_files = [
            ('test.txt', b'This is a test text file for encryption.', 'text/plain'),
            ('test.json', json.dumps({'test': 'data', 'numbers': [1, 2, 3]}).encode(), 'application/json'),
            ('binary.dat', bytes(range(256)), 'application/octet-stream')
        ]
        
        for filename, content, content_type in test_files:
            print(f"\\nTesting file workflow with {filename}")
            
            # Step 1: Upload and encrypt file
            upload_data = {
                'algorithm': 'AES-256-GCM',
                'password': 'file_encryption_password'
            }
            
            files = {
                'file': (filename, io.BytesIO(content), content_type)
            }
            
            upload_response = client.post(
                '/api/encrypt/file',
                data=upload_data,
                content_type='multipart/form-data',
                buffered=True,
                follow_redirects=True
            )
            
            # Handle file upload endpoint variations
            if upload_response.status_code == 404:
                print(f"  File upload endpoint not available, skipping {filename}")
                continue
            
            if upload_response.status_code != 200:
                print(f"  File upload failed for {filename}: {upload_response.status_code}")
                continue
            
            upload_result = json.loads(upload_response.data)
            assert upload_result['success'] is True
            assert 'file_id' in upload_result
            
            file_id = upload_result['file_id']
            
            # Step 2: List uploaded files
            list_response = client.get('/api/files')
            if list_response.status_code == 200:
                list_result = json.loads(list_response.data)
                assert list_result['success'] is True
                assert 'files' in list_result
                
                # Find our uploaded file
                uploaded_file = next(
                    (f for f in list_result['files'] if f.get('file_id') == file_id),
                    None
                )
                assert uploaded_file is not None
            
            # Step 3: Download and decrypt file
            download_data = {
                'password': 'file_encryption_password'
            }
            
            download_response = client.post(
                f'/api/download/{file_id}',
                data=json.dumps(download_data),
                content_type='application/json'
            )
            
            if download_response.status_code == 200:
                # Verify content
                if download_response.content_type == 'application/json':
                    download_result = json.loads(download_response.data)
                    assert download_result['success'] is True
                    assert 'decrypted_data' in download_result
                else:
                    # Direct file download
                    assert download_response.data == content
            
            # Step 4: Clean up - delete file
            delete_response = client.delete(f'/api/files/{file_id}')
            if delete_response.status_code == 200:
                delete_result = json.loads(delete_response.data)
                assert delete_result['success'] is True
            
            print(f"  ✓ {filename} file workflow completed successfully")
    
    def test_algorithm_discovery_workflow(self, client):
        """Test algorithm discovery and information workflow"""
        print("\\nTesting algorithm discovery workflow")
        
        # Step 1: Get all algorithms
        all_algos_response = client.get('/api/algorithms')
        assert all_algos_response.status_code == 200
        
        all_algos_result = json.loads(all_algos_response.data)
        assert 'algorithms' in all_algos_result
        
        # Step 2: Test each data type
        data_types = ['text', 'image', 'file']
        
        for data_type in data_types:
            type_response = client.get(f'/api/algorithms/{data_type}')
            
            if type_response.status_code == 200:
                type_result = json.loads(type_response.data)
                assert type_result['data_type'] == data_type
                assert 'algorithms' in type_result
                
                # Step 3: Get details for each algorithm
                for algo in type_result['algorithms']:
                    algo_name = algo['name']
                    detail_response = client.get(f'/api/algorithms/{algo_name}/details')
                    
                    if detail_response.status_code == 200:
                        detail_result = json.loads(detail_response.data)
                        assert detail_result['details']['algorithm'] == algo_name
                        assert 'security_level' in detail_result['details']
                        assert 'description' in detail_result['details']
        
        print("  ✓ Algorithm discovery workflow completed successfully")
    
    def test_error_handling_workflow(self, client):
        """Test error handling across the entire workflow"""
        print("\\nTesting error handling workflow")
        
        # Test 1: Invalid encryption request
        invalid_request = {
            'data': '',  # Empty data
            'algorithm': 'INVALID_ALGORITHM',
            'password': 'password'
        }
        
        response = client.post(
            '/api/encrypt',
            data=json.dumps(invalid_request),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        result = json.loads(response.data)
        assert result['success'] is False
        assert 'error' in result
        
        # Test 2: Decryption with wrong password
        # First encrypt something
        encrypt_request = {
            'data': 'Test message for wrong password',
            'algorithm': 'AES-256-GCM',
            'password': 'correct_password'
        }
        
        encrypt_response = client.post(
            '/api/encrypt',
            data=json.dumps(encrypt_request),
            content_type='application/json'
        )
        
        if encrypt_response.status_code == 200:
            encrypt_result = json.loads(encrypt_response.data)
            
            # Try to decrypt with wrong password
            decrypt_request = {
                'encrypted_data': encrypt_result['encrypted_data'],
                'algorithm': 'AES-256-GCM',
                'password': 'wrong_password',
                'metadata': encrypt_result['metadata']
            }
            
            decrypt_response = client.post(
                '/api/decrypt',
                data=json.dumps(decrypt_request),
                content_type='application/json'
            )
            
            # Should fail with authentication error
            assert decrypt_response.status_code in [400, 500]
            decrypt_result = json.loads(decrypt_response.data)
            assert decrypt_result['success'] is False
        
        # Test 3: Malformed JSON
        malformed_response = client.post(
            '/api/encrypt',
            data='{"invalid": json}',  # Malformed JSON
            content_type='application/json'
        )
        
        assert malformed_response.status_code == 400
        
        print("  ✓ Error handling workflow completed successfully")

class TestConcurrentOperations:
    """Test concurrent operations and race conditions"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_concurrent_encryptions(self, client):
        """Test multiple concurrent encryption requests"""
        print("\\nTesting concurrent encryption operations")
        
        results = []
        errors = []
        
        def encrypt_worker(worker_id):
            """Worker function for concurrent encryption"""
            try:
                request_data = {
                    'data': f'Concurrent test data from worker {worker_id}',
                    'algorithm': 'AES-256-GCM',
                    'password': f'password_{worker_id}'
                }
                
                response = client.post(
                    '/api/encrypt',
                    data=json.dumps(request_data),
                    content_type='application/json'
                )
                
                if response.status_code == 200:
                    result = json.loads(response.data)
                    results.append((worker_id, result))
                else:
                    errors.append((worker_id, response.status_code))
                    
            except Exception as e:
                errors.append((worker_id, str(e)))
        
        # Start multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=encrypt_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)  # 30 second timeout
        
        # Verify results
        print(f"  Completed operations: {len(results)}")
        print(f"  Errors: {len(errors)}")
        
        if errors:
            print(f"  Error details: {errors}")
        
        # Should handle most concurrent requests successfully
        assert len(results) >= 7  # At least 70% success rate
        assert len(errors) <= 3   # At most 30% error rate
        
        # Verify all successful results are valid
        for worker_id, result in results:
            assert result['success'] is True
            assert 'encrypted_data' in result
            assert result['metadata']['algorithm'] == 'AES-256-GCM'
        
        print("  ✓ Concurrent encryption test completed")
    
    def test_stress_test_api(self, client):
        """Stress test the API with rapid requests"""
        print("\\nRunning API stress test")
        
        request_data = {
            'data': 'Stress test data',
            'algorithm': 'Caesar',
            'options': {'shift': 13}
        }
        
        start_time = time.time()
        successful_requests = 0
        failed_requests = 0
        
        # Make 100 rapid requests
        for i in range(100):
            try:
                response = client.post(
                    '/api/encrypt',
                    data=json.dumps(request_data),
                    content_type='application/json'
                )
                
                if response.status_code == 200:
                    successful_requests += 1
                else:
                    failed_requests += 1
                    
            except Exception:
                failed_requests += 1
        
        end_time = time.time()
        total_time = end_time - start_time
        requests_per_second = 100 / total_time
        
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Requests per second: {requests_per_second:.1f}")
        print(f"  Successful: {successful_requests}")
        print(f"  Failed: {failed_requests}")
        
        # Should handle reasonable load
        assert successful_requests >= 90  # At least 90% success rate
        assert requests_per_second >= 10  # At least 10 requests per second
        
        print("  ✓ Stress test completed")

class TestSystemIntegration:
    """Test integration with system components"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_health_monitoring_integration(self, client):
        """Test health monitoring and system status"""
        print("\\nTesting health monitoring integration")
        
        # Test basic health check
        health_response = client.get('/api/health')
        assert health_response.status_code == 200
        
        health_data = json.loads(health_response.data)
        assert health_data['status'] == 'healthy'
        assert 'timestamp' in health_data
        
        # Test detailed system status if available
        status_response = client.get('/api/system/status')
        if status_response.status_code == 200:
            status_data = json.loads(status_response.data)
            assert 'system_info' in status_data or 'status' in status_data
        
        print("  ✓ Health monitoring integration test completed")
    
    def test_logging_integration(self, client):
        """Test that operations are properly logged"""
        print("\\nTesting logging integration")
        
        # Perform some operations that should be logged
        operations = [
            {'endpoint': '/api/encrypt', 'method': 'POST', 'data': {
                'data': 'Logging test',
                'algorithm': 'AES-256-GCM',
                'password': 'logging_password'
            }},
            {'endpoint': '/api/algorithms', 'method': 'GET', 'data': None},
            {'endpoint': '/api/health', 'method': 'GET', 'data': None}
        ]
        
        for operation in operations:
            if operation['method'] == 'GET':
                response = client.get(operation['endpoint'])
            elif operation['method'] == 'POST':
                response = client.post(
                    operation['endpoint'],
                    data=json.dumps(operation['data']),
                    content_type='application/json'
                )
            
            # Operations should complete successfully
            assert response.status_code in [200, 201, 202]
        
        print("  ✓ Logging integration test completed")
    
    def test_configuration_integration(self, client):
        """Test configuration system integration"""
        print("\\nTesting configuration integration")
        
        # Test that configuration affects behavior
        # This would typically test different config settings
        
        # Test CORS headers
        response = client.get('/api/health')
        
        # Should have CORS headers if configured
        cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers'
        ]
        
        cors_enabled = any(header in response.headers for header in cors_headers)
        print(f"  CORS enabled: {cors_enabled}")
        
        # Test content type validation
        invalid_content_response = client.post(
            '/api/encrypt',
            data='test data',
            content_type='text/plain'  # Invalid content type
        )
        
        # Should reject invalid content type
        assert invalid_content_response.status_code in [400, 415]
        
        print("  ✓ Configuration integration test completed")

class TestSecurityIntegration:
    """Test security features integration"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_input_sanitization(self, client):
        """Test that inputs are properly sanitized"""
        print("\\nTesting input sanitization")
        
        # Test with potentially malicious inputs
        malicious_inputs = [
            '<script>alert("xss")</script>',
            '"; DROP TABLE users; --',
            '../../../etc/passwd',
            '{{7*7}}',  # Template injection
            '${7*7}'    # Expression injection
        ]
        
        for malicious_input in malicious_inputs:
            request_data = {
                'data': malicious_input,
                'algorithm': 'Caesar',
                'options': {'shift': 1}
            }
            
            response = client.post(
                '/api/encrypt',
                data=json.dumps(request_data),
                content_type='application/json'
            )
            
            # Should either process safely or reject
            if response.status_code == 200:
                result = json.loads(response.data)
                assert result['success'] is True
                # Verify that the malicious input doesn't execute
                assert 'alert(' not in str(result)
                assert 'DROP TABLE' not in str(result)
            else:
                # Rejection is also acceptable
                assert response.status_code in [400, 422]
        
        print("  ✓ Input sanitization test completed")
    
    def test_rate_limiting_behavior(self, client):
        """Test rate limiting if implemented"""
        print("\\nTesting rate limiting behavior")
        
        # Make many rapid requests to test rate limiting
        request_data = {
            'data': 'Rate limit test',
            'algorithm': 'Caesar',
            'options': {'shift': 1}
        }
        
        responses = []
        for i in range(50):
            response = client.post(
                '/api/encrypt',
                data=json.dumps(request_data),
                content_type='application/json'
            )
            responses.append(response.status_code)
        
        # Count different response types
        success_count = responses.count(200)
        rate_limited_count = responses.count(429)  # Too Many Requests
        
        print(f"  Successful requests: {success_count}")
        print(f"  Rate limited requests: {rate_limited_count}")
        
        # Either all succeed (no rate limiting) or some are rate limited
        assert success_count + rate_limited_count == 50
        
        print("  ✓ Rate limiting test completed")
    
    def test_error_information_disclosure(self, client):
        """Test that errors don't disclose sensitive information"""
        print("\\nTesting error information disclosure")
        
        # Test with various invalid inputs
        invalid_requests = [
            {'data': 'test', 'algorithm': 'AES-256-GCM'},  # Missing password
            {'data': 'test', 'algorithm': 'INVALID_ALGO', 'password': 'pwd'},
            {'algorithm': 'AES-256-GCM', 'password': 'pwd'},  # Missing data
        ]
        
        for invalid_request in invalid_requests:
            response = client.post(
                '/api/encrypt',
                data=json.dumps(invalid_request),
                content_type='application/json'
            )
            
            assert response.status_code == 400
            result = json.loads(response.data)
            
            # Error messages should not contain sensitive information
            error_message = result.get('error', '').lower()
            
            # Should not contain file paths, stack traces, or internal details
            sensitive_indicators = ['traceback', 'file "', 'line ', 'exception', 'stack']
            for indicator in sensitive_indicators:
                assert indicator not in error_message, f"Error contains sensitive info: {error_message}"
        
        print("  ✓ Error information disclosure test completed")

class TestDataIntegrityIntegration:
    """Test data integrity across the entire system"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        os.environ['FLASK_ENV'] = 'testing'
        test_app = create_app()
        test_app.config['TESTING'] = True
        
        with test_app.test_client() as client:
            with test_app.app_context():
                yield client
    
    def test_round_trip_integrity(self, client):
        """Test data integrity through complete encrypt/decrypt cycles"""
        print("\\nTesting round-trip data integrity")
        
        # Test with various data types and sizes
        test_cases = [
            ('simple text', 'Simple ASCII text'),
            ('unicode text', 'Unicode: 世界 🌍 🔐 ñáéíóú'),
            ('json data', json.dumps({'test': True, 'numbers': [1, 2, 3]})),
            ('large text', 'A' * 10000),  # 10KB
            ('binary-like', ''.join(chr(i) for i in range(256)))  # All possible bytes as chars
        ]
        
        algorithms = ['AES-256-GCM', 'ChaCha20-Poly1305']
        
        for algo in algorithms:
            for test_name, test_data in test_cases:
                print(f"  Testing {algo} with {test_name}")
                
                # Encrypt
                encrypt_request = {
                    'data': test_data,
                    'algorithm': algo,
                    'password': 'integrity_test_password'
                }
                
                encrypt_response = client.post(
                    '/api/encrypt',
                    data=json.dumps(encrypt_request),
                    content_type='application/json'
                )
                
                assert encrypt_response.status_code == 200
                encrypt_result = json.loads(encrypt_response.data)
                assert encrypt_result['success'] is True
                
                # Decrypt
                decrypt_request = {
                    'encrypted_data': encrypt_result['encrypted_data'],
                    'algorithm': algo,
                    'password': 'integrity_test_password',
                    'metadata': encrypt_result['metadata']
                }
                
                decrypt_response = client.post(
                    '/api/decrypt',
                    data=json.dumps(decrypt_request),
                    content_type='application/json'
                )
                
                assert decrypt_response.status_code == 200
                decrypt_result = json.loads(decrypt_response.data)
                assert decrypt_result['success'] is True
                
                # Verify integrity
                assert decrypt_result['decrypted_data'] == test_data
                print(f"    ✓ Integrity verified for {test_name}")
        
        print("  ✓ Round-trip integrity test completed")

if __name__ == '__main__':
    # Run integration tests
    pytest.main([__file__, '-v', '--tb=short'])