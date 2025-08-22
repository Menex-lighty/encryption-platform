"""
Performance Benchmark Suite for Universal Encryption Platform
Comprehensive performance testing and profiling
"""

import pytest
import time
import os
import sys
import threading
import multiprocessing
import psutil
import statistics
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import gc
import tracemalloc

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from crypto.symmetric import AESCrypto, ChaCha20Crypto
from crypto.asymmetric import RSACrypto
from crypto.classical import CaesarCipher
from crypto.utils import generate_salt, derive_key
import app

class PerformanceBenchmark:
    """Base class for performance benchmarks"""
    
    def __init__(self):
        self.results = {}
        self.process = psutil.Process()
    
    def measure_time(self, func, *args, **kwargs):
        """Measure execution time of a function"""
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        return result, end_time - start_time
    
    def measure_memory(self, func, *args, **kwargs):
        """Measure memory usage of a function"""
        tracemalloc.start()
        initial_memory = self.process.memory_info().rss
        
        result = func(*args, **kwargs)
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        final_memory = self.process.memory_info().rss
        
        return result, {
            'initial_rss': initial_memory,
            'final_rss': final_memory,
            'peak_traced': peak,
            'current_traced': current
        }
    
    def run_multiple_times(self, func, iterations=10, *args, **kwargs):
        """Run function multiple times and collect statistics"""
        times = []
        
        for _ in range(iterations):
            _, exec_time = self.measure_time(func, *args, **kwargs)
            times.append(exec_time)
        
        return {
            'min': min(times),
            'max': max(times),
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0,
            'iterations': iterations,
            'times': times
        }

class TestCryptographicPerformance:
    """Test performance of cryptographic operations"""
    
    def setup_method(self):
        """Set up test data"""
        self.benchmark = PerformanceBenchmark()
        self.results = {}
        self.aes = AESCrypto()
        self.chacha20 = ChaCha20Crypto()
        self.rsa = RSACrypto()
        self.caesar = CaesarCipher()
        
        # Test data of various sizes
        self.data_sizes = {
            'tiny': b'Hello',  # 5 bytes
            'small': b'A' * 1024,  # 1KB
            'medium': b'A' * (100 * 1024),  # 100KB
            'large': b'A' * (1024 * 1024),  # 1MB
            'xlarge': b'A' * (10 * 1024 * 1024)  # 10MB
        }
        
        self.password = "benchmark_password_123"
        self.salt = generate_salt()
        self.aes_key = derive_key(self.password, self.salt, length=32)
        self.chacha_key = os.urandom(32)
    
    def test_aes_encryption_performance(self):
        """Benchmark AES encryption across different data sizes"""
        results = {}
        
        for size_name, data in self.data_sizes.items():
            if size_name == 'xlarge':  # Skip very large for faster testing
                continue
                
            print(f"\nTesting AES-256-GCM with {size_name} data ({len(data)} bytes)")
            
            # Encryption performance
            encrypt_stats = self.benchmark.run_multiple_times(
                self.aes.encrypt_gcm,
                iterations=10 if size_name != 'large' else 3,
                plaintext=data,
                key=self.aes_key
            )
            
            # Calculate throughput
            throughput_mbps = (len(data) / (1024 * 1024)) / encrypt_stats['mean']
            
            results[size_name] = {
                'size_bytes': len(data),
                'encryption_stats': encrypt_stats,
                'throughput_mbps': throughput_mbps
            }
            
            print(f"  Encryption: {encrypt_stats['mean']:.4f}s ± {encrypt_stats['stdev']:.4f}s")
            print(f"  Throughput: {throughput_mbps:.2f} MB/s")
        
        self.results['aes_performance'] = results
        
        # Performance assertions
        assert results['small']['throughput_mbps'] > 1.0  # At least 1 MB/s for small data
        if 'medium' in results:
            assert results['medium']['encryption_stats']['mean'] < 1.0  # Under 1 second for 100KB
    
    def test_chacha20_encryption_performance(self):
        """Benchmark ChaCha20 encryption performance"""
        results = {}
        
        for size_name, data in self.data_sizes.items():
            if size_name in ['large', 'xlarge']:  # Skip large data for faster testing
                continue
                
            print(f"\nTesting ChaCha20-Poly1305 with {size_name} data ({len(data)} bytes)")
            
            encrypt_stats = self.benchmark.run_multiple_times(
                self.chacha20.encrypt,
                iterations=10,
                plaintext=data,
                key=self.chacha_key
            )
            
            throughput_mbps = (len(data) / (1024 * 1024)) / encrypt_stats['mean']
            
            results[size_name] = {
                'size_bytes': len(data),
                'encryption_stats': encrypt_stats,
                'throughput_mbps': throughput_mbps
            }
            
            print(f"  Encryption: {encrypt_stats['mean']:.4f}s ± {encrypt_stats['stdev']:.4f}s")
            print(f"  Throughput: {throughput_mbps:.2f} MB/s")
        
        self.results['chacha20_performance'] = results
    
    def test_rsa_performance(self):
        """Benchmark RSA operations"""
        print(f"\nTesting RSA performance")
        
        # Key generation
        keygen_stats = self.benchmark.run_multiple_times(
            self.rsa.generate_keypair,
            iterations=3,  # RSA key generation is slow
            key_size=2048
        )
        
        print(f"  Key generation (2048-bit): {keygen_stats['mean']:.3f}s ± {keygen_stats['stdev']:.3f}s")
        
        # Generate a key pair for encryption/decryption tests
        private_key, public_key = self.rsa.generate_keypair(2048)
        
        # Encryption/decryption with small data
        small_data = b"RSA test message"
        
        encrypt_stats = self.benchmark.run_multiple_times(
            self.rsa.encrypt,
            iterations=10,
            plaintext=small_data,
            public_key=public_key
        )
        
        # Test decryption
        ciphertext = self.rsa.encrypt(small_data, public_key)
        decrypt_stats = self.benchmark.run_multiple_times(
            self.rsa.decrypt,
            iterations=10,
            ciphertext=ciphertext,
            private_key=private_key
        )
        
        print(f"  Encryption: {encrypt_stats['mean']:.4f}s ± {encrypt_stats['stdev']:.4f}s")
        print(f"  Decryption: {decrypt_stats['mean']:.4f}s ± {decrypt_stats['stdev']:.4f}s")
        
        self.results['rsa_performance'] = {
            'key_generation': keygen_stats,
            'encryption': encrypt_stats,
            'decryption': decrypt_stats
        }
    
    def test_classical_cipher_performance(self):
        """Benchmark classical cipher performance"""
        text = "The quick brown fox jumps over the lazy dog" * 100  # ~4KB
        
        print(f"\nTesting Caesar cipher with {len(text)} characters")
        
        encrypt_stats = self.benchmark.run_multiple_times(
            self.caesar.encrypt,
            iterations=100,
            plaintext=text,
            shift=13
        )
        
        encrypted = self.caesar.encrypt(text, 13)
        decrypt_stats = self.benchmark.run_multiple_times(
            self.caesar.decrypt,
            iterations=100,
            ciphertext=encrypted,
            shift=13
        )
        
        print(f"  Encryption: {encrypt_stats['mean']:.6f}s ± {encrypt_stats['stdev']:.6f}s")
        print(f"  Decryption: {decrypt_stats['mean']:.6f}s ± {decrypt_stats['stdev']:.6f}s")
        
        # Classical ciphers should be reasonably fast (account for logging overhead)
        assert encrypt_stats['mean'] < 0.01   # Under 10ms
        assert decrypt_stats['mean'] < 0.01   # Under 10ms
        
        self.results['caesar_performance'] = {
            'encryption': encrypt_stats,
            'decryption': decrypt_stats
        }
    
    def test_key_derivation_performance(self):
        """Benchmark key derivation functions"""
        password = "benchmark_password"
        salt = generate_salt()
        
        print(f"\nTesting key derivation performance")
        
        # PBKDF2 performance - create wrapper to avoid parameter conflict
        def derive_key_wrapper():
            return derive_key(password, salt, algorithm='PBKDF2', iterations=100000)
        
        pbkdf2_stats = self.benchmark.run_multiple_times(
            derive_key_wrapper,
            iterations=5  # benchmark iterations
        )
        
        print(f"  PBKDF2 (100k iterations): {pbkdf2_stats['mean']:.3f}s ± {pbkdf2_stats['stdev']:.3f}s")
        
        # Test with different iteration counts
        iteration_counts = [10000, 50000, 100000]
        iteration_results = {}
        
        for kdf_iterations in iteration_counts:
            def derive_key_with_iterations():
                return derive_key(password, salt, algorithm='PBKDF2', iterations=kdf_iterations)
            
            stats = self.benchmark.run_multiple_times(
                derive_key_with_iterations,
                iterations=3
            )
            iteration_results[kdf_iterations] = stats
            
        self.results['key_derivation'] = {
            'pbkdf2_100k': pbkdf2_stats,
            'iteration_scaling': iteration_results
        }

class TestMemoryUsage:
    """Test memory usage patterns"""
    
    def setup_method(self):
        """Set up memory testing"""
        self.benchmark = PerformanceBenchmark()
        self.aes = AESCrypto()
        self.data_1mb = b'A' * (1024 * 1024)
        self.password = "memory_test_password"
        self.salt = generate_salt()
        self.key = derive_key(self.password, self.salt, length=32)
    
    def test_memory_usage_single_encryption(self):
        """Test memory usage for single encryption"""
        print(f"\nTesting memory usage for single 1MB encryption")
        
        # Measure memory usage
        result, memory_info = self.benchmark.measure_memory(
            self.aes.encrypt_gcm,
            self.data_1mb,
            self.key
        )
        
        memory_increase = memory_info['final_rss'] - memory_info['initial_rss']
        peak_traced = memory_info['peak_traced']
        
        print(f"  RSS memory increase: {memory_increase / 1024 / 1024:.2f} MB")
        print(f"  Peak traced memory: {peak_traced / 1024 / 1024:.2f} MB")
        
        # Memory usage should be reasonable
        assert memory_increase < 100 * 1024 * 1024  # Less than 100MB increase
        
        # Clean up
        del result
        gc.collect()
    
    def test_memory_usage_multiple_encryptions(self):
        """Test memory usage for multiple encryptions"""
        print(f"\nTesting memory usage for 10 sequential 1MB encryptions")
        
        initial_memory = self.benchmark.process.memory_info().rss
        results = []
        
        for i in range(10):
            result = self.aes.encrypt_gcm(self.data_1mb, self.key)
            results.append(result)
            
            if i % 5 == 4:  # Check memory every 5 iterations
                current_memory = self.benchmark.process.memory_info().rss
                memory_increase = current_memory - initial_memory
                print(f"  After {i+1} encryptions: {memory_increase / 1024 / 1024:.2f} MB")
        
        final_memory = self.benchmark.process.memory_info().rss
        total_increase = final_memory - initial_memory
        
        print(f"  Total memory increase: {total_increase / 1024 / 1024:.2f} MB")
        
        # Clean up and measure memory recovery
        del results
        gc.collect()
        
        after_cleanup_memory = self.benchmark.process.memory_info().rss
        cleanup_recovery = final_memory - after_cleanup_memory
        
        print(f"  Memory recovered after cleanup: {cleanup_recovery / 1024 / 1024:.2f} MB")
        
        # Should recover most memory
        assert cleanup_recovery > total_increase * 0.5  # At least 50% recovery
    
    def test_memory_leaks(self):
        """Test for memory leaks in encryption operations"""
        print(f"\nTesting for memory leaks over 100 operations")
        
        initial_memory = self.benchmark.process.memory_info().rss
        memory_samples = [initial_memory]
        
        small_data = b'A' * 1024  # 1KB
        
        for i in range(100):
            # Encrypt and immediately decrypt
            result = self.aes.encrypt_gcm(small_data, self.key)
            decrypted = self.aes.decrypt_gcm(
                result['ciphertext'],
                self.key,
                result['iv'],
                result['tag']
            )
            
            # Sample memory every 20 operations
            if i % 20 == 19:
                memory_samples.append(self.benchmark.process.memory_info().rss)
        
        # Calculate memory trend
        memory_increases = [
            (memory_samples[i] - memory_samples[i-1]) / 1024 / 1024
            for i in range(1, len(memory_samples))
        ]
        
        print(f"  Memory increases between samples: {memory_increases}")
        print(f"  Average increase per 20 operations: {statistics.mean(memory_increases):.2f} MB")
        
        # Should not have significant memory increase trend
        assert statistics.mean(memory_increases) < 5.0  # Less than 5MB average increase

def process_encrypt_batch(args):
    """Encrypt a batch of data in a separate process (standalone function for pickling)"""
    batch_size, password, salt, test_data = args
    
    # Re-initialize crypto objects in each process
    aes = AESCrypto()
    key = derive_key(password, salt, length=32)
    
    total_bytes = 0
    for i in range(batch_size):
        data = f"Process data {i} ".encode() + test_data
        result = aes.encrypt_gcm(data, key)
        total_bytes += len(data)
    
    return total_bytes

class TestConcurrencyPerformance:
    """Test concurrent operation performance"""
    
    def setup_method(self):
        """Set up concurrency testing"""
        self.benchmark = PerformanceBenchmark()
        self.aes = AESCrypto()
        self.test_data = b'A' * 10240  # 10KB
        self.password = "concurrency_test_password"
        self.salt = generate_salt()
        self.key = derive_key(self.password, self.salt, length=32)
    
    def encrypt_operation(self, data_id):
        """Single encryption operation for concurrency testing"""
        data = f"Test data {data_id} ".encode() + self.test_data
        result = self.aes.encrypt_gcm(data, self.key)
        
        # Verify by decrypting
        decrypted = self.aes.decrypt_gcm(
            result['ciphertext'],
            self.key,
            result['iv'],
            result['tag']
        )
        
        assert decrypted == data
        return len(data)
    
    def test_thread_concurrency(self):
        """Test performance with multiple threads"""
        thread_counts = [1, 2, 4, 8]
        operations_per_thread = 10
        
        print(f"\nTesting thread concurrency performance")
        
        for thread_count in thread_counts:
            start_time = time.perf_counter()
            
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = [
                    executor.submit(self.encrypt_operation, i)
                    for i in range(thread_count * operations_per_thread)
                ]
                
                # Wait for all operations to complete
                total_bytes = sum(future.result() for future in futures)
            
            end_time = time.perf_counter()
            execution_time = end_time - start_time
            
            operations_per_second = (thread_count * operations_per_thread) / execution_time
            throughput_mbps = (total_bytes / (1024 * 1024)) / execution_time
            
            print(f"  {thread_count} threads: {operations_per_second:.1f} ops/sec, {throughput_mbps:.2f} MB/s")
            
            # Should handle concurrent operations efficiently
            assert operations_per_second > 10  # At least 10 operations per second
    
    def test_process_concurrency(self):
        """Test performance with multiple processes"""
        if multiprocessing.cpu_count() < 2:
            pytest.skip("Multiprocessing test requires at least 2 CPU cores")
        
        process_counts = [1, 2, min(4, multiprocessing.cpu_count())]
        operations_per_process = 5  # Fewer operations for process overhead
        
        print(f"\nTesting process concurrency performance")
        
        for process_count in process_counts:
            start_time = time.perf_counter()
            
            # Prepare arguments for the standalone function
            args = (operations_per_process, self.password, self.salt, self.test_data)
            
            with ProcessPoolExecutor(max_workers=process_count) as executor:
                futures = [
                    executor.submit(process_encrypt_batch, args)
                    for _ in range(process_count)
                ]
                
                total_bytes = sum(future.result() for future in futures)
            
            end_time = time.perf_counter()
            execution_time = end_time - start_time
            
            total_operations = process_count * operations_per_process
            operations_per_second = total_operations / execution_time
            throughput_mbps = (total_bytes / (1024 * 1024)) / execution_time
            
            print(f"  {process_count} processes: {operations_per_second:.1f} ops/sec, {throughput_mbps:.2f} MB/s")

class TestAPIPerformance:
    """Test API endpoint performance"""
    
    def setup_method(self):
        """Set up API testing"""
        self.benchmark = PerformanceBenchmark()
        os.environ['FLASK_ENV'] = 'testing'
        self.app = app.create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        
        self.test_request = {
            'data': 'API performance test data',
            'algorithm': 'AES-256-GCM',
            'password': 'api_test_password'
        }
    
    def make_encrypt_request(self):
        """Make a single encryption API request"""
        response = self.client.post(
            '/api/encrypt',
            data=json.dumps(self.test_request),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        result = json.loads(response.data)
        assert result['success'] is True
        
        return result
    
    def test_api_response_time(self):
        """Test API response times"""
        print(f"\nTesting API response times")
        
        # Warm up
        for _ in range(5):
            self.make_encrypt_request()
        
        # Measure response times
        response_times = []
        for _ in range(20):
            _, response_time = self.benchmark.measure_time(self.make_encrypt_request)
            response_times.append(response_time)
        
        avg_response_time = statistics.mean(response_times)
        p95_response_time = sorted(response_times)[int(0.95 * len(response_times))]
        
        print(f"  Average response time: {avg_response_time:.3f}s")
        print(f"  95th percentile: {p95_response_time:.3f}s")
        
        # API should respond quickly
        assert avg_response_time < 0.5  # Under 500ms average
        assert p95_response_time < 1.0  # Under 1s for 95% of requests
    
    def test_api_concurrent_requests(self):
        """Test API performance under concurrent load"""
        print(f"\nTesting API concurrent request handling")
        
        def make_request_batch(batch_size):
            """Make a batch of API requests"""
            times = []
            for _ in range(batch_size):
                _, request_time = self.benchmark.measure_time(self.make_encrypt_request)
                times.append(request_time)
            return times
        
        # Test with different concurrent loads
        concurrent_levels = [1, 5, 10]
        
        for concurrent_count in concurrent_levels:
            requests_per_thread = 5
            
            start_time = time.perf_counter()
            
            with ThreadPoolExecutor(max_workers=concurrent_count) as executor:
                futures = [
                    executor.submit(make_request_batch, requests_per_thread)
                    for _ in range(concurrent_count)
                ]
                
                all_times = []
                for future in futures:
                    all_times.extend(future.result())
            
            end_time = time.perf_counter()
            total_time = end_time - start_time
            
            total_requests = concurrent_count * requests_per_thread
            requests_per_second = total_requests / total_time
            avg_response_time = statistics.mean(all_times)
            
            print(f"  {concurrent_count} concurrent: {requests_per_second:.1f} req/sec, {avg_response_time:.3f}s avg")
            
            # Should handle reasonable concurrent load
            assert requests_per_second > 2  # At least 2 requests per second

class BenchmarkReporter:
    """Generate performance benchmark reports"""
    
    def __init__(self):
        self.all_results = {}
    
    def collect_results(self, test_instance):
        """Collect results from a test instance"""
        if hasattr(test_instance, 'results'):
            self.all_results.update(test_instance.results)
    
    def generate_report(self, output_file=None):
        """Generate a comprehensive performance report"""
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'system_info': {
                'cpu_count': multiprocessing.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'platform': sys.platform,
                'python_version': sys.version
            },
            'benchmark_results': self.all_results
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
        
        return report

# Pytest fixtures and configuration
@pytest.fixture(scope="session")
def benchmark_reporter():
    """Benchmark reporter fixture"""
    return BenchmarkReporter()

@pytest.mark.performance
class TestPerformanceSuite:
    """Main performance test suite"""
    
    def test_run_all_benchmarks(self, benchmark_reporter):
        """Run all performance benchmarks and generate report"""
        print("\n" + "="*60)
        print("UNIVERSAL ENCRYPTION PLATFORM - PERFORMANCE BENCHMARK")
        print("="*60)
        
        # Run cryptographic benchmarks
        crypto_bench = TestCryptographicPerformance()
        crypto_bench.setup_method()
        
        crypto_bench.test_aes_encryption_performance()
        crypto_bench.test_chacha20_encryption_performance()
        crypto_bench.test_rsa_performance()
        crypto_bench.test_classical_cipher_performance()
        crypto_bench.test_key_derivation_performance()
        
        benchmark_reporter.collect_results(crypto_bench)
        
        # Run memory benchmarks
        memory_bench = TestMemoryUsage()
        memory_bench.setup_method()
        
        memory_bench.test_memory_usage_single_encryption()
        memory_bench.test_memory_usage_multiple_encryptions()
        memory_bench.test_memory_leaks()
        
        benchmark_reporter.collect_results(memory_bench)
        
        # Run concurrency benchmarks
        concurrency_bench = TestConcurrencyPerformance()
        concurrency_bench.setup_method()
        
        concurrency_bench.test_thread_concurrency()
        if multiprocessing.cpu_count() >= 2:
            concurrency_bench.test_process_concurrency()
        
        benchmark_reporter.collect_results(concurrency_bench)
        
        # Run API benchmarks
        try:
            api_bench = TestAPIPerformance()
            api_bench.setup_method()
            
            api_bench.test_api_response_time()
            api_bench.test_api_concurrent_requests()
            
            benchmark_reporter.collect_results(api_bench)
        except Exception as e:
            print(f"API benchmarks skipped: {e}")
        
        # Generate report
        report_file = Path(__file__).parent / 'performance_report.json'
        report = benchmark_reporter.generate_report(report_file)
        
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY")
        print("="*60)
        print(f"Report generated: {report_file}")
        print(f"System: {report['system_info']['cpu_count']} CPUs, "
              f"{report['system_info']['memory_total'] // (1024**3)}GB RAM")
        
        # Print key performance metrics
        if 'aes_performance' in benchmark_reporter.all_results:
            aes_results = benchmark_reporter.all_results['aes_performance']
            if 'small' in aes_results:
                throughput = aes_results['small']['throughput_mbps']
                print(f"AES-256-GCM throughput (1KB): {throughput:.2f} MB/s")

if __name__ == '__main__':
    # Run performance tests
    pytest.main([__file__, '-v', '--tb=short', '-m', 'performance'])