# Testing Guide for Universal Encryption Platform

This document provides comprehensive information about testing the Universal Encryption Platform, including setup, execution, and interpretation of results.

## 🧪 Test Suite Overview

The test suite includes:

- **Unit Tests** - Individual component testing (crypto, utils)
- **Integration Tests** - End-to-end workflow testing
- **Performance Tests** - Benchmarking and profiling
- **Security Tests** - Security validation and vulnerability testing
- **API Tests** - REST API endpoint testing

## 📁 Test Structure

```
tests/
├── conftest.py              # Pytest configuration and fixtures
├── test_crypto.py          # Cryptographic algorithm tests
├── test_utils.py           # Utility function tests
├── test_api.py             # API endpoint tests
├── test_integration.py     # End-to-end integration tests
├── test_performance.py     # Performance benchmarks
└── performance_report.json # Generated performance results
```

## 🚀 Quick Start

### 1. Install Test Dependencies

```bash
# Option 1: Use the test runner
python run_tests.py install-deps

# Option 2: Manual installation
pip install pytest pytest-cov pytest-flask pytest-timeout psutil
```

### 2. Run Tests

```bash
# Quick test run (recommended for development)
python run_tests.py quick

# Full test suite with coverage
python run_tests.py all

# Specific test types
python run_tests.py unit
python run_tests.py integration
python run_tests.py performance
```

## 📊 Test Types and Commands

### Unit Tests
Test individual components in isolation.

```bash
# Run all unit tests
python run_tests.py unit

# Run specific test file
pytest tests/test_crypto.py -v

# Run specific test class
pytest tests/test_crypto.py::TestSymmetricEncryption -v

# Run specific test method
pytest tests/test_crypto.py::TestSymmetricEncryption::test_aes_encryption_performance -v
```

### Integration Tests
Test complete workflows and component interactions.

```bash
# Run all integration tests
python run_tests.py integration

# Run with verbose output
pytest tests/test_integration.py -v -s

# Run specific integration test
pytest tests/test_integration.py::TestFullWorkflowIntegration::test_text_encryption_full_workflow -v
```

### Performance Tests
Benchmark encryption operations and system performance.

```bash
# Run performance benchmarks
python run_tests.py performance

# Run with detailed output
pytest tests/test_performance.py -v -s

# Run specific benchmark
pytest tests/test_performance.py::TestCryptographicPerformance::test_aes_performance -v
```

### Security Tests
Validate security properties and configurations.

```bash
# Run security tests
python run_tests.py security

# Run with security markers
pytest tests/ -m security -v
```

### Coverage Analysis
Generate test coverage reports.

```bash
# Generate coverage report
python run_tests.py coverage

# View HTML coverage report
open htmlcov/index.html  # macOS/Linux
start htmlcov/index.html  # Windows
```

## 🎯 Test Markers

Tests are organized using pytest markers:

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests  
pytest -m integration

# Run only performance tests
pytest -m performance

# Exclude slow tests
pytest -m "not slow"

# Run security tests
pytest -m security
```

## 📈 Performance Benchmarking

### Running Benchmarks

```bash
# Full performance suite
python run_tests.py performance

# Quick performance check
pytest tests/test_performance.py::TestCryptographicPerformance::test_aes_performance -v
```

### Understanding Results

Performance tests measure:

- **Encryption/Decryption Speed** - Operations per second
- **Throughput** - MB/s for different data sizes
- **Memory Usage** - RAM consumption patterns
- **Concurrency** - Multi-thread performance
- **API Response Times** - REST endpoint latency

Example output:
```
AES Performance - Small: 0.045s, Medium: 0.123s
  ✓ AES-256-GCM throughput (1KB): 22.5 MB/s
  ✓ Memory usage - Peak increase: 5.2MB
```

### Performance Thresholds

The test suite enforces these performance requirements:

- **AES-256-GCM**: >1 MB/s throughput for small data
- **API Response**: <500ms average, <1s 95th percentile
- **Memory**: <100MB increase for 1MB encryption
- **Concurrency**: >10 operations/second

## 🔍 Test Configuration

### pytest.ini Configuration

Key settings in `pytest.ini`:

```ini
[tool:pytest]
testpaths = tests
addopts = -v --tb=short --cov=. --cov-report=html
markers = 
    slow: marks tests as slow
    performance: marks tests as performance benchmarks
    security: marks tests as security tests
timeout = 300
```

### Environment Variables

Configure test behavior:

```bash
# Set Flask environment
export FLASK_ENV=testing

# Configure test uploads
export UPLOAD_FOLDER=/tmp/test_uploads

# Skip slow tests
export SKIP_SLOW_TESTS=1
```

## 🛠️ Test Development

### Writing New Tests

1. **Choose the right test file** based on functionality
2. **Use appropriate fixtures** from `conftest.py`
3. **Add proper markers** for test categorization
4. **Include performance assertions** where relevant

Example test structure:

```python
import pytest

class TestNewFeature:
    """Test new encryption feature"""
    
    def test_basic_functionality(self, test_config):
        """Test basic functionality"""
        # Arrange
        data = test_config['test_data']['small']
        
        # Act
        result = encrypt_function(data)
        
        # Assert
        assert result is not None
        assert 'encrypted_data' in result
    
    @pytest.mark.performance
    def test_performance(self, crypto_instances):
        """Test performance requirements"""
        # Performance test implementation
        pass
    
    @pytest.mark.slow
    def test_large_data(self):
        """Test with large data sets"""
        # Slow test implementation
        pass
```

### Test Fixtures

Available fixtures in `conftest.py`:

- `test_config` - Test configuration and data
- `test_app` - Flask application instance
- `test_client` - Flask test client
- `crypto_instances` - Crypto algorithm instances
- `test_keys` - Pre-generated test keys
- `temp_directory` - Temporary directory for files
- `memory_monitor` - Memory usage monitoring

### Best Practices

1. **Use descriptive test names** that explain what is being tested
2. **Test both success and failure cases**
3. **Include edge cases** (empty data, large data, invalid inputs)
4. **Add performance assertions** for critical operations
5. **Mock external dependencies** when appropriate
6. **Clean up resources** in teardown methods

## 🚨 Troubleshooting

### Common Issues

**Tests fail with import errors:**
```bash
# Solution: Install dependencies
python run_tests.py install-deps
```

**Performance tests timeout:**
```bash
# Solution: Run with higher timeout
pytest tests/test_performance.py --timeout=600
```

**Coverage reports not generated:**
```bash
# Solution: Install coverage dependencies
pip install pytest-cov coverage
```

**File upload tests fail:**
```bash
# Solution: Check upload directory permissions
mkdir -p /tmp/test_uploads
chmod 755 /tmp/test_uploads
```

### Debug Mode

Run tests in debug mode:

```bash
# Verbose output with no capture
pytest tests/ -v -s --tb=long

# Debug specific test
pytest tests/test_crypto.py::TestAES::test_encryption -v -s --pdb
```

### Test Data Cleanup

Clean up test artifacts:

```bash
# Remove coverage files
rm -rf htmlcov/ .coverage coverage.json

# Remove test caches
rm -rf .pytest_cache/ __pycache__/

# Remove temporary files
rm -rf /tmp/test_*
```

## 📊 Continuous Integration

### GitHub Actions

The project includes automated testing via GitHub Actions:

- **Code Quality** - Linting, formatting, type checking
- **Multi-Platform Testing** - Ubuntu, Windows, macOS
- **Multiple Python Versions** - 3.8, 3.9, 3.10, 3.11
- **Performance Monitoring** - Benchmark tracking
- **Security Scanning** - Vulnerability detection

### CI Configuration

Key CI jobs:

1. **Lint** - Code quality checks
2. **Test** - Cross-platform test execution
3. **Performance** - Benchmark monitoring
4. **Security** - Security validation
5. **Docker** - Container build testing

### Coverage Reporting

Test coverage is automatically:

- Calculated during CI runs
- Uploaded to Codecov
- Displayed in pull requests
- Enforced with minimum thresholds (80%)

## 📈 Test Metrics

### Coverage Targets

- **Overall Coverage**: >80%
- **Critical Modules**: >90%
  - crypto/* modules
  - utils/* modules  
  - Main app.py

### Performance Baselines

Established performance baselines:

- **AES-256-GCM**: 20+ MB/s (1KB data)
- **ChaCha20**: 25+ MB/s (1KB data)  
- **RSA-2048**: <2s key generation
- **API Response**: <500ms average

### Quality Gates

Automated quality gates:

- All tests must pass
- Coverage must be >80%
- Performance within 20% of baseline
- No security vulnerabilities
- Code formatting compliance

## 🔧 Advanced Testing

### Load Testing

Test API under load:

```bash
# Install load testing tools
pip install locust

# Run load test
locust -f tests/load_test.py --host=http://localhost:5000
```

### Memory Profiling

Profile memory usage:

```bash
# Install memory profiler
pip install memory-profiler

# Run with memory profiling
python -m memory_profiler tests/test_performance.py
```

### Security Testing

Additional security testing:

```bash
# Install security tools
pip install bandit safety

# Run security scan
bandit -r . -x tests/
safety check
```

## 📚 Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [Flask Testing](https://flask.palletsprojects.com/en/2.0.x/testing/)
- [Cryptography Testing Best Practices](https://cryptography.io/en/latest/development/test-vectors/)

## 🤝 Contributing

When contributing tests:

1. **Add tests for new features**
2. **Maintain or improve coverage**
3. **Include performance tests for crypto operations**
4. **Add integration tests for new endpoints**
5. **Update this documentation** for new test types

For questions about testing, please open an issue or discussion on GitHub.