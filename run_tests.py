#!/usr/bin/env python3
"""
Test Runner for Universal Encryption Platform
Comprehensive test execution with different modes and reporting
"""

import sys
import os
import argparse
import subprocess
import time
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def run_command(cmd, description=""):
    """Run a command and return success status"""
    print(f"\n{'='*60}")
    print(f"Running: {description or cmd}")
    print(f"{'='*60}")
    
    start_time = time.time()
    try:
        result = subprocess.run(cmd, shell=True, check=True, cwd=project_root)
        duration = time.time() - start_time
        print(f"\n✓ Completed successfully in {duration:.2f}s")
        return True
    except subprocess.CalledProcessError as e:
        duration = time.time() - start_time
        print(f"\n✗ Failed with exit code {e.returncode} after {duration:.2f}s")
        return False

def check_dependencies():
    """Check if required testing dependencies are installed"""
    print("Checking testing dependencies...")
    
    required_packages = [
        'pytest', 'pytest-cov', 'pytest-flask', 'pytest-timeout',
        'psutil', 'requests'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"Missing packages: {', '.join(missing)}")
        print("Install with: pip install " + " ".join(missing))
        return False
    
    print("✓ All dependencies available")
    return True

def run_unit_tests():
    """Run unit tests"""
    cmd = "pytest tests/test_crypto.py tests/test_utils.py -m unit -v"
    return run_command(cmd, "Unit Tests")

def run_integration_tests():
    """Run integration tests"""
    cmd = "pytest tests/test_integration.py tests/test_api.py -m integration -v"
    return run_command(cmd, "Integration Tests")

def run_performance_tests():
    """Run performance benchmarks"""
    cmd = "pytest tests/test_performance.py -m performance -v -s"
    return run_command(cmd, "Performance Benchmarks")

def run_security_tests():
    """Run security tests"""
    cmd = "pytest tests/ -m security -v"
    return run_command(cmd, "Security Tests")

def run_all_tests():
    """Run all tests with coverage"""
    cmd = "pytest tests/ --cov=. --cov-report=html --cov-report=term-missing --cov-fail-under=80"
    return run_command(cmd, "All Tests with Coverage")

def run_quick_tests():
    """Run quick tests (exclude slow and performance tests)"""
    cmd = "pytest tests/ -m 'not slow and not performance' -x --tb=short"
    return run_command(cmd, "Quick Tests")

def run_smoke_tests():
    """Run basic smoke tests"""
    cmd = "pytest tests/test_api.py::TestAPIEndpoints::test_health_check -v"
    return run_command(cmd, "Smoke Tests")

def run_lint_checks():
    """Run code quality checks"""
    print("\n" + "="*60)
    print("Running Code Quality Checks")
    print("="*60)
    
    checks = [
        ("flake8 --max-line-length=100 --exclude=venv,env,__pycache__", "Flake8 Linting"),
        ("black --check --diff .", "Black Code Formatting Check"),
        ("isort --check-only --diff .", "Import Sorting Check")
    ]
    
    all_passed = True
    for cmd, description in checks:
        try:
            result = subprocess.run(cmd, shell=True, check=True, cwd=project_root, 
                                  capture_output=True, text=True)
            print(f"✓ {description}: PASSED")
        except subprocess.CalledProcessError as e:
            print(f"✗ {description}: FAILED")
            if e.stdout:
                print(f"Output: {e.stdout}")
            if e.stderr:
                print(f"Error: {e.stderr}")
            all_passed = False
        except FileNotFoundError:
            print(f"⚠ {description}: SKIPPED (tool not installed)")
    
    return all_passed

def generate_coverage_report():
    """Generate detailed coverage report"""
    print("\n" + "="*60)
    print("Generating Coverage Report")
    print("="*60)
    
    # Run tests with coverage
    cmd = "pytest tests/ --cov=. --cov-report=html:htmlcov --cov-report=json:coverage.json --cov-report=term"
    if run_command(cmd, "Coverage Analysis"):
        print("\nCoverage reports generated:")
        print(f"  HTML: {project_root}/htmlcov/index.html")
        print(f"  JSON: {project_root}/coverage.json")
        return True
    return False

def run_test_discovery():
    """Discover and list all available tests"""
    cmd = "pytest --collect-only -q"
    return run_command(cmd, "Test Discovery")

def install_test_dependencies():
    """Install testing dependencies"""
    dependencies = [
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0", 
        "pytest-flask>=1.2.0",
        "pytest-timeout>=2.1.0",
        "psutil>=5.9.0",
        "requests>=2.28.0",
        "black>=23.0.0",
        "flake8>=6.0.0",
        "isort>=5.12.0"
    ]
    
    cmd = f"pip install {' '.join(dependencies)}"
    return run_command(cmd, "Installing Test Dependencies")

def main():
    """Main test runner function"""
    parser = argparse.ArgumentParser(
        description="Universal Encryption Platform Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Test Types:
  unit        - Unit tests for individual components
  integration - Integration tests for full workflows  
  performance - Performance benchmarks and profiling
  security    - Security-focused tests
  all         - All tests with coverage reporting
  quick       - Fast tests only (exclude slow/performance)
  smoke       - Basic functionality tests
  lint        - Code quality checks
  coverage    - Generate detailed coverage report
  discover    - List all available tests

Examples:
  python run_tests.py unit
  python run_tests.py all
  python run_tests.py quick --verbose
  python run_tests.py performance --no-coverage
        """
    )
    
    parser.add_argument(
        'test_type',
        choices=['unit', 'integration', 'performance', 'security', 'all', 
                'quick', 'smoke', 'lint', 'coverage', 'discover', 'install-deps'],
        help='Type of tests to run'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--no-coverage',
        action='store_true',
        help='Skip coverage reporting'
    )
    
    parser.add_argument(
        '--fail-fast', '-x',
        action='store_true',
        help='Stop on first failure'
    )
    
    parser.add_argument(
        '--parallel', '-n',
        type=int,
        help='Run tests in parallel (requires pytest-xdist)'
    )
    
    args = parser.parse_args()
    
    print("Universal Encryption Platform - Test Runner")
    print(f"Running: {args.test_type} tests")
    print(f"Working directory: {project_root}")
    
    # Handle special commands first
    if args.test_type == 'install-deps':
        success = install_test_dependencies()
        sys.exit(0 if success else 1)
    
    if args.test_type == 'discover':
        success = run_test_discovery()
        sys.exit(0 if success else 1)
    
    # Check dependencies
    if not check_dependencies():
        print("\nSome dependencies are missing. Run:")
        print("python run_tests.py install-deps")
        sys.exit(1)
    
    # Run the requested test type
    start_time = time.time()
    success = False
    
    if args.test_type == 'unit':
        success = run_unit_tests()
    elif args.test_type == 'integration':
        success = run_integration_tests()
    elif args.test_type == 'performance':
        success = run_performance_tests()
    elif args.test_type == 'security':
        success = run_security_tests()
    elif args.test_type == 'all':
        success = run_all_tests()
    elif args.test_type == 'quick':
        success = run_quick_tests()
    elif args.test_type == 'smoke':
        success = run_smoke_tests()
    elif args.test_type == 'lint':
        success = run_lint_checks()
    elif args.test_type == 'coverage':
        success = generate_coverage_report()
    
    duration = time.time() - start_time
    
    print(f"\n{'='*60}")
    print(f"Test Summary")
    print(f"{'='*60}")
    print(f"Test type: {args.test_type}")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Result: {'PASSED' if success else 'FAILED'}")
    
    if success:
        print("\n✓ All tests completed successfully!")
        
        # Show next steps
        if args.test_type == 'all':
            print("\nNext steps:")
            print("- View coverage report: htmlcov/index.html")
            print("- Run performance tests: python run_tests.py performance")
            print("- Run security tests: python run_tests.py security")
        elif args.test_type == 'quick':
            print("\nFor comprehensive testing, run: python run_tests.py all")
    else:
        print("\n✗ Some tests failed. Check output above for details.")
        
        if args.test_type == 'all':
            print("\nTry running individual test types:")
            print("- python run_tests.py unit")
            print("- python run_tests.py integration")
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()