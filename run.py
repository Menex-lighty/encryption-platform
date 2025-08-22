#!/usr/bin/env python3
"""
Universal Encryption Platform - Application Runner
Simple script to start the Flask backend with different configurations
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def setup_logging(level='INFO'):
    """Configure logging"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('logs/app.log', mode='a')
        ]
    )

def check_dependencies():
    """Check if required dependencies are installed"""
    required_modules = [
        ('flask', 'Flask'), 
        ('cryptography', 'cryptography'), 
        ('flask_cors', 'Flask-CORS'), 
        ('werkzeug', 'Werkzeug'), 
        ('PIL', 'Pillow'),  # Fixed: PIL is the import name for Pillow
        ('argon2', 'argon2-cffi')
    ]
    
    missing = []
    for import_name, package_name in required_modules:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package_name)
    
    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        print("Install with: pip install -r requirements.txt")
        return False
    
    return True

def create_directories():
    """Ensure required directories exist"""
    directories = ['uploads', 'temp', 'logs', 'uploads/encrypted', 'uploads/metadata']
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)

def print_startup_banner(mode, host, port):
    """Print application startup banner"""
    print(f"""
🔐 Universal Encryption Platform
================================
Mode: {mode.upper()}
Server: http://{host}:{port}

Available Endpoints:
• Web Interface: http://{host}:{port}/
• Live Demo: http://{host}:{port}/demo
• API Docs: http://{host}:{port}/docs
• Health Check: http://{host}:{port}/api/health

API Examples:
• List Algorithms: http://{host}:{port}/api/algorithms
• Test Encryption: http://{host}:{port}/api/test/encryption

Press Ctrl+C to stop the server
""")

def run_development(host='localhost', port=5000, debug=True):
    """Run in development mode"""
    os.environ['FLASK_ENV'] = 'development'
    
    setup_logging('DEBUG' if debug else 'INFO')
    create_directories()
    
    try:
        from app import create_app
        app = create_app()
        
        print_startup_banner('development', host, port)
        
        app.run(
            host=host,
            port=port,
            debug=debug,
            use_reloader=True,
            threaded=True
        )
        
    except ImportError as e:
        print(f"❌ Failed to import app: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Failed to start development server: {e}")
        sys.exit(1)

def run_production(host='0.0.0.0', port=5000, workers=4):
    """Run in production mode with Gunicorn"""
    os.environ['FLASK_ENV'] = 'production'
    
    setup_logging('WARNING')
    create_directories()
    
    try:
        import gunicorn.app.base
        
        class StandaloneApplication(gunicorn.app.base.BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()
            
            def load_config(self):
                config = {key: value for key, value in self.options.items()
                         if key in self.cfg.settings and value is not None}
                for key, value in config.items():
                    self.cfg.set(key.lower(), value)
            
            def load(self):
                return self.application
        
        from app import create_app
        app = create_app()
        
        options = {
            'bind': f'{host}:{port}',
            'workers': workers,
            'worker_class': 'sync',
            'worker_connections': 1000,
            'timeout': 120,
            'keepalive': 2,
            'max_requests': 1000,
            'max_requests_jitter': 100,
            'preload_app': True,
            'access_log_format': '%h %l %u %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"'
        }
        
        print_startup_banner('production', host, port)
        print(f"Workers: {workers}")
        
        StandaloneApplication(app, options).run()
        
    except ImportError:
        print("❌ Gunicorn not available, falling back to development server")
        run_development(host, port, debug=False)
    except Exception as e:
        print(f"❌ Failed to start production server: {e}")
        sys.exit(1)

def run_testing():
    """Run test suite"""
    os.environ['FLASK_ENV'] = 'testing'
    
    setup_logging('DEBUG')
    
    try:
        import pytest
        
        # Run tests
        test_args = [
            'tests/',
            '-v',
            '--tb=short',
            '--color=yes'
        ]
        
        print("🧪 Running test suite...")
        exit_code = pytest.main(test_args)
        
        if exit_code == 0:
            print("✅ All tests passed!")
        else:
            print("❌ Some tests failed!")
        
        sys.exit(exit_code)
        
    except ImportError:
        print("❌ pytest not available")
        print("Install with: pip install pytest pytest-flask")
        sys.exit(1)

def run_docker():
    """Run with Docker Compose"""
    try:
        import subprocess
        
        print("🐳 Starting with Docker Compose...")
        
        # Check if docker-compose.yml exists
        if not Path('docker-compose.yml').exists():
            print("❌ docker-compose.yml not found")
            sys.exit(1)
        
        # Start services
        result = subprocess.run(['docker-compose', 'up', '-d'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Docker services started")
            print("\n📋 Service Status:")
            subprocess.run(['docker-compose', 'ps'])
            print("\n🌐 Access the application at: http://localhost:5000")
        else:
            print(f"❌ Docker Compose failed: {result.stderr}")
            sys.exit(1)
            
    except FileNotFoundError:
        print("❌ Docker Compose not found")
        print("Install Docker and Docker Compose first")
        sys.exit(1)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Universal Encryption Platform Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                          # Development mode
  python run.py --mode production        # Production mode
  python run.py --host 0.0.0.0 --port 8080  # Custom host/port
  python run.py --mode test              # Run tests
  python run.py --mode docker            # Docker Compose
        """
    )
    
    parser.add_argument('--mode', 
                       choices=['dev', 'development', 'prod', 'production', 'test', 'docker'],
                       default='development',
                       help='Run mode (default: development)')
    
    parser.add_argument('--host',
                       default='localhost',
                       help='Host to bind to (default: localhost)')
    
    parser.add_argument('--port', 
                       type=int, 
                       default=5000,
                       help='Port to bind to (default: 5000)')
    
    parser.add_argument('--workers',
                       type=int,
                       default=4,
                       help='Number of workers for production (default: 4)')
    
    parser.add_argument('--debug',
                       action='store_true',
                       help='Enable debug mode')
    
    parser.add_argument('--no-check',
                       action='store_true',
                       help='Skip dependency check')
    
    args = parser.parse_args()
    
    # Check dependencies unless skipped
    if not args.no_check and not check_dependencies():
        sys.exit(1)
    
    # Normalize mode
    mode = args.mode.lower()
    if mode in ['dev', 'development']:
        run_development(args.host, args.port, args.debug)
    elif mode in ['prod', 'production']:
        run_production(args.host, args.port, args.workers)
    elif mode == 'test':
        run_testing()
    elif mode == 'docker':
        run_docker()
    else:
        parser.error(f"Unknown mode: {args.mode}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        sys.exit(1)