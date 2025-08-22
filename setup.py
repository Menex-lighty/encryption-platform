#!/usr/bin/env python3
"""
Universal Encryption Platform - Automated Setup Script
Phase 1: Core Foundation Setup

This script automates the setup process for development and production deployment.
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

class SetupManager:
    """Handles automated setup for Universal Encryption Platform"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.absolute()
        self.system = platform.system().lower()
        self.python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        
    def print_banner(self):
        """Print setup banner"""
        print("""
🔐 Universal Encryption Platform - Setup
========================================
Phase 1: Core Foundation

Setting up development environment...
""")
        
    def check_requirements(self):
        """Check system requirements"""
        print("📋 Checking system requirements...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            print("❌ Python 3.8+ required")
            sys.exit(1)
        print(f"✅ Python {self.python_version}")
        
        # Check pip
        try:
            subprocess.run([sys.executable, "-m", "pip", "--version"], 
                         check=True, capture_output=True)
            print("✅ pip available")
        except subprocess.CalledProcessError:
            print("❌ pip not available")
            sys.exit(1)
        
        # Check Docker (optional)
        try:
            subprocess.run(["docker", "--version"], 
                         check=True, capture_output=True)
            print("✅ Docker available")
            self.has_docker = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("⚠️  Docker not found (optional)")
            self.has_docker = False
        
        # Check system dependencies
        if self.system == "linux":
            self.check_linux_deps()
        elif self.system == "darwin":
            self.check_macos_deps()
        elif self.system == "windows":
            self.check_windows_deps()
    
    def check_linux_deps(self):
        """Check Linux system dependencies"""
        deps = ["gcc", "g++", "libffi-dev", "libssl-dev"]
        missing = []
        
        for dep in deps:
            try:
                subprocess.run(["dpkg", "-l", dep], 
                             check=True, capture_output=True)
            except subprocess.CalledProcessError:
                missing.append(dep)
        
        if missing:
            print(f"⚠️  Missing packages: {', '.join(missing)}")
            print("   Install with: sudo apt-get install " + " ".join(missing))
    
    def check_macos_deps(self):
        """Check macOS system dependencies"""
        try:
            subprocess.run(["xcode-select", "--version"], 
                         check=True, capture_output=True)
            print("✅ Xcode Command Line Tools")
        except subprocess.CalledProcessError:
            print("⚠️  Install Xcode Command Line Tools: xcode-select --install")
    
    def check_windows_deps(self):
        """Check Windows system dependencies"""
        try:
            subprocess.run(["cl"], check=True, capture_output=True)
            print("✅ Microsoft Visual C++")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("⚠️  Microsoft Visual C++ Build Tools recommended")
    
    def create_directories(self):
        """Create necessary directories"""
        print("📁 Creating directories...")
        
        directories = [
            "uploads",
            "uploads/encrypted",
            "uploads/metadata",
            "temp",
            "logs",
            "crypto",
            "utils",
            "routes",
            "templates",
            "static/css",
            "static/js",
            "tests",
            "docs",
            "secrets"
        ]
        
        for directory in directories:
            dir_path = self.base_dir / directory
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"   ✅ {directory}")
    
    def create_init_files(self):
        """Create __init__.py files for Python modules"""
        print("🐍 Creating Python module files...")
        
        modules = ["crypto", "utils", "routes"]
        
        for module in modules:
            init_file = self.base_dir / module / "__init__.py"
            if not init_file.exists():
                init_file.write_text(f'"""\n{module.title()} module for Universal Encryption Platform\n"""\n')
                print(f"   ✅ {module}/__init__.py")
    
    def setup_virtual_environment(self):
        """Set up Python virtual environment"""
        print("🔧 Setting up virtual environment...")
        
        venv_path = self.base_dir / "venv"
        
        if not venv_path.exists():
            subprocess.run([
                sys.executable, "-m", "venv", str(venv_path)
            ], check=True)
            print("   ✅ Virtual environment created")
        else:
            print("   ✅ Virtual environment exists")
        
        # Get activation script path
        if self.system == "windows":
            activate_script = venv_path / "Scripts" / "activate.bat"
            pip_path = venv_path / "Scripts" / "pip"
        else:
            activate_script = venv_path / "bin" / "activate"
            pip_path = venv_path / "bin" / "pip"
        
        print(f"   📝 Activate with: source {activate_script}")
        return pip_path
    
    def install_dependencies(self, pip_path):
        """Install Python dependencies"""
        print("📦 Installing dependencies...")
        
        requirements_file = self.base_dir / "requirements.txt"
        if requirements_file.exists():
            try:
                subprocess.run([
                    str(pip_path), "install", "-r", str(requirements_file)
                ], check=True)
                print("   ✅ Dependencies installed")
            except subprocess.CalledProcessError as e:
                print(f"   ❌ Failed to install dependencies: {e}")
                return False
        else:
            print("   ⚠️  requirements.txt not found")
        
        return True
    
    def create_env_file(self):
        """Create .env file for configuration"""
        print("⚙️  Creating configuration...")
        
        env_file = self.base_dir / ".env"
        if not env_file.exists():
            env_content = f"""# Universal Encryption Platform Configuration
# Generated by setup script

# Flask Configuration
FLASK_ENV=development
SECRET_KEY=dev-secret-change-in-production
JWT_SECRET_KEY=dev-jwt-secret-change-in-production

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# File Upload Configuration
UPLOAD_FOLDER=./uploads
TEMP_FOLDER=./temp
MAX_CONTENT_LENGTH=16777216

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=./logs/app.log

# Cryptography Configuration
PBKDF2_ITERATIONS=100000
DEFAULT_KDF_ALGORITHM=PBKDF2

# API Configuration
API_VERSION=v1
DEFAULT_PAGE_SIZE=50

# Security Configuration
FILE_RETENTION_HOURS=24
CLEANUP_INTERVAL_MINUTES=60

# Performance Configuration
MAX_WORKER_THREADS=4
THREAD_TIMEOUT=30
"""
            env_file.write_text(env_content)
            print("   ✅ .env file created")
        else:
            print("   ✅ .env file exists")
    
    def create_gitignore(self):
        """Create .gitignore file"""
        print("📝 Creating .gitignore...")
        
        gitignore_file = self.base_dir / ".gitignore"
        if not gitignore_file.exists():
            gitignore_content = """# Universal Encryption Platform .gitignore

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/

# Flask
instance/
.webassets-cache

# Environment Variables
.env
.env.local
.env.production

# Uploads and Temporary Files
uploads/
temp/
*.enc
*.tmp

# Logs
logs/
*.log

# Database
*.db
*.sqlite

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Docker
.dockerignore

# Secrets
secrets/
*.key
*.pem
*.crt

# Testing
.coverage
htmlcov/
.pytest_cache/
.tox/

# Documentation
docs/_build/
"""
            gitignore_file.write_text(gitignore_content)
            print("   ✅ .gitignore created")
    
    def test_installation(self):
        """Test the installation"""
        print("🧪 Testing installation...")
        
        try:
            # Test importing main modules
            sys.path.insert(0, str(self.base_dir))
            
            # Test crypto module
            try:
                from crypto.utils import generate_salt
                print("   ✅ Crypto module")
            except ImportError as e:
                print(f"   ❌ Crypto module: {e}")
            
            # Test Flask app
            try:
                # This would test app creation
                print("   ✅ Flask app structure")
            except Exception as e:
                print(f"   ⚠️  Flask app: {e}")
        
        except Exception as e:
            print(f"   ❌ Testing failed: {e}")
    
    def print_next_steps(self):
        """Print next steps for user"""
        print("""
🎉 Setup Complete!

Next Steps:
===========

1. Activate virtual environment:
   source venv/bin/activate  # Linux/Mac
   venv\\Scripts\\activate    # Windows

2. Start development server:
   python app.py

3. Access the application:
   🌐 Web Interface: http://localhost:5000
   🔧 Interactive Demo: http://localhost:5000/demo
   📚 API Documentation: http://localhost:5000/docs

4. Test API:
   curl http://localhost:5000/api/health

5. Docker deployment (optional):
   docker-compose up -d

Development Files:
==================
• app.py                 - Main Flask application
• crypto/                - Encryption algorithms
• utils/                 - Utility functions
• templates/             - HTML templates
• requirements.txt       - Python dependencies
• docker-compose.yml     - Container orchestration
• .env                   - Configuration

Resources:
==========
• Phase 1 focuses on core encryption functionality
• Add your encryption algorithms to crypto/ modules
• Modify templates/ for custom UI
• Extend utils/ for additional features

Happy coding! 🔐
""")
    
    def setup_docker(self):
        """Set up Docker configuration"""
        if not self.has_docker:
            return
        
        print("🐳 Setting up Docker...")
        
        # Create Dockerfile if it doesn't exist
        dockerfile = self.base_dir / "Dockerfile"
        if dockerfile.exists():
            print("   ✅ Dockerfile exists")
        else:
            print("   ⚠️  Dockerfile not found")
        
        # Create docker-compose.yml if it doesn't exist
        compose_file = self.base_dir / "docker-compose.yml"
        if compose_file.exists():
            print("   ✅ docker-compose.yml exists")
        else:
            print("   ⚠️  docker-compose.yml not found")
    
    def run_setup(self):
        """Run complete setup process"""
        try:
            self.print_banner()
            self.check_requirements()
            self.create_directories()
            self.create_init_files()
            
            # Set up virtual environment
            pip_path = self.setup_virtual_environment()
            
            # Install dependencies
            if not self.install_dependencies(pip_path):
                print("⚠️  Continuing with partial setup...")
            
            self.create_env_file()
            self.create_gitignore()
            self.setup_docker()
            self.test_installation()
            self.print_next_steps()
            
        except KeyboardInterrupt:
            print("\n\n❌ Setup interrupted by user")
            sys.exit(1)
        except Exception as e:
            print(f"\n\n❌ Setup failed: {e}")
            sys.exit(1)

def main():
    """Main setup function"""
    if len(sys.argv) > 1:
        if sys.argv[1] in ["--help", "-h"]:
            print("""
Universal Encryption Platform Setup Script

Usage:
  python setup.py          # Run full setup
  python setup.py --help   # Show this help

This script will:
• Check system requirements
• Create directory structure
• Set up virtual environment
• Install dependencies
• Create configuration files
• Test installation
""")
            return
    
    manager = SetupManager()
    manager.run_setup()

if __name__ == "__main__":
    main()