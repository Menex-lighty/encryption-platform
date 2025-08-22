#!/bin/bash
# Fix Universal Encryption Platform Dependencies

echo "🔧 Fixing Universal Encryption Platform Dependencies..."

# Check Python version
echo "📍 Checking Python version..."
python --version

# Check if virtual environment is activated
echo "📍 Checking virtual environment..."
python -c "import sys; print('Virtual env active' if sys.prefix != sys.base_prefix else 'No virtual env')"

# Upgrade pip first
echo "📦 Upgrading pip..."
python -m pip install --upgrade pip

# Force reinstall cryptography with the correct version
echo "🔐 Reinstalling cryptography library..."
pip uninstall cryptography -y
pip install cryptography==41.0.7

# Install other potential missing dependencies
echo "📚 Installing additional dependencies..."
pip install argon2-cffi==23.1.0
pip install pycryptodome==3.19.0

# Verify installation
echo "✅ Verifying cryptography installation..."
python -c "
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    print('✅ Argon2 import successful')
except ImportError as e:
    print(f'❌ Argon2 import failed: {e}')

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    print('✅ PBKDF2 import successful')
except ImportError as e:
    print(f'❌ PBKDF2 import failed: {e}')

try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    print('✅ Scrypt import successful')
except ImportError as e:
    print(f'❌ Scrypt import failed: {e}')
"

echo "🎉 Dependencies check complete!"