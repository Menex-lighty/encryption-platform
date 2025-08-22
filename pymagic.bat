# Universal Encryption Platform - Windows Magic Fix
# Complete solution for python-magic on Windows

echo "🔧 Fixing python-magic for Windows..."

# Method 1: Reinstall python-magic with binary support
echo "📦 Method 1: Reinstalling python-magic with Windows binaries..."
pip uninstall python-magic python-magic-bin -y
pip install python-magic-bin==0.4.14
pip install python-magic==0.4.27

# Method 2: Alternative - Use filetype library instead (more reliable on Windows)
echo "📦 Method 2: Installing alternative file type detection..."
pip install filetype==1.2.0

# Method 3: Install libmagic manually for Windows
echo "📦 Method 3: Manual libmagic installation guide..."
echo "Download libmagic binaries from: https://github.com/pidydx/libmagicwin64"

# Test the installation
echo "🧪 Testing magic installation..."
python -c "
try:
    import magic
    print('✅ python-magic imported successfully')
    
    # Test magic functionality
    magic_obj = magic.Magic()
    test_result = magic_obj.from_buffer(b'Hello World')
    print(f'✅ Magic test result: {test_result}')
    
except Exception as e:
    print(f'❌ Magic import/test failed: {e}')
    print('Trying alternative...')
    
    try:
        import filetype
        print('✅ filetype library available as alternative')
    except ImportError:
        print('❌ No file type detection available')
"

echo "🎉 Magic fix complete!"