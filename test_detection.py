#!/usr/bin/env python3
"""
Test script for file type detection methods
"""

import sys

def test_file_detection():
    print('🧪 Testing file type detection methods...')
    print('-' * 50)
    
    # Test 1: python-magic
    print("Test 1: python-magic")
    try:
        import magic
        m = magic.Magic(mime=True)
        result = m.from_buffer(b'Hello World')
        print(f'✅ python-magic: {result}')
    except Exception as e:
        print(f'❌ python-magic failed: {e}')
    
    # Test 2: filetype library
    print("\nTest 2: filetype library")
    try:
        import filetype
        print('✅ filetype library imported successfully')
        
        # Test with sample data
        test_data = b'\x89PNG\r\n\x1a\n'  # PNG header
        kind = filetype.guess(test_data)
        if kind:
            print(f'✅ filetype detection: {kind.mime}')
        else:
            print('❌ filetype could not detect sample data')
    except Exception as e:
        print(f'❌ filetype failed: {e}')
    
    # Test 3: mimetypes (always works)
    print("\nTest 3: mimetypes (built-in)")
    try:
        import mimetypes
        mime_type, encoding = mimetypes.guess_type('test.jpg')
        print(f'✅ mimetypes: {mime_type}')
        
        # Test more types
        test_files = ['test.png', 'test.mp4', 'test.pdf', 'test.txt']
        for filename in test_files:
            mime_type, _ = mimetypes.guess_type(filename)
            print(f'  - {filename}: {mime_type}')
            
    except Exception as e:
        print(f'❌ mimetypes failed: {e}')
    
    print('\n' + '=' * 50)
    print('File type detection setup complete!')

def test_crypto_utils():
    print('\n🔐 Testing crypto utilities...')
    print('-' * 50)
    
    try:
        from crypto.utils import generate_salt, derive_key, validate_password_strength
        print('✅ Crypto utils imported successfully')
        
        # Test salt generation
        salt = generate_salt()
        print(f'✅ Salt generation: {len(salt)} bytes')
        
        # Test key derivation
        key = derive_key('test_password', salt, algorithm='PBKDF2')
        print(f'✅ Key derivation working: {len(key)} bytes')
        
        # Test password validation
        strength = validate_password_strength('TestPassword123!')
        strength_level = strength.get('strength', 'Unknown')
        print(f'✅ Password validation: {strength_level}')
        
        print('\n✅ All crypto tests passed!')
        
    except Exception as e:
        print(f'❌ Crypto utils failed: {e}')
        import traceback
        traceback.print_exc()

def test_app_imports():
    print('\n🚀 Testing app imports...')
    print('-' * 50)
    
    try:
        # Test main app import
        from app import create_app
        print('✅ Main app imported successfully')
        
        # Test validators
        from utils.validators import validate_encryption_request
        print('✅ Validators imported successfully')
        
        # Test formatters
        from utils.formatters import format_response
        print('✅ Formatters imported successfully')
        
        print('\n✅ All app imports successful!')
        
    except Exception as e:
        print(f'❌ App import failed: {e}')
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_file_detection()
    test_crypto_utils()
    test_app_imports()
    
    print('\n🎉 Testing complete!')
    print('\nNext steps:')
    print('1. If python-magic failed, that\'s OK - we have fallbacks')
    print('2. If filetype failed, install it: pip install filetype')
    print('3. If crypto utils work, try: python app.py')