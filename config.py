"""
Configuration Management for Universal Encryption Platform
Environment-based configuration with security best practices
"""

import os
from datetime import timedelta
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.absolute()

class Config:
    """Base configuration class"""
    
    # ================================
    # Flask Configuration
    # ================================
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-change-in-production'
    FLASK_ENV = os.environ.get('FLASK_ENV', 'development')
    
    # ================================
    # Security Configuration
    # ================================
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # CORS Configuration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://localhost:8080').split(',')
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'memory://')
    RATELIMIT_DEFAULT = "100/hour"
    
    # ================================
    # File Upload Configuration
    # ================================
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', str(BASE_DIR / 'uploads'))
    TEMP_FOLDER = os.environ.get('TEMP_FOLDER', str(BASE_DIR / 'temp'))
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB
    
    # File retention
    FILE_RETENTION_HOURS = int(os.environ.get('FILE_RETENTION_HOURS', 24))
    CLEANUP_INTERVAL_MINUTES = int(os.environ.get('CLEANUP_INTERVAL_MINUTES', 60))
    
    # ================================
    # Cryptography Configuration
    # ================================
    # Key Derivation
    DEFAULT_KDF_ALGORITHM = os.environ.get('DEFAULT_KDF_ALGORITHM', 'PBKDF2')
    PBKDF2_ITERATIONS = int(os.environ.get('PBKDF2_ITERATIONS', 100000))
    SCRYPT_N = int(os.environ.get('SCRYPT_N', 16384))  # 2^14
    ARGON2_TIME_COST = int(os.environ.get('ARGON2_TIME_COST', 2))
    ARGON2_MEMORY_COST = int(os.environ.get('ARGON2_MEMORY_COST', 65536))  # 64MB
    
    # Default algorithms by data type
    RECOMMENDED_ALGORITHMS = {
        'text': 'AES-256-GCM',
        'image': 'AES-256-CBC',
        'video': 'AES-256-CTR',
        'file': 'AES-256-XTS'
    }
    
    # Algorithm security levels
    ALGORITHM_SECURITY_LEVELS = {
        'AES-256-GCM': 'very_high',
        'ChaCha20-Poly1305': 'very_high',
        'RSA-4096': 'very_high',
        'AES-256-CBC': 'very_high',
        'AES-256-XTS': 'very_high',
        'Caesar': 'educational',
        'Vigenere': 'low',
        'ROT13': 'educational',
        'Atbash': 'educational',
        'Playfair': 'low'
    }
    
    # ================================
    # API Configuration
    # ================================
    API_VERSION = os.environ.get('API_VERSION', 'v1')
    API_TITLE = "Universal Encryption Platform API"
    API_DESCRIPTION = "Cross-platform encryption system with intelligent algorithm selection"
    
    # Pagination
    DEFAULT_PAGE_SIZE = int(os.environ.get('DEFAULT_PAGE_SIZE', 50))
    MAX_PAGE_SIZE = int(os.environ.get('MAX_PAGE_SIZE', 1000))
    
    # ================================
    # Logging Configuration
    # ================================
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', str(BASE_DIR / 'logs' / 'app.log'))
    LOG_MAX_BYTES = int(os.environ.get('LOG_MAX_BYTES', 10 * 1024 * 1024))  # 10MB
    LOG_BACKUP_COUNT = int(os.environ.get('LOG_BACKUP_COUNT', 5))
    
    # ================================
    # Database Configuration (Optional)
    # ================================
    # Uncomment if using database
    # DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///encryption_platform.db')
    # SQLALCHEMY_DATABASE_URI = DATABASE_URL
    # SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # ================================
    # Cache Configuration (Optional)
    # ================================
    # CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')
    # CACHE_REDIS_URL = os.environ.get('CACHE_REDIS_URL', 'redis://localhost:6379/0')
    # CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', 300))
    
    # ================================
    # Performance Configuration
    # ================================
    # Threading
    MAX_WORKER_THREADS = int(os.environ.get('MAX_WORKER_THREADS', 4))
    THREAD_TIMEOUT = int(os.environ.get('THREAD_TIMEOUT', 30))
    
    # Memory limits
    MAX_MEMORY_USAGE_MB = int(os.environ.get('MAX_MEMORY_USAGE_MB', 512))
    
    @staticmethod
    def init_app(app):
        """Initialize application with configuration"""
        # Create necessary directories
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.TEMP_FOLDER, exist_ok=True)
        os.makedirs(os.path.dirname(Config.LOG_FILE), exist_ok=True)
        
        # Set up logging
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug and not app.testing:
            # File logging
            file_handler = RotatingFileHandler(
                Config.LOG_FILE,
                maxBytes=Config.LOG_MAX_BYTES,
                backupCount=Config.LOG_BACKUP_COUNT
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(getattr(logging, Config.LOG_LEVEL))
            app.logger.addHandler(file_handler)
            
            app.logger.setLevel(getattr(logging, Config.LOG_LEVEL))
            app.logger.info('Universal Encryption Platform startup')


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    FLASK_ENV = 'development'
    
    # Relaxed security for development
    CORS_ORIGINS = ['*']
    
    # More verbose logging
    LOG_LEVEL = 'DEBUG'
    
    # Faster key derivation for testing
    PBKDF2_ITERATIONS = 10000
    
    # Shorter file retention
    FILE_RETENTION_HOURS = 1


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    FLASK_ENV = 'testing'
    
    # Use in-memory storage for testing
    UPLOAD_FOLDER = '/tmp/test_uploads'
    TEMP_FOLDER = '/tmp/test_temp'
    
    # Fast encryption for tests
    PBKDF2_ITERATIONS = 1000
    
    # Disable rate limiting
    RATELIMIT_STORAGE_URL = 'memory://'
    
    # Test-specific settings
    SECRET_KEY = 'test-secret-key'
    JWT_SECRET_KEY = 'test-jwt-secret'


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    FLASK_ENV = 'production'
    
    # Enhanced security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Strict CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '').split(',')
    
    # Production logging
    LOG_LEVEL = 'WARNING'
    
    # Enhanced key derivation
    PBKDF2_ITERATIONS = 200000
    
    # Validate required environment variables
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Ensure production secrets are set
        required_vars = ['SECRET_KEY', 'JWT_SECRET_KEY']
        missing_vars = [var for var in required_vars if not os.environ.get(var)]
        
        if missing_vars:
            raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
        # Production-specific logging
        import logging
        from logging.handlers import SysLogHandler
        
        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.WARNING)
        app.logger.addHandler(syslog_handler)


class DockerConfig(Config):
    """Docker deployment configuration"""
    
    # Container-friendly paths
    UPLOAD_FOLDER = '/app/data/uploads'
    TEMP_FOLDER = '/app/data/temp'
    LOG_FILE = '/app/logs/app.log'
    
    # Use environment variables for external services
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
    DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://user:pass@postgres:5432/encryption_db')


# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'docker': DockerConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])

# Security utilities
class SecurityConfig:
    """Security-specific configuration and utilities"""
    
    # Password requirements
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 256
    
    # Algorithm blacklist (insecure algorithms)
    DEPRECATED_ALGORITHMS = ['DES', 'MD5', 'SHA1']
    
    # File type restrictions
    ALLOWED_MIME_TYPES = [
        'text/plain',
        'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp',
        'video/mp4', 'video/avi', 'video/mov', 'video/mkv',
        'application/pdf',
        'application/zip', 'application/x-rar-compressed'
    ]
    
    # Rate limiting by endpoint
    RATE_LIMITS = {
        'encrypt': '50/hour',
        'decrypt': '50/hour',
        'upload': '20/hour',
        'algorithms': '200/hour'
    }
    
    @staticmethod
    def validate_algorithm(algorithm: str, data_type: str) -> bool:
        """Validate algorithm choice for security"""
        if algorithm in SecurityConfig.DEPRECATED_ALGORITHMS:
            return False
        
        # Add custom validation logic here
        return True
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize uploaded filenames"""
        import re
        # Remove dangerous characters
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:255-len(ext)] + ext
        return filename

# Application factory configuration
def create_app_config(config_name=None):
    """Create application configuration"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    return config.get(config_name, config['default'])