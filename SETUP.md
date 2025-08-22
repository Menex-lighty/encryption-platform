# 🚀 Setup Guide for Universal Encryption Platform

This guide will help you get the Universal Encryption Platform up and running quickly.

## Prerequisites

- **Python 3.8+** installed on your system
- **Git** for version control
- **pip** package manager

## Quick Setup

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/universal-encryption-platform.git
cd universal-encryption-platform
```

### 2. Create Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Setup Environment Variables
```bash
# Copy the example environment file
cp .env.example .env

# Edit .env file with your preferred settings
# At minimum, change the SECRET_KEY and JWT_SECRET_KEY for production use
```

### 5. Run Setup Script
```bash
# This will create necessary directories and run initial tests
python setup.py
```

### 6. Start the Application
```bash
python run.py
```

## Verification

Once the application is running, visit these URLs to verify everything works:

- **Main Application**: http://localhost:5000
- **Interactive Demo**: http://localhost:5000/demo
- **API Documentation**: http://localhost:5000/docs
- **Health Check**: http://localhost:5000/api/health

## Development Setup

### Running Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=html
```

### Code Quality Tools
```bash
# Format code
black .

# Check linting
flake8

# Type checking
mypy .

# Security scan
bandit -r .
```

## Docker Setup (Alternative)

If you prefer using Docker:

```bash
# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f backend

# Stop services
docker-compose down
```

## Configuration

### Environment Variables

Key configuration options in `.env`:

- `SECRET_KEY`: Flask secret key (change for production!)
- `CORS_ORIGINS`: Allowed frontend origins
- `MAX_CONTENT_LENGTH`: File upload size limit (default: 16MB)
- `PBKDF2_ITERATIONS`: Key derivation iterations (default: 100,000)

### File Storage

By default, files are stored in:
- `uploads/encrypted/`: Encrypted files
- `uploads/metadata/`: File metadata
- `logs/`: Application logs
- `temp/`: Temporary files

## Troubleshooting

### Common Issues

1. **Import Errors**: Make sure virtual environment is activated
2. **Port Already in Use**: Change port in `run.py` or stop other services
3. **Permission Errors**: Check file permissions on uploads directory
4. **Missing Dependencies**: Run `pip install -r requirements.txt` again

### Windows-Specific Issues

If you encounter issues with `python-magic`:
```bash
# Install Windows-compatible version
pip install python-magic-bin
pip install filetype
```

### Getting Help

- Check the main [README.md](README.md) for comprehensive documentation
- Review [TESTING.md](TESTING.md) for testing information
- Open an issue on GitHub for bugs or feature requests

## Next Steps

1. **Explore the Demo**: Visit `/demo` to try different encryption algorithms
2. **Read the API Docs**: Check `/docs` for API documentation
3. **Run Tests**: Ensure everything works with `python -m pytest`
4. **Customize**: Modify algorithms, add features, or integrate with your app

## Security Notes

- **Never commit `.env` files** to version control
- **Change default secrets** before deploying to production
- **Use HTTPS** in production environments
- **Regularly update dependencies** for security patches

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and ensure code quality
5. Submit a pull request

Happy encrypting! 🔐