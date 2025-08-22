# Universal Encryption Platform - Backend Docker Image
# Phase 1: Core Foundation

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libmagic1 \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    UPLOAD_FOLDER=/app/data/uploads \
    TEMP_FOLDER=/app/data/temp \
    LOG_FILE=/app/logs/app.log

# Create necessary directories
RUN mkdir -p /app/data/uploads \
             /app/data/temp \
             /app/logs \
             /app/data/uploads/encrypted \
             /app/data/uploads/metadata

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create crypto module directories with __init__.py files
RUN mkdir -p crypto utils && \
    touch crypto/__init__.py utils/__init__.py

# Set proper permissions
RUN chmod -R 755 /app && \
    chmod -R 777 /app/data && \
    chmod -R 777 /app/logs

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/api/health')" || exit 1

# Expose port
EXPOSE 5000

# Start command
CMD ["python", "app.py"]

# Alternative production command with Gunicorn
# CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "app:create_app()"]