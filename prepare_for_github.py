#!/usr/bin/env python3
"""
GitHub Preparation Script for Universal Encryption Platform
This script cleans up sensitive files and prepares the repository for GitHub.
"""

import os
import shutil
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def remove_directory_contents(directory_path):
    """Remove all contents from a directory but keep the directory itself."""
    if os.path.exists(directory_path):
        try:
            for item in os.listdir(directory_path):
                item_path = os.path.join(directory_path, item)
                if item == '.gitkeep':
                    continue  # Keep .gitkeep files
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
            logger.info(f"Cleaned directory: {directory_path}")
        except Exception as e:
            logger.error(f"Error cleaning {directory_path}: {e}")
    else:
        logger.warning(f"Directory does not exist: {directory_path}")

def remove_file(file_path):
    """Remove a specific file if it exists."""
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            logger.info(f"Removed file: {file_path}")
        except Exception as e:
            logger.error(f"Error removing {file_path}: {e}")
    else:
        logger.info(f"File does not exist (already clean): {file_path}")

def main():
    """Main cleanup function."""
    logger.info("Starting GitHub preparation cleanup...")
    
    # Get the current directory (project root)
    project_root = Path(__file__).parent.absolute()
    logger.info(f"Project root: {project_root}")
    
    # Directories to clean (remove contents but keep directory)
    directories_to_clean = [
        'uploads/encrypted',
        'uploads/metadata', 
        'logs',
        'temp',
    ]
    
    # Files to remove
    files_to_remove = [
        '.env',  # Will be recreated from .env.example
        'logs/app.log',
        'tests/performance_report.json',
    ]
    
    # Clean directories
    logger.info("Cleaning sensitive directories...")
    for directory in directories_to_clean:
        dir_path = os.path.join(project_root, directory)
        remove_directory_contents(dir_path)
    
    # Remove sensitive files
    logger.info("Removing sensitive files...")
    for file_path in files_to_remove:
        full_path = os.path.join(project_root, file_path)
        remove_file(full_path)
    
    # Check for virtual environment
    venv_path = os.path.join(project_root, 'venv')
    if os.path.exists(venv_path):
        logger.warning("WARNING: Virtual environment 'venv' directory found.")
        logger.warning("This should be in .gitignore and not committed to GitHub.")
        logger.warning("Consider removing it with: rm -rf venv/")
    
    # Check for __pycache__ directories
    logger.info("Checking for __pycache__ directories...")
    for root, dirs, files in os.walk(project_root):
        if '__pycache__' in dirs:
            cache_path = os.path.join(root, '__pycache__')
            try:
                shutil.rmtree(cache_path)
                logger.info(f"Removed __pycache__: {cache_path}")
            except Exception as e:
                logger.error(f"Error removing __pycache__ {cache_path}: {e}")
    
    # Verify .env.example exists
    env_example = os.path.join(project_root, '.env.example')
    if not os.path.exists(env_example):
        logger.error("ERROR: .env.example file not found!")
        logger.error("Please ensure .env.example exists before committing.")
    else:
        logger.info("✓ .env.example file exists")
    
    # Verify .gitignore exists
    gitignore = os.path.join(project_root, '.gitignore')
    if not os.path.exists(gitignore):
        logger.error("ERROR: .gitignore file not found!")
        logger.error("Please ensure .gitignore exists before committing.")
    else:
        logger.info("✓ .gitignore file exists")
    
    # Check for .gitkeep files
    gitkeep_dirs = ['uploads', 'uploads/encrypted', 'uploads/metadata', 'logs', 'temp']
    for directory in gitkeep_dirs:
        gitkeep_path = os.path.join(project_root, directory, '.gitkeep')
        if os.path.exists(gitkeep_path):
            logger.info(f"✓ .gitkeep exists in {directory}")
        else:
            logger.warning(f"⚠ Missing .gitkeep in {directory}")
    
    logger.info("GitHub preparation cleanup completed!")
    logger.info("\nNext steps:")
    logger.info("1. Review the changes")
    logger.info("2. Copy .env.example to .env and configure for development")
    logger.info("3. Test the application: python run.py")
    logger.info("4. Initialize git: git init")
    logger.info("5. Add files: git add .")
    logger.info("6. Commit: git commit -m 'Initial commit'")
    logger.info("7. Add GitHub remote and push")

if __name__ == "__main__":
    main()