"""
Logging configuration for KubeGuard
Based on previous project logging setup with KubeGuard-specific configuration
"""

import os
import logging
from logging.handlers import RotatingFileHandler


def setup_logging(log_dir="logs", console_level=logging.INFO, file_level=logging.DEBUG):
    """
    Configure logging for KubeGuard application
    
    Args:
        log_dir: Directory to store log files
        console_level: Log level for console output (default: INFO for API calls)
        file_level: Log level for file output (default: DEBUG for everything)
    """
    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)  # Capture everything at root level
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Configure formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create file handler for all logs (DEBUG and above)
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'kubeguard.log'),
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(file_level)
    file_handler.setFormatter(formatter)
    
    # Create console handler (configurable level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)
    
    # Add handlers to root logger
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Configure specific loggers to reduce noise
    logging.getLogger('httpx').setLevel(logging.WARNING)  # Reduce HTTP client noise
    logging.getLogger('openai').setLevel(logging.WARNING)  # Reduce OpenAI client noise
    logging.getLogger('anthropic').setLevel(logging.WARNING)  # Reduce Anthropic noise
    
    # Set KubeGuard logger to be more verbose
    kubeguard_logger = logging.getLogger('kubeguard')
    kubeguard_logger.setLevel(logging.DEBUG)
    
    return root_logger


def setup_debug_logging(log_dir="logs"):
    """Setup logging with maximum verbosity for debugging"""
    return setup_logging(log_dir, console_level=logging.DEBUG, file_level=logging.DEBUG)


def setup_production_logging(log_dir="logs"):
    """Setup logging for production with minimal console output"""
    return setup_logging(log_dir, console_level=logging.WARNING, file_level=logging.INFO)