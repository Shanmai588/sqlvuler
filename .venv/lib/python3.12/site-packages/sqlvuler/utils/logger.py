#!/usr/bin/env python3
"""
Logging Utilities for SQLVuler
"""

import os
import logging
import sys
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init()

# Global logger instance
_logger = None

def setup_logger(name="sqlvuler", level=None, log_file=None, verbose=False):
    """
    Setup and configure the logger
    
    Args:
        name (str): Logger name
        level (int): Logging level
        log_file (str): Path to log file
        verbose (bool): Enable verbose logging
        
    Returns:
        logging.Logger: Configured logger instance
    """
    global _logger
    
    if _logger is not None:
        return _logger
    
    # Determine logging level
    if level is None:
        level = logging.DEBUG if verbose else logging.INFO
    
    # Configure logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    
    # Clear any existing handlers
    if logger.handlers:
        logger.handlers = []
    
    # Create console handler with custom formatter
    console_handler = ColorizingStreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = ColorizedFormatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if log file is specified
    if log_file is None:
        # Default to logs directory with timestamp
        logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(logs_dir, f"sqlvuler_{timestamp}.log")
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)  # Always log detailed info to file
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Store the global logger instance
    _logger = logger
    
    logger.debug(f"Logger initialized (level: {'DEBUG' if verbose else 'INFO'}, file: {log_file})")
    return logger

def get_logger():
    """
    Get the global logger instance
    
    Returns:
        logging.Logger: Logger instance
    """
    global _logger
    
    if _logger is None:
        _logger = setup_logger()
    
    return _logger

class ColorizingStreamHandler(logging.StreamHandler):
    """Stream handler that supports colorized output"""
    
    def emit(self, record):
        """Emit a record with colorized output"""
        try:
            msg = self.format(record)
            stream = self.stream
            stream.write(msg)
            stream.write(self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)

class ColorizedFormatter(logging.Formatter):
    """Formatter that adds color to log messages based on level"""
    
    COLORS = {
        logging.DEBUG: Fore.BLUE,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT
    }
    
    def format(self, record):
        """Format record with appropriate color based on level"""
        # Don't colorize if the message already contains color codes
        if any(code in record.msg for code in [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.CYAN]):
            return record.msg
        
        # Get the appropriate color for the log level
        color = self.COLORS.get(record.levelno, Fore.WHITE)
        
        # Format the message with color
        formatted_msg = f"{color}{record.msg}{Style.RESET_ALL}"
        
        # Replace the message and format the record
        record.msg = formatted_msg
        
        return record.msg