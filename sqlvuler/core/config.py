#!/usr/bin/env python3
"""
Configuration Manager for SQLVuler
Handles loading, saving, and managing configuration options
"""

import os
import json
import copy
from pathlib import Path

from sqlvuler.utils.logger import get_logger

class ConfigManager:
    """Configuration Manager for SQLVuler"""
    
    def __init__(self, config_path=None):
        """
        Initialize the Configuration Manager
        
        Args:
            config_path (str): Path to a configuration file
        """
        self.logger = get_logger()
        
        # Default configuration
        self.default_config = {
            "general": {
                "threads": 5,
                "user_agent": "SQLVuler/1.0 (Educational Purpose Only)",
            },
            "scanner": {
                "detection_level": "medium",
                "risk_level": "medium",
                "techniques": ["error", "boolean", "time"],
                "dbms_enumeration": True,
                "data_extraction": True
            },
            "http": {
                "proxy": None,
                "retry": 3,
                "delay": 0,
                "timeout": 10,
                "follow_redirects": True
            },
            "payloads": {
                "path": "payloads",
                "custom_path": None
            },
            "target": {
                "url": "",
                "method": "GET",
                "content_type": "",
                "headers": {}
            },
            "parameters": {
                "list": [],
                "max_length": 1000,
                "test_cookies": False,
                "parse_json": True
            }
        }
        
        # Current configuration (starts as a copy of the default)
        self.config = copy.deepcopy(self.default_config)
        
        # Base directory for configuration files
        self.config_dir = self._get_config_dir()
        
        # Dictionary of handlers
        self.handlers = {}
        
        # Load configuration file if provided
        if config_path:
            self.load_config(config_path)
        else:
            # Try to load default configuration file
            default_config_path = os.path.join(self.config_dir, "default.json")
            if os.path.exists(default_config_path):
                self.load_config(default_config_path)
    
    def _get_config_dir(self):
        """
        Get the configuration directory path
        
        Returns:
            str: Path to the configuration directory
        """
        # Get the base directory
        base_dir = Path(__file__).parent.parent.parent
        
        # Configuration directory
        config_dir = os.path.join(base_dir, "data", "configs")
        
        # Create directory if it doesn't exist
        os.makedirs(config_dir, exist_ok=True)
        
        return config_dir
    
    def load_config(self, config_path):
        """
        Load configuration from a file
        
        Args:
            config_path (str): Path to the configuration file
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        try:
            with open(config_path, 'r') as f:
                loaded_config = json.load(f)
            
            # Merge with default configuration
            self._merge_configs(loaded_config)
            
            self.logger.info(f"Loaded configuration from {config_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            return False
    
    def save_config(self, config_path=None):
        """
        Save configuration to a file
        
        Args:
            config_path (str): Path to save the configuration file
                               If None, uses the default path
                               
        Returns:
            bool: True if saved successfully, False otherwise
        """
        if not config_path:
            config_path = os.path.join(self.config_dir, "default.json")
        
        try:
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            
            self.logger.info(f"Saved configuration to {config_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving configuration: {str(e)}")
            return False
    
    def reset_to_default(self):
        """Reset configuration to default values"""
        self.config = copy.deepcopy(self.default_config)
        self.logger.info("Reset configuration to default values")
    
    def _merge_configs(self, loaded_config):
        """
        Merge loaded configuration with the current configuration
        
        Args:
            loaded_config (dict): Configuration loaded from a file
        """
        for section, options in loaded_config.items():
            if section not in self.config:
                self.config[section] = {}
            
            if isinstance(options, dict):
                for option, value in options.items():
                    self.config[section][option] = value
    
    def get(self, option_path):
        """
        Get a configuration option
        
        Args:
            option_path (str): Path to the option (e.g., "general.threads")
            
        Returns:
            any: The option value
            
        Raises:
            KeyError: If the option path is not found
        """
        parts = option_path.split('.')
        
        if len(parts) == 1:
            if parts[0] in self.config:
                return self.config[parts[0]]
            else:
                raise KeyError(f"Option '{option_path}' not found")
        elif len(parts) == 2:
            section, option = parts
            if section in self.config and option in self.config[section]:
                return self.config[section][option]
            else:
                raise KeyError(f"Option '{option_path}' not found")
        else:
            raise KeyError(f"Invalid option path format: {option_path}")
    
    def set(self, option_path, value):
        """
        Set a configuration option
        
        Args:
            option_path (str): Path to the option (e.g., "general.threads")
            value (any): Value to set
            
        Raises:
            KeyError: If the option path is not found
        """
        parts = option_path.split('.')
        
        if len(parts) == 1:
            # Setting an entire section
            section = parts[0]
            if not isinstance(value, dict):
                raise ValueError(f"Value for section '{section}' must be a dictionary")
            
            if section not in self.config:
                self.config[section] = {}
            
            self.config[section] = value
        elif len(parts) == 2:
            # Setting a specific option
            section, option = parts
            
            if section not in self.config:
                self.config[section] = {}
            
            self.config[section][option] = value
        else:
            raise KeyError(f"Invalid option path format: {option_path}")
    
    def get_all(self):
        """
        Get the entire configuration
        
        Returns:
            dict: The current configuration
        """
        return copy.deepcopy(self.config)
    
    def register_handler(self, name, handler):
        """
        Register a handler for a specific configuration section
        
        Args:
            name (str): Section name
            handler (object): Handler object
            
        Returns:
            bool: True if registered successfully, False otherwise
        """
        try:
            self.handlers[name] = handler
            self.logger.debug(f"Registered handler for section: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Error registering handler: {str(e)}")
            return False
    
    def get_handler(self, name):
        """
        Get a handler by name
        
        Args:
            name (str): Handler name
            
        Returns:
            object: Handler object or None if not found
        """
        return self.handlers.get(name)
    
    def save_all(self):
        """
        Save all configuration sections that have handlers
        
        Returns:
            bool: True if all sections saved successfully, False otherwise
        """
        success = True
        
        for name, handler in self.handlers.items():
            if hasattr(handler, 'save_to_config'):
                try:
                    if not handler.save_to_config():
                        success = False
                except Exception as e:
                    self.logger.error(f"Error saving section {name}: {str(e)}")
                    success = False
        
        return success
    
    def load_all(self):
        """
        Load all configuration sections that have handlers
        
        Returns:
            bool: True if all sections loaded successfully, False otherwise
        """
        success = True
        
        for name, handler in self.handlers.items():
            if hasattr(handler, 'load_from_config'):
                try:
                    if not handler.load_from_config():
                        success = False
                except Exception as e:
                    self.logger.error(f"Error loading section {name}: {str(e)}")
                    success = False
        
        return success