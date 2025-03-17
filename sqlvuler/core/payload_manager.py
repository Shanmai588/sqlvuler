#!/usr/bin/env python3
"""
Payload Manager for SQLVuler
Handles loading and managing SQL injection payloads
"""

import os
import glob
import json
import re
from pathlib import Path

from sqlvuler.utils.logger import get_logger

class PayloadManager:
    """Manager for SQL injection payloads"""
    
    def __init__(self, config_manager=None):
        """
        Initialize the Payload Manager
        
        Args:
            config_manager: Configuration manager instance
        """
        self.logger = get_logger()
        self.config_manager = config_manager
        
        # Get payload directories
        self.base_dir = self._get_base_dir()
        self.payloads = {}
        self.metadata = {}
        
        # Load payloads
        self.load_payloads()
    
    def _get_base_dir(self):
        """
        Get the base directory for payloads
        
        Returns:
            str: Path to the payloads directory
        """
        # If config manager is provided, use the configured path
        if self.config_manager:
            try:
                path = self.config_manager.get("payloads.path")
                if path:
                    return path
            except (KeyError, AttributeError):
                pass
        
        # Default to payloads directory in the package
        return os.path.join(Path(__file__).parent.parent.parent, "payloads")
    
    def load_payloads(self):
        """
        Load all payloads from the payloads directory
        
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        self.logger.info(f"Loading payloads from {self.base_dir}")
        
        if not os.path.exists(self.base_dir):
            self.logger.error(f"Payloads directory not found: {self.base_dir}")
            return False
        
        # Find all payload files recursively
        payload_files = glob.glob(os.path.join(self.base_dir, "**/*.txt"), recursive=True)
        
        if not payload_files:
            self.logger.warning(f"No payload files found in {self.base_dir}")
            return False
        
        # Load each payload file
        for payload_file in payload_files:
            try:
                self._load_payload_file(payload_file)
            except Exception as e:
                self.logger.error(f"Error loading payload file {payload_file}: {str(e)}")
        
        self.logger.info(f"Loaded {len(self.payloads)} payload categories")
        return True
    
    def _load_payload_file(self, file_path):
        """
        Load payloads from a single file
        
        Args:
            file_path (str): Path to the payload file
        """
        # Determine category from path
        rel_path = os.path.relpath(file_path, self.base_dir)
        parts = os.path.normpath(rel_path).split(os.sep)
        
        # Category is based on directory structure
        if len(parts) >= 2:
            category = "/".join(parts[:-1])
        else:
            category = "generic"
        
        # Filename without extension becomes the payload type
        payload_type = os.path.splitext(parts[-1])[0]
        
        # Read the file
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse metadata and payloads
        metadata, payloads = self._parse_payload_content(content)
        
        # Store metadata
        if category not in self.metadata:
            self.metadata[category] = {}
        
        self.metadata[category][payload_type] = metadata
        
        # Store payloads
        if category not in self.payloads:
            self.payloads[category] = {}
        
        self.payloads[category][payload_type] = payloads
        
        self.logger.debug(f"Loaded {len(payloads)} payloads from {file_path}")
    
    def _parse_payload_content(self, content):
        """
        Parse payload file content
        
        Args:
            content (str): File content
            
        Returns:
            tuple: (metadata, payloads)
        """
        lines = content.splitlines()
        metadata = {}
        payloads = []
        
        # Extract metadata from comments at the beginning
        for line in lines:
            line = line.strip()
            if line.startswith('#'):
                # Parse metadata from comment lines
                if ':' in line:
                    key, value = line[1:].split(':', 1)
                    metadata[key.strip()] = value.strip()
            elif line:
                # Parse payload
                if '|' in line:
                    # Format: payload|description|risk
                    parts = line.split('|')
                    if len(parts) >= 3:
                        payload, description, risk = parts[:3]
                        payloads.append({
                            'payload': payload,
                            'description': description,
                            'risk': risk.lower()
                        })
                    elif len(parts) == 2:
                        payload, description = parts
                        payloads.append({
                            'payload': payload,
                            'description': description,
                            'risk': 'medium'  # Default risk level
                        })
                    else:
                        # Just the payload
                        payloads.append({
                            'payload': line,
                            'description': '',
                            'risk': 'medium'  # Default risk level
                        })
                else:
                    # Just the payload
                    payloads.append({
                        'payload': line,
                        'description': '',
                        'risk': 'medium'  # Default risk level
                    })
        
        return metadata, payloads
    
    def get_payloads(self, category=None, payload_type=None, risk_level=None):
        """
        Get payloads filtered by category, type and/or risk level
        
        Args:
            category (str): Payload category
            payload_type (str): Payload type
            risk_level (str): Risk level (low, medium, high)
            
        Returns:
            list: List of payloads
        """
        result = []
        
        # Filter by category
        if category:
            if category not in self.payloads:
                return []
            
            categories = [category]
        else:
            categories = self.payloads.keys()
        
        # Collect payloads from each category
        for cat in categories:
            if not self.payloads.get(cat):
                continue
                
            # Filter by payload type
            if payload_type:
                if payload_type not in self.payloads[cat]:
                    continue
                
                types = [payload_type]
            else:
                types = self.payloads[cat].keys()
            
            # Collect payloads of each type
            for typ in types:
                if not self.payloads[cat].get(typ):
                    continue
                    
                # Filter by risk level
                for payload in self.payloads[cat][typ]:
                    if risk_level and payload['risk'] != risk_level.lower():
                        continue
                    
                    # Add category and type information to the payload
                    payload_info = payload.copy()
                    payload_info['category'] = cat
                    payload_info['type'] = typ
                    
                    result.append(payload_info)
        
        return result
    
    def get_categories(self):
        """
        Get all payload categories
        
        Returns:
            list: List of category names
        """
        return list(self.payloads.keys())
    
    def get_types(self, category=None):
        """
        Get payload types for a category
        
        Args:
            category (str): Category name
            
        Returns:
            list: List of payload types
        """
        if category:
            if category not in self.payloads:
                return []
            
            return list(self.payloads[category].keys())
        else:
            # Get all types across all categories
            types = set()
            for category in self.payloads:
                types.update(self.payloads[category].keys())
            
            return list(types)
    
    def get_metadata(self, category=None, payload_type=None):
        """
        Get metadata for a category and/or payload type
        
        Args:
            category (str): Category name
            payload_type (str): Payload type
            
        Returns:
            dict: Metadata dictionary
        """
        if category and payload_type:
            if category in self.metadata and payload_type in self.metadata[category]:
                return self.metadata[category][payload_type]
            else:
                return {}
        elif category:
            if category in self.metadata:
                return self.metadata[category]
            else:
                return {}
        else:
            return self.metadata
    
    def format_payload(self, payload, variables=None):
        """
        Format a payload with variable substitution
        
        Args:
            payload (str): Payload template
            variables (dict): Variables to substitute
            
        Returns:
            str: Formatted payload
        """
        if not variables:
            return payload
        
        # Replace variables in the payload
        formatted = payload
        
        for var_name, var_value in variables.items():
            placeholder = '{' + var_name + '}'
            formatted = formatted.replace(placeholder, str(var_value))
        
        return formatted