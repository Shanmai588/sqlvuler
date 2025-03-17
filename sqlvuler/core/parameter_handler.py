#!/usr/bin/env python3
"""
Parameter Handler for SQLVuler
Loads and manages parameters from user inputs or HTTP request files
"""

import re
import json
import urllib.parse
from colorama import Fore, Style

from sqlvuler.utils.logger import get_logger

class ParameterHandler:
    """Handles parameter extraction and management for SQL injection testing"""
    
    def __init__(self, config_manager=None):
        """
        Initialize the Parameter Handler
        
        Args:
            config_manager: Configuration manager instance
        """
        self.logger = get_logger()
        self.config_manager = config_manager
        
        # Store parameters and request details
        self.parameters = []
        self.request_details = {
            "headers": {},
            "method": "GET",
            "url": "",
            "content_type": ""
        }
        
        # Load settings from config manager if provided
        if self.config_manager:
            self.load_from_config()
    
    def load_from_file(self, file_path):
        """
        Load parameters from a file containing an HTTP request
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        self.logger.info(f"Loading parameters from {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                request_content = f.read()
            
            return self.parse_http_request(request_content)
            
        except Exception as e:
            self.logger.error(f"Error loading parameters from file: {str(e)}")
            return False

    def save_to_config(self):
        """Save current parameters and settings to the configuration manager"""
        if not self.config_manager:
            return False
        
        try:
            # Save parameter list (serialized)
            param_list = []
            for param in self.parameters:
                # Create a simplified version of each parameter
                param_data = {
                    "name": param["name"],
                    "value": param["value"],
                    "type": param["type"],
                    "enabled": param["enabled"]
                }
                param_list.append(param_data)
            
            self.config_manager.set("parameters.list", param_list)
            
            # Save request details
            self.config_manager.set("target.url", self.request_details["url"])
            self.config_manager.set("target.method", self.request_details["method"])
            self.config_manager.set("target.content_type", self.request_details["content_type"])
            
            # Headers need special handling for serialization
            if self.request_details["headers"]:
                header_dict = dict(self.request_details["headers"])
                self.config_manager.set("target.headers", header_dict)
            
            self.logger.debug("Saved parameters to configuration")
            return True
        except Exception as e:
            self.logger.error(f"Error saving parameters to configuration: {str(e)}")
            return False
    
    def load_from_config(self):
        """Load parameters from the configuration manager"""
        if not self.config_manager:
            return False
        
        try:
            # Load parameters list
            param_list = self.config_manager.get("parameters.list")
            if param_list:
                # Clear existing parameters
                self.parameters = []
                
                # Restore parameters with full attributes
                for param_data in param_list:
                    param_type = param_data.get("type", "GET")
                    in_url = param_type == "GET"
                    in_body = param_type == "POST"
                    in_cookie = param_type == "COOKIE"
                    
                    self.parameters.append({
                        "name": param_data["name"],
                        "value": param_data["value"],
                        "type": param_type,
                        "url": self.config_manager.get("target.url", ""),
                        "in_url": in_url,
                        "in_body": in_body,
                        "in_cookie": in_cookie,
                        "enabled": param_data.get("enabled", True)
                    })
            
            # Load request details
            if self.config_manager.get("target.url"):
                self.request_details["url"] = self.config_manager.get("target.url")
            
            if self.config_manager.get("target.method"):
                self.request_details["method"] = self.config_manager.get("target.method")
            
            if self.config_manager.get("target.content_type"):
                self.request_details["content_type"] = self.config_manager.get("target.content_type")
            
            if self.config_manager.get("target.headers"):
                self.request_details["headers"] = self.config_manager.get("target.headers")
            
            self.logger.debug("Loaded parameters from configuration")
            return True
        except Exception as e:
            self.logger.error(f"Error loading parameters from configuration: {str(e)}")
            return False

    def parse_http_request(self, request_content):
        """
        Parse an HTTP request string
        
        Args:
            request_content (str): HTTP request content
            
        Returns:
            bool: True if parsed successfully, False otherwise
        """
        # Reset current parameters and request details
        self.parameters = []
        self.request_details = {
            "headers": {},
            "method": "GET",
            "url": "",
            "content_type": ""
        }
        
        try:
            # Split the request into lines
            lines = request_content.strip().split('\n')
            
            if not lines:
                self.logger.error("Empty request content")
                return False
            
            # Parse the request line (first line)
            request_line = lines[0]
            parts = request_line.split(' ')
            
            if len(parts) < 2:
                self.logger.error(f"Invalid request line: {request_line}")
                return False
            
            # Extract method and URL
            self.request_details["method"] = parts[0].upper()
            self.request_details["url"] = parts[1]
            
            # Parse headers
            headers = {}
            body_start = 0
            
            for i, line in enumerate(lines[1:], 1):
                line = line.strip()
                
                # Empty line indicates the end of headers
                if not line:
                    body_start = i + 1
                    break
                
                # Parse header
                if ':' in line:
                    header_name, header_value = line.split(':', 1)
                    header_name = header_name.strip()
                    header_value = header_value.strip()
                    headers[header_name] = header_value
            
            self.request_details["headers"] = headers
            
            # Set content type
            if "Content-Type" in headers:
                self.request_details["content_type"] = headers["Content-Type"]
            
            # Extract body
            body = ""
            if body_start > 0 and body_start < len(lines):
                body = '\n'.join(lines[body_start:])
            
            # Extract parameters from URL
            self._extract_url_parameters(self.request_details["url"])
            
            # Extract parameters from body based on content type
            if body and self.request_details["method"] in ["POST", "PUT"]:
                self._extract_body_parameters(body)
            
            # Extract parameters from cookies
            if "Cookie" in headers:
                self._extract_cookie_parameters(headers["Cookie"])
            
            self.logger.info(f"Parsed request: {self.request_details['method']} {self.request_details['url']}")
            self.logger.info(f"Found {len(self.parameters)} parameters")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing HTTP request: {str(e)}")
            return False
    
    def _extract_url_parameters(self, url):
        """
        Extract parameters from URL query string
        
        Args:
            url (str): URL to extract parameters from
        """
        # Split URL into base and query string
        if '?' in url:
            base_url, query_string = url.split('?', 1)
        else:
            base_url, query_string = url, ""
        
        # Parse query parameters
        if query_string:
            try:
                query_params = urllib.parse.parse_qsl(query_string)
                
                for name, value in query_params:
                    self.parameters.append({
                        "name": name,
                        "value": value,
                        "type": "GET",
                        "url": url,
                        "in_url": True,
                        "in_body": False,
                        "in_cookie": False,
                        "enabled": True
                    })
                    
                    self.logger.debug(f"Found URL parameter: {name}={value}")
            
            except Exception as e:
                self.logger.error(f"Error extracting URL parameters: {str(e)}")
    
    def _extract_body_parameters(self, body):
        """
        Extract parameters from request body
        
        Args:
            body (str): Request body content
        """
        content_type = self.request_details.get("content_type", "").lower()
        
        # Handle URL-encoded form data
        if "application/x-www-form-urlencoded" in content_type:
            try:
                form_params = urllib.parse.parse_qsl(body)
                
                for name, value in form_params:
                    self.parameters.append({
                        "name": name,
                        "value": value,
                        "type": self.request_details["method"],
                        "url": self.request_details["url"],
                        "in_url": False,
                        "in_body": True,
                        "in_cookie": False,
                        "enabled": True
                    })
                    
                    self.logger.debug(f"Found form parameter: {name}={value}")
            
            except Exception as e:
                self.logger.error(f"Error extracting form parameters: {str(e)}")
        
        # Handle JSON data
        elif "application/json" in content_type:
            try:
                json_data = json.loads(body)
                
                # Recursively extract JSON parameters
                self._extract_json_parameters(json_data, "")
            
            except Exception as e:
                self.logger.error(f"Error extracting JSON parameters: {str(e)}")
        
        # Handle multipart form data
        elif "multipart/form-data" in content_type:
            # Find boundary in content type
            boundary_match = re.search(r'boundary=([^;]+)', content_type)
            
            if boundary_match:
                boundary = boundary_match.group(1)
                self._extract_multipart_parameters(body, boundary)
        
        # Handle plain text or other formats
        else:
            self.logger.debug(f"Unsupported content type for parameter extraction: {content_type}")
    
    def _extract_json_parameters(self, json_data, prefix):
        """
        Recursively extract parameters from JSON data
        
        Args:
            json_data (dict/list): JSON data
            prefix (str): Prefix for nested parameters
        """
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                # Create parameter name with prefix
                param_name = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, (dict, list)):
                    # Recursive extraction for nested structures
                    self._extract_json_parameters(value, param_name)
                else:
                    # Add leaf parameter
                    self.parameters.append({
                        "name": param_name,
                        "value": str(value),
                        "type": self.request_details["method"],
                        "url": self.request_details["url"],
                        "in_url": False,
                        "in_body": True,
                        "in_cookie": False,
                        "enabled": True,
                        "json_path": param_name
                    })
                    
                    self.logger.debug(f"Found JSON parameter: {param_name}={value}")
        
        elif isinstance(json_data, list):
            # For lists, use index as key
            for i, item in enumerate(json_data):
                param_name = f"{prefix}[{i}]"
                
                if isinstance(item, (dict, list)):
                    self._extract_json_parameters(item, param_name)
                else:
                    self.parameters.append({
                        "name": param_name,
                        "value": str(item),
                        "type": self.request_details["method"],
                        "url": self.request_details["url"],
                        "in_url": False,
                        "in_body": True,
                        "in_cookie": False,
                        "enabled": True,
                        "json_path": param_name
                    })
                    
                    self.logger.debug(f"Found JSON array parameter: {param_name}={item}")
    
    def _extract_multipart_parameters(self, body, boundary):
        """
        Extract parameters from multipart form data
        
        Args:
            body (str): Request body
            boundary (str): Multipart boundary
        """
        # Split body into parts using boundary
        parts = body.split(f"--{boundary}")
        
        for part in parts:
            # Skip empty parts and boundary end marker
            if not part.strip() or part.strip() == "--":
                continue
            
            # Parse part headers
            headers_text, content = part.split("\r\n\r\n", 1) if "\r\n\r\n" in part else (part, "")
            
            # Find content disposition header
            match = re.search(r'Content-Disposition: form-data; name="([^"]+)"', headers_text)
            
            if match:
                name = match.group(1)
                value = content.strip()
                
                self.parameters.append({
                    "name": name,
                    "value": value,
                    "type": self.request_details["method"],
                    "url": self.request_details["url"],
                    "in_url": False,
                    "in_body": True,
                    "in_cookie": False,
                    "enabled": True
                })
                
                self.logger.debug(f"Found multipart parameter: {name}={value}")
    
    def _extract_cookie_parameters(self, cookie_header):
        """
        Extract parameters from cookie header
        
        Args:
            cookie_header (str): Cookie header value
        """
        try:
            cookies = cookie_header.split(';')
            
            for cookie in cookies:
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    name = name.strip()
                    value = value.strip()
                    
                    self.parameters.append({
                        "name": name,
                        "value": value,
                        "type": "COOKIE",
                        "url": self.request_details["url"],
                        "in_url": False,
                        "in_body": False,
                        "in_cookie": True,
                        "enabled": True
                    })
                    
                    self.logger.debug(f"Found cookie parameter: {name}={value}")
        
        except Exception as e:
            self.logger.error(f"Error extracting cookie parameters: {str(e)}")
    
    def load_parameters_from_user_input(self, url, param_str):
        """
        Load parameters from user input string
        
        Args:
            url (str): Target URL
            param_str (str): Parameter string (format: param1=value1&param2=value2)
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        self.logger.info(f"Loading parameters from user input for {url}")
        
        # Reset current parameters
        self.parameters = []
        self.request_details = {
            "headers": {},
            "method": "GET",
            "url": url,
            "content_type": ""
        }
        
        try:
            # Parse parameters from string
            params = urllib.parse.parse_qsl(param_str)
            
            for name, value in params:
                self.parameters.append({
                    "name": name,
                    "value": value,
                    "type": "GET",
                    "url": url,
                    "in_url": True,
                    "in_body": False,
                    "in_cookie": False,
                    "enabled": True
                })
                
                self.logger.debug(f"Added parameter: {name}={value}")
            
            self.logger.info(f"Loaded {len(self.parameters)} parameters from user input")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading parameters from user input: {str(e)}")
            return False
    
    def add_parameter(self, name, value, param_type="GET", enabled=True):
        """
        Add a parameter manually
        
        Args:
            name (str): Parameter name
            value (str): Parameter value
            param_type (str): Parameter type (GET, POST, COOKIE)
            enabled (bool): Whether the parameter is enabled for testing
            
        Returns:
            bool: True if added successfully, False otherwise
        """
        try:
            param_type = param_type.upper()
            
            # Determine parameter location
            in_url = param_type == "GET"
            in_body = param_type == "POST"
            in_cookie = param_type == "COOKIE"
            
            # Add parameter
            self.parameters.append({
                "name": name,
                "value": value,
                "type": param_type,
                "url": self.request_details["url"],
                "in_url": in_url,
                "in_body": in_body,
                "in_cookie": in_cookie,
                "enabled": enabled
            })
            
            self.logger.info(f"Added parameter: {name}={value} ({param_type})")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding parameter: {str(e)}")
            return False
    
    def get_parameter(self, index):
        """
        Get a parameter by index
        
        Args:
            index (int): Parameter index (0-based)
            
        Returns:
            dict: Parameter information or None if not found
        """
        try:
            if 0 <= index < len(self.parameters):
                return self.parameters[index]
            else:
                self.logger.error(f"Parameter index out of range: {index}")
                return None
        except Exception as e:
            self.logger.error(f"Error getting parameter: {str(e)}")
            return None
    
    def set_parameter_value(self, index, value):
        """
        Set a parameter value
        
        Args:
            index (int): Parameter index (0-based)
            value (str): New parameter value
            
        Returns:
            bool: True if set successfully, False otherwise
        """
        try:
            if 0 <= index < len(self.parameters):
                old_value = self.parameters[index]["value"]
                self.parameters[index]["value"] = value
                self.logger.info(f"Changed parameter {self.parameters[index]['name']} value: {old_value} -> {value}")
                return True
            else:
                self.logger.error(f"Parameter index out of range: {index}")
                return False
        except Exception as e:
            self.logger.error(f"Error setting parameter value: {str(e)}")
            return False
    
    def toggle_parameter(self, index):
        """
        Toggle parameter enabled status
        
        Args:
            index (int): Parameter index (0-based)
            
        Returns:
            bool: New enabled status or None if error
        """
        try:
            if 0 <= index < len(self.parameters):
                current_status = self.parameters[index]["enabled"]
                new_status = not current_status
                self.parameters[index]["enabled"] = new_status
                self.logger.info(
                    f"Toggled parameter {self.parameters[index]['name']}: "
                    f"{'Enabled' if new_status else 'Disabled'}"
                )
                return new_status
            else:
                self.logger.error(f"Parameter index out of range: {index}")
                return None
        except Exception as e:
            self.logger.error(f"Error toggling parameter: {str(e)}")
            return None
    
    def get_enabled_parameters(self):
        """
        Get all enabled parameters
        
        Returns:
            list: List of enabled parameters
        """
        return [p for p in self.parameters if p["enabled"]]
    
    def format_parameters_table(self):
        """
        Format parameters as a table for display
        
        Returns:
            str: Formatted table
        """
        if not self.parameters:
            return "No parameters found."
        
        # Create table header
        header = f"\n{Fore.CYAN}{'ID':^5} | {'Name':^20} | {'Value':^30} | {'Type':^10} | {'Enabled':^10}{Style.RESET_ALL}"
        separator = f"{'-' * 5}-+-{'-' * 20}-+-{'-' * 30}-+-{'-' * 10}-+-{'-' * 10}"
        
        # Create table rows
        rows = []
        for i, param in enumerate(self.parameters):
            name = param["name"][:18] + ".." if len(param["name"]) > 20 else param["name"]
            value = param["value"][:28] + ".." if len(param["value"]) > 30 else param["value"]
            enabled = f"{Fore.GREEN}Yes{Style.RESET_ALL}" if param["enabled"] else f"{Fore.RED}No{Style.RESET_ALL}"
            
            row = f"{i + 1:^5} | {name:^20} | {value:^30} | {param['type']:^10} | {enabled:^10}"
            rows.append(row)
        
        # Combine table parts
        table = f"{header}\n{separator}\n" + "\n".join(rows)
        return table
    
    def create_test_payload(self, param_index, payload):
        """
        Create a test payload for a parameter
        
        Args:
            param_index (int): Parameter index
            payload (str): Payload to inject
            
        Returns:
            dict: Test information or None if error
        """
        try:
            if not 0 <= param_index < len(self.parameters):
                self.logger.error(f"Parameter index out of range: {param_index}")
                return None
            
            param = self.parameters[param_index]
            url = param["url"]
            
            # Create test info based on parameter type
            if param["in_url"]:
                # For GET parameters, modify URL
                test_url = self._modify_url_param(url, param["name"], payload)
                return {
                    "method": "GET",
                    "url": test_url,
                    "headers": self.request_details["headers"],
                    "data": None,
                    "cookies": None,
                    "parameter": param["name"],
                    "original_value": param["value"],
                    "payload": payload,
                    "type": param["type"]
                }
            
            elif param["in_body"]:
                # For POST parameters, modify body data
                data = {}
                
                # Add all body parameters with original values
                for p in self.parameters:
                    if p["in_body"]:
                        data[p["name"]] = p["value"]
                
                # Replace target parameter with payload
                data[param["name"]] = payload
                
                return {
                    "method": param["type"],
                    "url": url,
                    "headers": self.request_details["headers"],
                    "data": data,
                    "cookies": None,
                    "parameter": param["name"],
                    "original_value": param["value"],
                    "payload": payload,
                    "type": param["type"]
                }
            
            elif param["in_cookie"]:
                # For cookie parameters, modify cookies
                cookies = {}
                
                # Add all cookie parameters with original values
                for p in self.parameters:
                    if p["in_cookie"]:
                        cookies[p["name"]] = p["value"]
                
                # Replace target parameter with payload
                cookies[param["name"]] = payload
                
                return {
                    "method": "GET",
                    "url": url,
                    "headers": self.request_details["headers"],
                    "data": None,
                    "cookies": cookies,
                    "parameter": param["name"],
                    "original_value": param["value"],
                    "payload": payload,
                    "type": param["type"]
                }
            
            else:
                self.logger.error(f"Unknown parameter type for {param['name']}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error creating test payload: {str(e)}")
            return None
    
    def _modify_url_param(self, url, param_name, value):
        """
        Modify a parameter in a URL
        
        Args:
            url (str): URL to modify
            param_name (str): Parameter name
            value (str): New parameter value
            
        Returns:
            str: Modified URL
        """
        try:
            # Parse URL
            parsed_url = urllib.parse.urlparse(url)
            
            # Parse query string
            query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
            
            # Update parameter
            query_params[param_name] = value
            
            # Rebuild URL
            new_query = urllib.parse.urlencode(query_params)
            
            # Rebuild URL parts
            url_parts = list(parsed_url)
            url_parts[4] = new_query
            
            return urllib.parse.urlunparse(url_parts)
            
        except Exception as e:
            self.logger.error(f"Error modifying URL parameter: {str(e)}")
            return url