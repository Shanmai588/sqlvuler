#!/usr/bin/env python3
"""
Helper functions for SQLVuler
"""

import os
import re
import json
import hashlib
import urllib.parse
from datetime import datetime
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

def extract_url_params(url):
    """
    Extract parameters from a URL
    
    Args:
        url (str): The URL to extract parameters from
        
    Returns:
        dict: Dictionary of parameters
    """
    parsed_url = urlparse(url)
    params = dict(parse_qsl(parsed_url.query))
    return params

def modify_url_param(url, param, value):
    """
    Modify a parameter in the URL
    
    Args:
        url (str): The URL to modify
        param (str): The parameter to modify
        value (str): The new value for the parameter
        
    Returns:
        str: The modified URL
    """
    parsed_url = urlparse(url)
    query_params = dict(parse_qsl(parsed_url.query))
    query_params[param] = value
    
    # Rebuild the URL with the modified parameter
    new_query = urlencode(query_params)
    parts = list(parsed_url)
    parts[4] = new_query
    
    return urlunparse(parts)

def generate_hash(data):
    """
    Generate a hash for the given data
    
    Args:
        data (str): Data to hash
        
    Returns:
        str: Hash of the data
    """
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    
    return hashlib.md5(data.encode()).hexdigest()

def save_to_file(content, filename, directory=None):
    """
    Save content to a file
    
    Args:
        content (str): Content to save
        filename (str): Filename to save to
        directory (str): Directory to save to
        
    Returns:
        str: Path to the saved file
    """
    if directory:
        os.makedirs(directory, exist_ok=True)
        file_path = os.path.join(directory, filename)
    else:
        file_path = filename
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    return file_path

def load_from_file(file_path):
    """
    Load content from a file
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        str: File content
    """
    with open(file_path, 'r') as f:
        return f.read()

def is_valid_url(url):
    """
    Check if a URL is valid
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_timestamp():
    """
    Get a formatted timestamp
    
    Returns:
        str: Formatted timestamp
    """
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def sanitize_filename(filename):
    """
    Sanitize a filename
    
    Args:
        filename (str): Filename to sanitize
        
    Returns:
        str: Sanitized filename
    """
    # Remove invalid characters
    sanitized = re.sub(r'[^\w\-\.]', '_', filename)
    
    # Ensure it's not too long
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    
    return sanitized

def escape_html(text):
    """
    Escape HTML special characters
    
    Args:
        text (str): Text to escape
        
    Returns:
        str: Escaped text
    """
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    
    return "".join(html_escape_table.get(c, c) for c in text)

def unescape_html(text):
    """
    Unescape HTML special characters
    
    Args:
        text (str): Text to unescape
        
    Returns:
        str: Unescaped text
    """
    html_unescape_table = {
        "&amp;": "&",
        "&quot;": '"',
        "&apos;": "'",
        "&gt;": ">",
        "&lt;": "<",
    }
    
    pattern = re.compile("|".join(html_unescape_table.keys()))
    return pattern.sub(lambda m: html_unescape_table[m.group(0)], text)

def url_encode(text):
    """
    URL encode text
    
    Args:
        text (str): Text to encode
        
    Returns:
        str: URL encoded text
    """
    return urllib.parse.quote(text)

def url_decode(text):
    """
    URL decode text
    
    Args:
        text (str): Text to decode
        
    Returns:
        str: URL decoded text
    """
    return urllib.parse.unquote(text)

def is_ip_address(address):
    """
    Check if a string is an IP address
    
    Args:
        address (str): String to check
        
    Returns:
        bool: True if IP address, False otherwise
    """
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    return bool(re.match(ipv4_pattern, address)) or bool(re.match(ipv6_pattern, address))

def parse_cookie_string(cookie_string):
    """
    Parse a cookie string into a dictionary
    
    Args:
        cookie_string (str): Cookie string (format: name1=value1; name2=value2)
        
    Returns:
        dict: Dictionary of cookies
    """
    cookies = {}
    
    if not cookie_string:
        return cookies
    
    for cookie in cookie_string.split(';'):
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            cookies[name.strip()] = value.strip()
    
    return cookies

def parse_header_string(header_string):
    """
    Parse a header string into a dictionary
    
    Args:
        header_string (str): Header string (format: name1=value1; name2=value2)
        
    Returns:
        dict: Dictionary of headers
    """
    headers = {}
    
    if not header_string:
        return headers
    
    for header in header_string.split(';'):
        if '=' in header:
            name, value = header.split('=', 1)
            headers[name.strip()] = value.strip()
    
    return headers
