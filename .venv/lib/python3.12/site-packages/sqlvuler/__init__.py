#!/usr/bin/env python3
"""
SQLVuler - SQL Injection Vulnerability Scanner

This tool is created for EDUCATIONAL PURPOSES ONLY. 
The author and users of this tool are not responsible for any misuse or illegal activities.
Always obtain proper authorization before testing any website or application.
"""

__version__ = '1.0.0'
__author__ = 'AduDev'
__description__ = 'SQL Injection Vulnerability Scanner Reporter for Educational Purposes'

# Import core modules for easier access
from sqlvuler.core.cli import CLIManager
from sqlvuler.core.config import ConfigManager
from sqlvuler.core.payload_manager import PayloadManager