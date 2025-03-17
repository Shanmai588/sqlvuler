#!/usr/bin/env python3
"""
SQLVuler - SQL Injection Vulnerability Scanner

This tool is created for EDUCATIONAL PURPOSES ONLY. 
The author and users of this tool are not responsible for any misuse or illegal activities.
Always obtain proper authorization before testing any website or application.
"""

__version__ = '1.0.2'
__author__ = 'AduDev'
__description__ = 'SQL Injection Vulnerability Scanner for Educational Purposes'

# Import core modules for easier access
from sqlvuler.core.cli import CLIManager
from sqlvuler.core.config import ConfigManager
from sqlvuler.core.payload_manager import PayloadManager
from sqlvuler.core.parameter_handler import ParameterHandler
from sqlvuler.core.request_handler import RequestHandler
from sqlvuler.core.detection_engine import DetectionEngine
from sqlvuler.core.database_identifier import DatabaseIdentifier
from sqlvuler.core.exploitation_engine import ExploitationEngine