#!/usr/bin/env python3
"""
Detection Engine for SQLVuler
Coordinates SQL injection detection and testing
"""

import time
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

from sqlvuler.utils.logger import get_logger
from sqlvuler.core.request_handler import RequestHandler
from sqlvuler.core.database_identifier import DatabaseIdentifier
from sqlvuler.core.exploitation_engine import ExploitationEngine

class DetectionEngine:
    """Core SQL injection detection engine"""
    
    def __init__(self, config_manager=None, payload_manager=None):
        """
        Initialize the Detection Engine
        
        Args:
            config_manager: Configuration manager instance
            payload_manager: Payload manager instance
        """
        self.logger = get_logger()
        self.config_manager = config_manager
        self.payload_manager = payload_manager
        
        # Create request handler
        self.request_handler = RequestHandler(config_manager, payload_manager)
        
        # Create database identifier
        self.db_identifier = DatabaseIdentifier(config_manager, self.request_handler)
        
        # Create exploitation engine
        self.exploitation_engine = ExploitationEngine(config_manager, self.request_handler, payload_manager)
        
        # Default configuration
        self.threads = 5
        self.techniques = ["error", "boolean", "time", "union"]
        self.detection_level = "medium"
        self.risk_level = "medium"
        
        # Load configuration if provided
        if self.config_manager:
            self._load_config()
        
        # Keep track of results
        self.vulnerable_params = []
        self.scan_results = {}
    
    def _load_config(self):
        """Load configuration from the config manager"""
        try:
            # Load scanner configuration
            if self.config_manager.get("general.threads"):
                self.threads = self.config_manager.get("general.threads")
            
            if self.config_manager.get("scanner.techniques"):
                self.techniques = self.config_manager.get("scanner.techniques")
            
            if self.config_manager.get("scanner.detection_level"):
                self.detection_level = self.config_manager.get("scanner.detection_level")
            
            if self.config_manager.get("scanner.risk_level"):
                self.risk_level = self.config_manager.get("scanner.risk_level")
            
            self.logger.debug("Loaded detection engine configuration")
        except Exception as e:
            self.logger.error(f"Error loading detection engine configuration: {str(e)}")
    
    def scan_parameter(self, parameter, techniques=None):
        """
        Scan a parameter for SQL injection vulnerabilities
        
        Args:
            parameter (dict): Parameter to test
            techniques (list): List of techniques to use
            
        Returns:
            dict: Scan results
        """
        # Skip disabled parameters
        if not parameter.get("enabled", True):
            return {"parameter": parameter["name"], "vulnerable": False, "reason": "Parameter is disabled"}
        
        # Use provided techniques or default
        if not techniques:
            techniques = self.techniques
        
        self.logger.info(f"Scanning parameter: {parameter['name']} using techniques: {', '.join(techniques)}")
        
        # Test parameter with each technique
        results = {}
        
        for technique in techniques:
            # Test the parameter
            technique_result = self.request_handler.test_parameter(parameter, technique)
            results[technique] = technique_result
            
            # Stop if we found a vulnerability
            if technique_result["vulnerable"]:
                self.logger.info(f"Vulnerability found using {technique}-based technique")
                
                # Add to vulnerable parameters list
                self.vulnerable_params.append({
                    "parameter": parameter["name"],
                    "type": parameter.get("type", "GET"),
                    "technique": technique,
                    "payload": technique_result.get("successful_payloads", [{}])[0].get("payload", ""),
                    "database_type": technique_result.get("database_type", "Unknown")
                })
                
                # No need to test other techniques
                break
        
        # Combine results
        combined_result = {
            "parameter": parameter["name"],
            "type": parameter.get("type", "GET"),
            "vulnerable": any(results[t]["vulnerable"] for t in techniques if t in results),
            "techniques_tested": list(results.keys()),
            "details": results
        }
        
        # Add to scan results
        self.scan_results[parameter["name"]] = combined_result
        
        return combined_result
    
    def scan_parameters(self, parameters, techniques=None, threads=None):
        """
        Scan multiple parameters for SQL injection vulnerabilities
        
        Args:
            parameters (list): List of parameters to test
            techniques (list): List of techniques to use
            threads (int): Number of threads to use
            
        Returns:
            dict: Scan results
        """
        # Reset results
        self.vulnerable_params = []
        self.scan_results = {}
        
        # Use provided values or defaults
        if not techniques:
            techniques = self.techniques
        
        if not threads:
            threads = self.threads
        
        # Filter out disabled parameters
        enabled_params = [p for p in parameters if p.get("enabled", True)]
        
        if not enabled_params:
            self.logger.warning("No enabled parameters to test")
            return {"vulnerable": False, "parameters_tested": 0, "vulnerable_params": []}
        
        self.logger.info(f"Scanning {len(enabled_params)} parameters using techniques: {', '.join(techniques)}")
        
        start_time = time.time()
        
        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit scanning tasks
            future_to_param = {
                executor.submit(self.scan_parameter, param, techniques): param
                for param in enabled_params
            }
            
            # Process results as they complete
            for future in future_to_param:
                param = future_to_param[future]
                try:
                    result = future.result()
                    if result["vulnerable"]:
                        self.logger.info(
                            f"{Fore.GREEN}Vulnerability found in parameter '{param['name']}' "
                            f"({param.get('type', 'GET')}){Style.RESET_ALL}"
                        )
                except Exception as e:
                    self.logger.error(f"Error scanning parameter '{param['name']}': {str(e)}")
        
        elapsed_time = time.time() - start_time
        
        # Prepare summary results
        summary = {
            "vulnerable": len(self.vulnerable_params) > 0,
            "parameters_tested": len(enabled_params),
            "vulnerable_params": self.vulnerable_params,
            "elapsed_time": elapsed_time,
            "results": self.scan_results
        }
        
        self.logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
        self.logger.info(f"Parameters tested: {len(enabled_params)}")
        self.logger.info(f"Vulnerable parameters found: {len(self.vulnerable_params)}")
        
        return summary
    
    def exploit_parameter(self, parameter):
        """
        Exploit a vulnerable parameter to extract database information
        
        Args:
            parameter (dict): Vulnerable parameter
            
        Returns:
            dict: Exploitation results
        """
        self.logger.info(f"Exploiting parameter: {parameter['name']}")
        
        # Check if parameter is vulnerable
        if parameter["name"] not in [p["parameter"] for p in self.vulnerable_params]:
            # Test the parameter first
            scan_result = self.scan_parameter(parameter)
            if not scan_result["vulnerable"]:
                self.logger.warning(f"Parameter '{parameter['name']}' is not vulnerable, cannot exploit")
                return {"error": "Parameter is not vulnerable"}
        
        # Use exploitation engine to dump database
        dump_result = self.exploitation_engine.dump_database(parameter)
        
        # Generate report
        report = self.exploitation_engine.generate_report(parameter, dump_result)
        
        return {
            "parameter": parameter["name"],
            "dump_result": dump_result,
            "report": report
        }
    
    def generate_report(self, scan_result=None):
        """
        Generate a comprehensive detection report
        
        Args:
            scan_result (dict): Scan results
            
        Returns:
            str: Formatted report
        """
        if not scan_result and not self.scan_results:
            return "No scan results available."
        
        # Use provided scan result or current results
        if not scan_result:
            scan_result = {
                "vulnerable": len(self.vulnerable_params) > 0,
                "parameters_tested": len(self.scan_results),
                "vulnerable_params": self.vulnerable_params,
                "results": self.scan_results
            }
        
        # Format the report
        report = f"""
{Fore.RED}SQLVuler Detection Report{Style.RESET_ALL}
{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}

{Fore.CYAN}Scan Summary:{Style.RESET_ALL}
  Parameters Tested: {scan_result['parameters_tested']}
  Vulnerable Parameters Found: {len(scan_result['vulnerable_params'])}
  Elapsed Time: {scan_result.get('elapsed_time', 0):.2f} seconds

"""
        
        if scan_result["vulnerable"]:
            report += f"{Fore.CYAN}Vulnerable Parameters:{Style.RESET_ALL}\n"
            
            for vuln in scan_result["vulnerable_params"]:
                report += f"  - {vuln['parameter']} ({vuln['type']})\n"
                report += f"    Technique: {vuln['technique']}\n"
                report += f"    Database Type: {vuln['database_type']}\n"
                if vuln.get('payload'):
                    report += f"    Payload: {vuln['payload']}\n"
                report += "\n"
        else:
            report += f"{Fore.GREEN}No SQL injection vulnerabilities were detected.{Style.RESET_ALL}\n"
        
        # Add detailed results section
        if scan_result.get("results"):
            report += f"\n{Fore.CYAN}Detailed Results:{Style.RESET_ALL}\n"
            
            for param_name, result in scan_result["results"].items():
                report += f"  Parameter: {param_name} ({result['type']})\n"
                report += f"  Vulnerable: {result['vulnerable']}\n"
                report += f"  Techniques Tested: {', '.join(result['techniques_tested'])}\n"
                
                if result["vulnerable"]:
                    # Find the technique that discovered the vulnerability
                    for technique, tech_result in result.get("details", {}).items():
                        if tech_result.get("vulnerable"):
                            report += f"  Detected By: {technique}-based technique\n"
                            break
                
                report += "\n"
        
        # Add remediation advice
        report += f"""
{Fore.CYAN}Remediation Advice:{Style.RESET_ALL}
  1. Use parameterized queries or prepared statements
  2. Apply input validation and sanitization
  3. Implement proper error handling to avoid exposing database errors
  4. Apply the principle of least privilege to database users
  5. Consider using an ORM (Object-Relational Mapping) framework

{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}
{Fore.RED}EDUCATIONAL PURPOSE ONLY - DO NOT USE FOR UNAUTHORIZED TESTING{Style.RESET_ALL}
"""
        
        return report
    
    def reset(self):
        """Reset detection engine"""
        self.vulnerable_params = []
        self.scan_results = {}
        self.request_handler.clear_cache()
        self.request_handler.reset_results()
        self.exploitation_engine.reset()