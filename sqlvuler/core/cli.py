#!/usr/bin/env python3
"""
Command Line Interface for SQLVuler
Provides an interactive terminal-like interface for the tool
"""

import os
import sys
import cmd
import readline
import shlex
from datetime import datetime

from colorama import Fore, Style, init

from sqlvuler.core.config import ConfigManager
from sqlvuler.core.parameter_handler import ParameterHandler
from sqlvuler.utils.logger import get_logger

# Initialize colorama for cross-platform colored terminal output
init()

class CLIManager(cmd.Cmd):
    """Interactive CLI for SQLVuler"""
    
    intro = ""
    prompt = f"{Fore.CYAN}sqlvuler> {Style.RESET_ALL}"
    doc_header = "Available commands (type help <command>):"
    ruler = "="
    
    def __init__(self, config_manager=None, show_banner=True):
        """
        Initialize the CLI Manager
        
        Args:
            config_manager (ConfigManager): Configuration manager instance
            show_banner (bool): Whether to show the banner on startup
        """
        super().__init__()
        self.logger = get_logger()
        
        # Initialize configuration manager
        self.config_manager = config_manager or ConfigManager()
        
        # Initialize parameter handler from the config manager
        # This creates the correct dependency chain
        parameter_handler = ParameterHandler(self.config_manager)
        self.config_manager.register_handler("parameters", parameter_handler)
        
        # Current module and target tracking
        self.current_module = None
        self.current_target = None
        self.scan_history = []
        self.last_command = None
        
        # Setup command history
        self.history_file = os.path.expanduser("~/.sqlvuler_history")
        
        # Display banner if requested
        if show_banner:
            self._print_banner()
    
    def _print_banner(self):
        """Display the SQLVuler banner"""
        banner = f"""
{Fore.RED}
 ____   ___  _     __     __        _           
/ ___| / _ \| |    \ \   / /   _   | | ___ _ __ 
\___ \| | | | |     \ \ / / | | |  | |/ _ \ '__|
 ___) | |_| | |___   \ V /| |_| |  | |  __/ |   
|____/ \__\_\_____|   \_/  \__,_|  |_|\___|_|   
                                                
{Style.RESET_ALL}
{Fore.YELLOW}Version: 1.0.0{Style.RESET_ALL}
{Fore.YELLOW}Author: Educational Purpose Tool{Style.RESET_ALL}

{Fore.RED}DISCLAIMER: EDUCATIONAL PURPOSE ONLY{Style.RESET_ALL}
This tool is designed for educational purposes only.
Use only on systems you have permission to test.
Unauthorized scanning of websites or applications is illegal.
The author is not responsible for any misuse of this tool.

Type {Fore.GREEN}'help'{Style.RESET_ALL} to see available commands.
Type {Fore.GREEN}'exit'{Style.RESET_ALL} to exit.
"""
        print(banner)
    
    def start(self):
        """Start the interactive CLI"""
        # Try to load command history
        self._load_history()
        
        # Start the command loop
        try:
            self.cmdloop()
        finally:
            # Save command history when exiting
            self._save_history()
    
    def _load_history(self):
        """Load command history from file"""
        try:
            if os.path.exists(self.history_file):
                readline.read_history_file(self.history_file)
                self.logger.debug(f"Loaded command history from {self.history_file}")
        except Exception as e:
            self.logger.debug(f"Could not load command history: {str(e)}")
    
    def _save_history(self):
        """Save command history to file"""
        try:
            readline.write_history_file(self.history_file)
            self.logger.debug(f"Saved command history to {self.history_file}")
        except Exception as e:
            self.logger.debug(f"Could not save command history: {str(e)}")
    
    def emptyline(self):
        """Handle empty line (do nothing)"""
        pass
    
    def default(self, line):
        """Handle unknown commands"""
        self.logger.error(f"Unknown command: {line}")
        print(f"Type {Fore.GREEN}'help'{Style.RESET_ALL} to see available commands.")
    
    def completedefault(self, text, line, begidx, endidx):
        """Default tab completion"""
        return []
    
    def do_exit(self, arg):
        """Exit the application"""
        print(f"\n{Fore.YELLOW}Exiting SQLVuler. Goodbye!{Style.RESET_ALL}")
        return True
    
    def do_quit(self, arg):
        """Exit the application (alias for exit)"""
        return self.do_exit(arg)
    
    def do_EOF(self, arg):
        """Handle Ctrl+D to exit"""
        print()  # Add a newline
        return self.do_exit(arg)
    
    def do_clear(self, arg):
        """
        Clear the screen or parameters
        Usage: clear [params]
        
        Examples:
          clear           - Clear the screen
          clear params    - Clear all parameters
        """
        args = shlex.split(arg)
        
        if not args:
            # Clear the screen
            os.system('cls' if os.name == 'nt' else 'clear')
            return
        
        if args[0].lower() == 'params':
            # Get parameter handler from the config manager
            parameter_handler = self.config_manager.get_handler("parameters")
            
            if not parameter_handler:
                print(f"{Fore.RED}Error: Parameter handler not available{Style.RESET_ALL}")
                return
                
            # Clear parameters
            parameter_handler.parameters = []
            parameter_handler.save_to_config()
            print(f"{Fore.GREEN}Parameters cleared{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Unknown clear target: {args[0]}{Style.RESET_ALL}")
            print(f"Usage: clear [params]")
    
    def do_banner(self, arg):
        """Display the SQLVuler banner"""
        self._print_banner()
    
    def do_history(self, arg):
        """Display command history"""
        history_size = readline.get_current_history_length()
        for i in range(1, history_size + 1):
            cmd = readline.get_history_item(i)
            if cmd:
                print(f"{i}: {cmd}")
    
    def do_load(self, arg):
        """
        Load parameters from a file or URL
        Usage: load <file_path> 
               load url <url> <params>
        
        Examples:
          load request.txt         - Load parameters from HTTP request file
          load url example.com id=1&user=admin - Load parameters from URL and query string
        """
        args = shlex.split(arg)
        if not args:
            print(f"{Fore.RED}Error: Missing file path or URL{Style.RESET_ALL}")
            print(f"Usage: load <file_path> OR load url <url> <params>")
            return
        
        # Get parameter handler from the config manager
        parameter_handler = self.config_manager.get_handler("parameters")
        
        if not parameter_handler:
            print(f"{Fore.RED}Error: Parameter handler not available{Style.RESET_ALL}")
            return
        
        if args[0].lower() == 'url':
            # Load from URL and parameter string
            if len(args) < 3:
                print(f"{Fore.RED}Error: Missing URL or parameters{Style.RESET_ALL}")
                print(f"Usage: load url <url> <params>")
                return
            
            url = args[1]
            params = args[2]
            
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            if parameter_handler.load_parameters_from_user_input(url, params):
                print(f"{Fore.GREEN}Successfully loaded parameters from URL{Style.RESET_ALL}")
                self.current_target = url
                
                # Update target in config
                self.config_manager.set("target.url", url)
                self.config_manager.set("target.method", "GET")
                
                # Save parameters to config
                parameter_handler.save_to_config()
            else:
                print(f"{Fore.RED}Failed to load parameters from URL{Style.RESET_ALL}")
        else:
            # Load from file
            file_path = args[0]
            
            if not os.path.exists(file_path):
                print(f"{Fore.RED}Error: File not found: {file_path}{Style.RESET_ALL}")
                return
            
            if parameter_handler.load_from_file(file_path):
                print(f"{Fore.GREEN}Successfully loaded parameters from {file_path}{Style.RESET_ALL}")
                self.current_target = parameter_handler.request_details.get("url", "")
                
                # Update target in config
                self.config_manager.set("target.url", self.current_target)
                self.config_manager.set("target.method", parameter_handler.request_details.get("method", "GET"))
                
                # Save parameters to config
                parameter_handler.save_to_config()
            else:
                print(f"{Fore.RED}Failed to load parameters from {file_path}{Style.RESET_ALL}")
    
    def do_add(self, arg):
        """
        Add a parameter manually
        Usage: add <n> <value> [type]
        
        Types: GET (default), POST, COOKIE
        
        Examples:
          add id 1            - Add GET parameter 'id' with value '1'
          add password 123 POST - Add POST parameter 'password' with value '123'
        """
        args = shlex.split(arg)
        if len(args) < 2:
            print(f"{Fore.RED}Error: Missing parameter name or value{Style.RESET_ALL}")
            print(f"Usage: add <n> <value> [type]")
            return
        
        # Get parameter handler from the config manager
        parameter_handler = self.config_manager.get_handler("parameters")
        
        if not parameter_handler:
            print(f"{Fore.RED}Error: Parameter handler not available{Style.RESET_ALL}")
            return
        
        name = args[0]
        value = args[1]
        param_type = args[2].upper() if len(args) > 2 else "GET"
        
        if param_type not in ["GET", "POST", "COOKIE"]:
            print(f"{Fore.RED}Error: Invalid parameter type: {param_type}{Style.RESET_ALL}")
            print(f"Valid types: GET, POST, COOKIE")
            return
        
        if not parameter_handler.request_details.get("url"):
            print(f"{Fore.RED}Error: No URL set. Use 'load url <url>' first.{Style.RESET_ALL}")
            return
        
        if parameter_handler.add_parameter(name, value, param_type):
            print(f"{Fore.GREEN}Added parameter: {name}={value} ({param_type}){Style.RESET_ALL}")
            parameter_handler.save_to_config()
        else:
            print(f"{Fore.RED}Failed to add parameter{Style.RESET_ALL}")
    
    def do_set(self, arg):
        """
        Set configuration options or parameter values
        Usage: set <option> <value>
               set param <id> value <value>
               set url <url>
        
        Examples:
          set general.threads 10    - Set configuration option
          set param 1 value admin   - Set parameter value
          set url http://example.com - Set target URL
        """
        args = shlex.split(arg)
        if len(args) < 2:
            print(f"{Fore.RED}Error: Missing parameters{Style.RESET_ALL}")
            print(f"Usage: set <option> <value>")
            return
        
        option = args[0].lower()
        
        if option == 'param':
            # Get parameter handler from the config manager
            parameter_handler = self.config_manager.get_handler("parameters")
            
            if not parameter_handler:
                print(f"{Fore.RED}Error: Parameter handler not available{Style.RESET_ALL}")
                return
                
            # Set parameter value
            if len(args) < 4 or args[2].lower() != 'value':
                print(f"{Fore.RED}Error: Invalid syntax{Style.RESET_ALL}")
                print(f"Usage: set param <id> value <value>")
                return
            
            try:
                param_id = int(args[1]) - 1  # Convert to 0-based index
                new_value = args[3]
                
                if parameter_handler.set_parameter_value(param_id, new_value):
                    print(f"{Fore.GREEN}Parameter value updated{Style.RESET_ALL}")
                    parameter_handler.save_to_config()
                else:
                    print(f"{Fore.RED}Failed to update parameter value{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Error: Parameter ID must be a number{Style.RESET_ALL}")
        
        elif option == 'url':
            # Get parameter handler from the config manager
            parameter_handler = self.config_manager.get_handler("parameters")
            
            if not parameter_handler:
                print(f"{Fore.RED}Error: Parameter handler not available{Style.RESET_ALL}")
                return
                
            # Set URL
            if len(args) < 2:
                print(f"{Fore.RED}Error: Missing URL{Style.RESET_ALL}")
                return
            
            url = args[1]
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            self.current_target = url
            parameter_handler.request_details["url"] = url
            parameter_handler.request_details["method"] = "GET"
            print(f"{Fore.GREEN}Target URL set to: {url}{Style.RESET_ALL}")
            
            # Update target in config
            self.config_manager.set("target.url", url)
            self.config_manager.set("target.method", "GET")
            parameter_handler.save_to_config()
        
        else:
            # Set configuration option
            option = args[0]
            value = args[1]
            
            # Handle special case for boolean values
            if value.lower() in ('true', 'yes', 'on', '1'):
                value = True
            elif value.lower() in ('false', 'no', 'off', '0'):
                value = False
            
            try:
                self.config_manager.set(option, value)
                print(f"{Fore.GREEN}Set {option} = {value}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error setting option: {str(e)}{Style.RESET_ALL}")
    
    def do_get(self, arg):
        """
        Get configuration option value
        Usage: get <option>
        """
        args = shlex.split(arg)
        if not args:
            print(f"{Fore.RED}Error: Missing parameter{Style.RESET_ALL}")
            print(f"Usage: get <option>")
            return
        
        option = args[0]
        
        try:
            value = self.config_manager.get(option)
            print(f"{option} = {value}")
        except Exception as e:
            print(f"{Fore.RED}Error getting option: {str(e)}{Style.RESET_ALL}")
    
    def do_toggle(self, arg):
        """
        Toggle parameter enabled status
        Usage: toggle param <id>
        
        Examples:
          toggle param 1     - Toggle parameter with ID 1
        """
        args = shlex.split(arg)
        if len(args) < 2 or args[0].lower() != 'param':
            print(f"{Fore.RED}Error: Invalid syntax{Style.RESET_ALL}")
            print(f"Usage: toggle param <id>")
            return
        
        # Get parameter handler from the config manager
        parameter_handler = self.config_manager.get_handler("parameters")
        
        if not parameter_handler:
            print(f"{Fore.RED}Error: Parameter handler not available{Style.RESET_ALL}")
            return
            
        try:
            param_id = int(args[1]) - 1  # Convert to 0-based index
            
            new_status = parameter_handler.toggle_parameter(param_id)
            if new_status is not None:
                print(f"{Fore.GREEN}Parameter {'enabled' if new_status else 'disabled'}{Style.RESET_ALL}")
                parameter_handler.save_to_config()
            else:
                print(f"{Fore.RED}Failed to toggle parameter{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Error: Parameter ID must be a number{Style.RESET_ALL}")
    
    def do_show(self, arg):
        """
        Show information about various components
        Usage: show [component]
        
        Components:
          config     - Show current configuration
          options    - Show available options
          modules    - Show available modules
          params     - Show loaded parameters
          results    - Show scan results
          request    - Show current request details
        """
        args = shlex.split(arg)
        if not args:
            print(f"{Fore.RED}Error: Missing component{Style.RESET_ALL}")
            print(f"Usage: show <component>")
            print(f"Type 'help show' for more information.")
            return
        
        component = args[0].lower()
        
        if component == 'config':
            self._show_config()
        elif component == 'options':
            self._show_options()
        elif component == 'modules':
            self._show_modules()
        elif component == 'params':
            self._show_params()
        elif component == 'results':
            self._show_results()
        elif component == 'request':
            self._show_request()
        else:
            print(f"{Fore.RED}Unknown component: {component}{Style.RESET_ALL}")
            print(f"Type 'help show' for more information.")
    
    def _show_config(self):
        """Show current configuration"""
        config = self.config_manager.get_all()
        
        print(f"\n{Fore.GREEN}Current Configuration:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
        
        for section, options in config.items():
            print(f"\n{Fore.CYAN}[{section}]{Style.RESET_ALL}")
            for option, value in options.items():
                print(f"  {option} = {value}")
        
        print(f"\n{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    
    def _show_options(self):
        """Show available options"""
        print(f"\n{Fore.GREEN}Available Options:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
        
        # We'll implement this when we have the options defined
        print(f"{Fore.YELLOW}Not implemented yet.{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    
    def _show_modules(self):
        """Show available modules"""
        print(f"\n{Fore.GREEN}Available Modules:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
        
        # We'll implement this when we have modules defined
        print(f"{Fore.YELLOW}Not implemented yet.{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    
    def _show_params(self):
        """Show detected parameters"""
        print(f"\n{Fore.GREEN}Parameters:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
        
        # Get parameter handler from the config manager
        parameter_handler = self.config_manager.get_handler("parameters")
        
        if parameter_handler and parameter_handler.parameters:
            print(parameter_handler.format_parameters_table())
        else:
            print(f"{Fore.YELLOW}No parameters loaded. Use 'load' to load parameters.{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    
    def _show_results(self):
        """Show scan results"""
        if not self.scan_history:
            print(f"{Fore.RED}No scan results available.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}Scan Results:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
        
        # We'll implement results display later
        print(f"{Fore.YELLOW}Not implemented yet.{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    
    def _show_request(self):
        """Show current request details"""
        # Get parameter handler from the config manager
        parameter_handler = self.config_manager.get_handler("parameters")
        
        if not parameter_handler:
            print(f"{Fore.YELLOW}Parameter handler not available.{Style.RESET_ALL}")
            return
            
        request_details = parameter_handler.request_details
        
        print(f"\n{Fore.GREEN}Request Details:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
        
        if request_details["url"]:
            print(f"{Fore.CYAN}Method:{Style.RESET_ALL} {request_details['method']}")
            print(f"{Fore.CYAN}URL:{Style.RESET_ALL} {request_details['url']}")
            print(f"{Fore.CYAN}Content Type:{Style.RESET_ALL} {request_details['content_type'] or 'Not specified'}")
            
            if request_details["headers"]:
                print(f"\n{Fore.CYAN}Headers:{Style.RESET_ALL}")
                for name, value in request_details["headers"].items():
                    print(f"  {name}: {value}")
        else:
            print(f"{Fore.YELLOW}No request loaded.{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    
    def do_test(self, arg):
        """
        Test a parameter for SQL injection vulnerabilities
        Usage: test param <id> [technique]
        
        Techniques: error (default), boolean, time, all
        
        Examples:
          test param 1        - Test parameter with ID 1 using error-based technique
          test param 2 time   - Test parameter with ID 2 using time-based technique
          test param 3 all    - Test parameter with ID 3 using all techniques
        """
        args = shlex.split(arg)
        if len(args) < 2 or args[0].lower() != 'param':
            print(f"{Fore.RED}Error: Invalid syntax{Style.RESET_ALL}")
            print(f"Usage: test param <id> [technique]")
            return
        
        # Get parameter handler from the config manager
        parameter_handler = self.config_manager.get_handler("parameters")
        
        if not parameter_handler:
            print(f"{Fore.RED}Error: Parameter handler not available{Style.RESET_ALL}")
            return
            
        try:
            param_id = int(args[1]) - 1  # Convert to 0-based index
            technique = args[2].lower() if len(args) > 2 else "error"
            
            if technique not in ["error", "boolean", "time", "all"]:
                print(f"{Fore.RED}Error: Invalid technique: {technique}{Style.RESET_ALL}")
                print(f"Valid techniques: error, boolean, time, all")
                return
            
            # Get parameter
            param = parameter_handler.get_parameter(param_id)
            if not param:
                print(f"{Fore.RED}Parameter not found with ID: {param_id + 1}{Style.RESET_ALL}")
                return
            
            print(f"{Fore.GREEN}Testing parameter: {param['name']} ({param['type']}) with technique: {technique}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}This functionality will be implemented in Phase 3.{Style.RESET_ALL}")
            
            # Add to scan history
            self.scan_history.append({
                'parameter': param['name'],
                'technique': technique,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'pending'
            })
        except ValueError:
            print(f"{Fore.RED}Error: Parameter ID must be a number{Style.RESET_ALL}")
    
    def do_scan(self, arg):
        """
        Start a scan on the target with current parameters
        Usage: scan [technique]
        
        Techniques: error (default), boolean, time, union, all
        
        Examples:
          scan          - Scan using error-based technique
          scan time     - Scan using time-based technique
          scan all      - Scan using all techniques
        """
        args = shlex.split(arg)
        technique = args[0].lower() if args else "error"
        
        if technique not in ["error", "boolean", "time", "union", "all"]:
            print(f"{Fore.RED}Error: Invalid technique: {technique}{Style.RESET_ALL}")
            print(f"Valid techniques: error, boolean, time, union, all")
            return
        
        # Get parameter handler from the config manager
        parameter_handler = self.config_manager.get_handler("parameters")
        
        if not parameter_handler:
            print(f"{Fore.RED}Error: Parameter handler not available{Style.RESET_ALL}")
            return
            
        # Check if we have parameters to test
        enabled_params = parameter_handler.get_enabled_parameters()
        if not enabled_params:
            print(f"{Fore.RED}No enabled parameters to test. Use 'load' to load parameters.{Style.RESET_ALL}")
            return
        
        # Check if we have a target URL
        if not parameter_handler.request_details.get("url"):
            print(f"{Fore.RED}No target URL set. Use 'load url <url>' or 'set url <url>'.{Style.RESET_ALL}")
            return
        
        # Get detection engine
        detection_engine = self._get_detection_engine()
        if not detection_engine:
            print(f"{Fore.RED}Error: Could not initialize detection engine{Style.RESET_ALL}")
            return
        
        # Set techniques to test
        techniques_to_test = ["error", "boolean", "time", "union"] if technique == "all" else [technique]
        
        print(f"\n{Fore.GREEN}Starting scan on {parameter_handler.request_details['url']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Testing {len(enabled_params)} parameters with technique(s): {', '.join(techniques_to_test)}{Style.RESET_ALL}")
        
        # Perform the scan
        scan_result = detection_engine.scan_parameters(enabled_params, techniques_to_test)
        
        # Display results summary
        if scan_result["vulnerable"]:
            print(f"\n{Fore.GREEN}SQL Injection vulnerabilities found in {len(scan_result['vulnerable_params'])} parameter(s)!{Style.RESET_ALL}")
            
            for vuln in scan_result["vulnerable_params"]:
                print(f"{Fore.CYAN}Parameter: {vuln['parameter']} ({vuln['type']}){Style.RESET_ALL}")
                print(f"{Fore.CYAN}Technique: {vuln['technique']}{Style.RESET_ALL}")
                
                if vuln.get('payload'):
                    print(f"{Fore.CYAN}Payload: {vuln['payload']}{Style.RESET_ALL}")
                
                print()
        else:
            print(f"\n{Fore.YELLOW}No SQL Injection vulnerabilities found.{Style.RESET_ALL}")
        
        # Generate and display report
        report = detection_engine.generate_report(scan_result)
        print("\nDetailed scan report:")
        print(report)
        
        # Add to scan history
        self.scan_history.append({
            'url': parameter_handler.request_details['url'],
            'parameters': len(enabled_params),
            'technique': technique,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'completed',
            'vulnerable': scan_result["vulnerable"],
            'vulnerable_count': len(scan_result['vulnerable_params'])
        })
    
    def do_exploit(self, arg):
        """
        Exploit a vulnerable parameter to extract database information
        Usage: exploit param <id>
        
        Examples:
          exploit param 1     - Exploit parameter with ID 1
        """
        args = shlex.split(arg)
        if len(args) < 2 or args[0].lower() != 'param':
            print(f"{Fore.RED}Error: Invalid syntax{Style.RESET_ALL}")
            print(f"Usage: exploit param <id>")
            return
        
        # Get parameter handler from the config manager
        parameter_handler = self.config_manager.get_handler("parameters")
        
        if not parameter_handler:
            print(f"{Fore.RED}Error: Parameter handler not available{Style.RESET_ALL}")
            return
            
        try:
            param_id = int(args[1]) - 1  # Convert to 0-based index
            
            # Get parameter
            param = parameter_handler.get_parameter(param_id)
            if not param:
                print(f"{Fore.RED}Parameter not found with ID: {param_id + 1}{Style.RESET_ALL}")
                return
            
            print(f"{Fore.GREEN}Exploiting parameter: {param['name']} ({param['type']}){Style.RESET_ALL}")
            
            # Get detection engine
            detection_engine = self._get_detection_engine()
            if not detection_engine:
                print(f"{Fore.RED}Error: Could not initialize detection engine{Style.RESET_ALL}")
                return
            
            # Exploit the parameter
            exploit_result = detection_engine.exploit_parameter(param)
            
            # Check for errors
            if exploit_result.get("error"):
                print(f"{Fore.RED}Error: {exploit_result['error']}{Style.RESET_ALL}")
                return
            
            # Display report
            if exploit_result.get("report"):
                print("\nExploitation Report:")
                print(exploit_result["report"])
        except ValueError:
            print(f"{Fore.RED}Error: Parameter ID must be a number{Style.RESET_ALL}")
    
    def do_save_report(self, arg):
        """
        Save a vulnerability report to a file
        Usage: save_report <filename>
        
        Examples:
          save_report vuln_report.txt     - Save report to vuln_report.txt
        """
        args = shlex.split(arg)
        if not args:
            print(f"{Fore.RED}Error: Missing filename{Style.RESET_ALL}")
            print(f"Usage: save_report <filename>")
            return
        
        filename = args[0]
        
        # Get detection engine
        detection_engine = self._get_detection_engine()
        if not detection_engine:
            print(f"{Fore.RED}Error: Could not initialize detection engine{Style.RESET_ALL}")
    
    def do_test(self, arg):
        """
        Test a parameter for SQL injection vulnerabilities
        Usage: test param <id> [technique]
        
        Techniques: error (default), boolean, time, union, all
        
        Examples:
          test param 1        - Test parameter with ID 1 using error-based technique
          test param 2 time   - Test parameter with ID 2 using time-based technique
          test param 3 all    - Test parameter with ID 3 using all techniques
        """
        args = shlex.split(arg)
        if len(args) < 2 or args[0].lower() != 'param':
            print(f"{Fore.RED}Error: Invalid syntax{Style.RESET_ALL}")
            print(f"Usage: test param <id> [technique]")
            return
        
        # Get parameter handler from the config manager
        parameter_handler = self.config_manager.get_handler("parameters")
        
        if not parameter_handler:
            print(f"{Fore.RED}Error: Parameter handler not available{Style.RESET_ALL}")
            return
            
        try:
            param_id = int(args[1]) - 1  # Convert to 0-based index
            technique = args[2].lower() if len(args) > 2 else "error"
            
            if technique not in ["error", "boolean", "time", "union", "all"]:
                print(f"{Fore.RED}Error: Invalid technique: {technique}{Style.RESET_ALL}")
                print(f"Valid techniques: error, boolean, time, union, all")
                return
            
            # Get parameter
            param = parameter_handler.get_parameter(param_id)
            if not param:
                print(f"{Fore.RED}Parameter not found with ID: {param_id + 1}{Style.RESET_ALL}")
                return
            
            print(f"{Fore.GREEN}Testing parameter: {param['name']} ({param['type']}) with technique: {technique}{Style.RESET_ALL}")
            
            # Get detection engine
            detection_engine = self._get_detection_engine()
            if not detection_engine:
                print(f"{Fore.RED}Error: Could not initialize detection engine{Style.RESET_ALL}")
                return
            
            # Test the parameter
            techniques_to_test = ["error", "boolean", "time", "union"] if technique == "all" else [technique]
            
            result = detection_engine.scan_parameter(param, techniques_to_test)
            
            # Display results
            if result["vulnerable"]:
                print(f"\n{Fore.GREEN}SQL Injection vulnerability found!{Style.RESET_ALL}")
                
                # Find the successful technique
                for tech, tech_result in result.get("details", {}).items():
                    if tech_result.get("vulnerable"):
                        print(f"{Fore.CYAN}Detected using {tech}-based technique{Style.RESET_ALL}")
                        
                        # Display successful payload if available
                        successful_payloads = tech_result.get("successful_payloads", [])
                        if successful_payloads:
                            payload = successful_payloads[0].get("payload", "")
                            print(f"{Fore.CYAN}Payload: {payload}{Style.RESET_ALL}")
                        
                        # Display evidence if available
                        evidence = tech_result.get("evidence")
                        if evidence:
                            print(f"{Fore.CYAN}Evidence: {evidence}{Style.RESET_ALL}")
                        
                        break
            else:
                print(f"\n{Fore.YELLOW}No SQL Injection vulnerability found.{Style.RESET_ALL}")
            
            # Add to scan history
            self.scan_history.append({
                'parameter': param['name'],
                'technique': technique,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'completed',
                'vulnerable': result["vulnerable"]
            })
        except ValueError:
            print(f"{Fore.RED}Error: Parameter ID must be a number{Style.RESET_ALL}")
    
    def _get_detection_engine(self):
        """Get or create a detection engine instance"""
        try:
            # Import here to avoid circular imports
            from sqlvuler.core.detection_engine import DetectionEngine
            from sqlvuler.core.payload_manager import PayloadManager
            
            # Create payload manager if needed
            payload_manager = PayloadManager(self.config_manager)
            
            # Create detection engine
            detection_engine = DetectionEngine(self.config_manager, payload_manager)
            
            return detection_engine
        except Exception as e:
            self.logger.error(f"Error creating detection engine: {str(e)}")
            return None
    
    def do_use(self, arg):
        """
        Select a module to use
        Usage: use <module>
        """
        args = shlex.split(arg)
        if not args:
            print(f"{Fore.RED}Error: Missing module{Style.RESET_ALL}")
            print(f"Usage: use <module>")
            return
        
        module = args[0]
        
        # We'll implement module selection later
        print(f"\n{Fore.GREEN}Selected module: {module}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This functionality will be implemented in Phase 3.{Style.RESET_ALL}")
        
        self.current_module = module
    
    def do_back(self, arg):
        """Return to the main menu from a module"""
        if not self.current_module:
            print(f"{Fore.YELLOW}Already at the main menu.{Style.RESET_ALL}")
            return
        
        self.current_module = None
        print(f"{Fore.GREEN}Returned to main menu.{Style.RESET_ALL}")
    
    def do_help(self, arg):
        """Show help information"""
        # Override the default help command
        super().do_help(arg)