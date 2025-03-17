#!/usr/bin/env python3
"""
SQLVuler - SQL Injection Vulnerability Scanner

This tool is created for EDUCATIONAL PURPOSES ONLY. 
The author of this tool are not responsible for any misuse or illegal activities.
Always obtain proper authorization before testing any website or application.
"""

import sys
import os
import argparse

# Add the parent directory to the path for importing modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlvuler.core.cli import CLIManager
from sqlvuler.core.config import ConfigManager
from sqlvuler.utils.logger import setup_logger

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="SQLVuler - SQL Injection Vulnerability Scanner (Educational Purpose Only)"
    )
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("--no-banner", help="Don't display the banner", action="store_true")
    
    return parser.parse_args()

def main():
    """Main entry point for SQLVuler"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Setup logger
    logger = setup_logger(verbose=args.verbose)
    
    try:
        # Load configuration
        config_manager = ConfigManager(config_path=args.config)
        
        # Start the CLI
        cli = CLIManager(config_manager=config_manager, show_banner=not args.no_banner)
        cli.start()
        
    except KeyboardInterrupt:
        logger.info("\nExiting SQLVuler. Have A Good Day!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
