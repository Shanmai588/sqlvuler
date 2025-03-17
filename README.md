# SQLVuler - SQL Injection Vulnerability Scanner

**DISCLAIMER: EDUCATIONAL PURPOSE ONLY**

This tool is designed for educational purposes only. Use only on systems you have permission to test. Unauthorized scanning of websites or applications is illegal. The author is not responsible for any misuse of this tool.

## Overview

SQLVuler is a comprehensive SQL injection vulnerability scanner with a terminal-like interface. It's designed to help security professionals and students learn about SQL injection vulnerabilities and how to detect them.

![SQLVULER_OVERVIEW](https://raw.githubusercontent.com/shanmai588/sqlvuler/main/assets/sqlvuler.gif)

## Features

- Interactive command-line interface
- Modular and extensible architecture
- Customizable payload system
- Multiple detection techniques:
  - Error-based injection detection
  - Time-based injection detection
  - Boolean-based injection detection
- Database identification and fingerprinting
- Data extraction capabilities
- Comprehensive reporting

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/sqlvuler.git
   cd sqlvuler
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Install the package in development mode:
   ```
   pip install -e .
   ```

## Usage

### Basic Usage

```
python sqlvuler.py
```

This will start the interactive CLI where you can enter commands.


### Interactive Commands

Once in the interactive CLI, you can use various commands:

- `scan <url>` - Start a scan on the specified URL
- `show <component>` - Display information (params, results, etc.)
- `help` - Display help information
- `exit/quit` - Exit the program

## Development

### Setting Up Development Environment

1. Create a virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate
   ```

2. Install development dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Open the project in VS Code:
   ```
   code sqlvuler.code-workspace
   ```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- This tool is inspired by SQLmap and other open-source security tools
- Thanks to the security community for their continuous research on SQL injection vulnerabilities
