# Network Management Package (NMP)

A distributed network diagnostic and management tool that allows running network tests across multiple machines.

## Features

- Remote command execution with security controls
- Network diagnostics (ping, nmap, curl, etc.)
- PCAP capture capabilities
- MTU discovery
- Active connection monitoring
- Cross-platform support (Windows/Linux)
- Async command execution
- Configurable retry mechanisms
- Comprehensive logging

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/nmp.git
cd nmp
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux:
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure the application:
- Copy `config.ini.example` to `config.ini`
- Update the configuration with your settings
- Set environment variables if needed:
  ```bash
  # Windows PowerShell
  $env:API_KEY="your-secret-key"
  # Linux/Mac
  export API_KEY="your-secret-key"
  ```

## Usage

1. Start the agent on target machines:
```bash
python agent.py
```

2. Run the controller on the main machine:
```bash
python controller.py
```

3. Use the interactive menu to run network diagnostics.

## Security Notes

- Always change the default API key in production
- Use SSL in production environments
- Review and restrict allowed commands as needed
- Run with appropriate privileges (some tests require admin/root)

## Development

- Run tests: `pytest`
- Format code: `black .`
- Type checking: `mypy .`

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
