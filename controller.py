# controller.py - To be run by you on VM1
# You would need to install requests: pip install requests

import requests
import json
import os
import logging
from typing import List, Dict, Any, Optional
import configparser
from pathlib import Path
import asyncio
import aiohttp
from utils import setup_logging, is_valid_ip_or_domain

# Setup logging
setup_logging()

class ConfigurationError(Exception):
    """Raised when there's an error in configuration"""
    pass

class CommandError(Exception):
    """Raised when there's an error executing a command"""
    pass

class Controller:
    def __init__(self, config_file: str = 'config.ini'):
        self.config = self._load_config(config_file)
        self.api_key = os.getenv('API_KEY', self.config.get('DEFAULT', 'API_KEY'))
        self.timeout = self.config.getint('DEFAULT', 'COMMAND_TIMEOUT', fallback=60)
        self.max_retries = self.config.getint('DEFAULT', 'MAX_RETRIES', fallback=3)
        
        # Load VMs from config
        self.target_vms = {
            vm_name: vm_ip
            for vm_name, vm_ip in self.config.items('VMS')
        }
        
        # Track registered agents
        self.registered_agents: Dict[str, Dict[str, Any]] = {}

    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        """Load and validate configuration"""
        if not Path(config_file).exists():
            raise ConfigurationError(f"Configuration file {config_file} not found")
            
        config = configparser.ConfigParser()
        config.read(config_file)
        
        required_sections = ['DEFAULT', 'VMS']
        for section in required_sections:
            if not config.has_section(section) and section != 'DEFAULT':
                raise ConfigurationError(f"Missing required section {section}")
                
        return config

    async def send_command_async(
        self,
        vm_name: str,
        command: List[str],
        attempt: int = 1
    ) -> Dict[str, Any]:
        """
        Send a command to a VM asynchronously with retries.
        
        Args:
            vm_name: Name of the target VM
            command: Command to execute as list of strings
            attempt: Current retry attempt number
            
        Returns:
            Dict containing command execution results
            
        Raises:
            CommandError: If command execution fails after all retries
        """
        if vm_name not in self.target_vms:
            raise CommandError(f"Unknown VM: {vm_name}")

        vm_ip = self.target_vms[vm_name]
        agent_url = f"http://{vm_ip}:5000/run-test"
        headers = {'Authorization': f'Bearer {self.api_key}'}
        payload = {'command': command}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    agent_url,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout
                ) as response:
                    response.raise_for_status()
                    result = await response.json()
                    
                    logging.info(f"Command executed successfully on {vm_name}")
                    return {
                        'vm_name': vm_name,
                        'success': True,
                        'result': result
                    }

        except aiohttp.ClientError as e:
            error_msg = f"Failed to communicate with agent on {vm_name}: {str(e)}"
            if attempt < self.max_retries:
                logging.warning(f"{error_msg} Retrying ({attempt}/{self.max_retries})...")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                return await self.send_command_async(vm_name, command, attempt + 1)
            else:
                raise CommandError(error_msg)

    async def send_bulk_commands_async(
        self,
        vm_name: str,
        commands: List[List[str]]
    ) -> List[Dict[str, Any]]:
        """
        Send multiple commands to a VM asynchronously.
        
        Args:
            vm_name: Name of the target VM
            commands: List of commands to execute
            
        Returns:
            List of command execution results
        """
        tasks = [
            self.send_command_async(vm_name, command)
            for command in commands
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def format_results(self, results: List[Dict[str, Any]]) -> None:
        """Format and print command execution results"""
        for result in results:
            if isinstance(result, Exception):
                print(f"[-] Error: {str(result)}")
                continue
                
            vm_name = result['vm_name']
            cmd_result = result['result']
            
            print(f"\n=== Results from {vm_name} ===")
            print("STDOUT:")
            print(cmd_result.get('stdout', ''))
            print("\nSTDERR:")
            print(cmd_result.get('stderr', ''))
            print(f"Return Code: {cmd_result.get('return_code')}")
            print("=" * 40)

    def validate_command(self, command: List[str]) -> bool:
        """
        Validate a command before execution.
        
        Args:
            command: Command as list of strings
            
        Returns:
            bool: True if command is valid, False otherwise
        """
        if not command or not isinstance(command, list):
            return False
            
        # Add additional command validation logic here
        # For example, checking for dangerous commands, etc.
        
        return True

async def main():
    """Main entry point for the controller"""
    controller = Controller()
    
    # Get target VM
    while True:
        print("\nAvailable VMs:", list(controller.target_vms.keys()))
        target_vm = input("Choose a target VM: ").strip().lower()
        if target_vm in controller.target_vms:
            break
        print("[-] Invalid VM name")
    
    # Example commands
    commands = [
        ["ping", "-n" if os.name == "windows" else "-c", "4", "google.com"],
        ["whoami"],
        ["systeminfo" if os.name == "windows" else "uname -a"]
    ]
    
    try:
        # Execute commands
        results = await controller.send_bulk_commands_async(target_vm, commands)
        
        # Print results
        controller.format_results(results)
        
    except Exception as e:
        logging.error(f"Error executing commands: {str(e)}")

if __name__ == '__main__':
    asyncio.run(main())