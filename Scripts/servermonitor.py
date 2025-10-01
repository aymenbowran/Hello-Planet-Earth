#!/usr/bin/env python3
"""
server health monitor with ping, port, and http checks, with optional email alerts.
This script is great for small to medium setups where you want basic preventive monitoring with email alerts and logging, pretty neat. (I love waking up at 3 am to fix a server issue because I got an alert, don't you?)

You might think, why not use existing tools like Nagios, Zabbix, or Prometheus? Well, those are great for large-scale deployments, but sometimes you just need a simple, lightweight script to keep an eye on a few critical servers without the overhead of a full monitoring stack. Plus, it's a fun project to build and customize..
Also..... make sure you don't forget to consider using env's instead of the e-mail password in the script + a json obviously (NO, I WON'T SHARE MY JSON!!!, there's plenty of examples online..)

Aymen
"""

import socket
import subprocess
import platform
import time
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import logging
import argparse
import requests


def setup_logging(log_file: Optional[str] = None) -> None:
    """Configure logging for the application."""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=handlers
    )


class ServerMonitor:
    """Monitor server health through various checks."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the server monitor.
        
        Args:
            config_path: Path to JSON configuration file
        """
        self.servers: List[Dict] = []
        self.status_history: Dict[str, List[Dict]] = {}
        self.alert_config: Dict = {}
        
        if config_path and config_path.exists():
            self.load_config(config_path)
    
    def load_config(self, config_path: Path) -> None:
        """
        Load configuration from JSON file.
        
        Expected format:
        {
            "servers": [
                {
                    "name": "Web Server",
                    "host": "example.com",
                    "checks": ["ping", "http"],
                    "http_url": "https://example.com/health",
                    "port": 80
                }
            ],
            "alerts": {
                "enabled": true,
                "email": {
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "sender": "alerts@example.com",
                    "password": "your_password",
                    "recipients": ["admin@example.com"]
                }
            }
        }
        """
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            self.servers = config.get('servers', [])
            self.alert_config = config.get('alerts', {})
            
            logging.info(f"Loaded configuration for {len(self.servers)} servers")
        
        except Exception as e:
            logging.error(f"Error loading config: {e}")
    
    def ping_server(self, host: str, timeout: int = 5) -> Dict:
        """
        Ping a server to check if it's reachable.
        
        Args:
            host: Hostname or IP address
            timeout: Timeout in seconds
        
        Returns:
            Dict with status and response time
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W' if platform.system().lower() != 'windows' else '-w', 
                   str(timeout * 1000) if platform.system().lower() == 'windows' else str(timeout), host]
        
        try:
            start_time = time.time()
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout + 1
            )
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            return {
                'status': 'up' if result.returncode == 0 else 'down',
                'response_time': round(response_time, 2),
                'check_type': 'ping'
            }
        
        except subprocess.TimeoutExpired:
            return {
                'status': 'timeout',
                'response_time': None,
                'check_type': 'ping'
            }
        except Exception as e:
            return {
                'status': 'error',
                'response_time': None,
                'check_type': 'ping',
                'error': str(e)
            }
    
    def check_port(self, host: str, port: int, timeout: int = 5) -> Dict:
        """
        Check if a specific port is open on a server.
        
        Args:
            host: Hostname or IP address
            port: Port number to check
            timeout: Timeout in seconds
        
        Returns:
            Dict with status and response time
        """
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            response_time = (time.time() - start_time) * 1000
            sock.close()
            
            return {
                'status': 'open' if result == 0 else 'closed',
                'response_time': round(response_time, 2),
                'check_type': 'port',
                'port': port
            }
        
        except socket.gaierror:
            return {
                'status': 'error',
                'response_time': None,
                'check_type': 'port',
                'port': port,
                'error': 'DNS resolution failed'
            }
        except Exception as e:
            return {
                'status': 'error',
                'response_time': None,
                'check_type': 'port',
                'port': port,
                'error': str(e)
            }
    
    def check_http(self, url: str, timeout: int = 10) -> Dict:
        """
        Check HTTP/HTTPS endpoint availability.
        
        Args:
            url: Full URL to check
            timeout: Timeout in seconds
        
        Returns:
            Dict with status, status code, and response time
        """
        try:
            start_time = time.time()
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            response_time = (time.time() - start_time) * 1000
            
            return {
                'status': 'up' if response.status_code < 400 else 'down',
                'status_code': response.status_code,
                'response_time': round(response_time, 2),
                'check_type': 'http'
            }
        
        except requests.exceptions.Timeout:
            return {
                'status': 'timeout',
                'status_code': None,
                'response_time': None,
                'check_type': 'http'
            }
        except Exception as e:
            return {
                'status': 'error',
                'status_code': None,
                'response_time': None,
                'check_type': 'http',
                'error': str(e)
            }
    
    def check_server(self, server_config: Dict) -> Dict:
        """
        Perform all configured checks for a server.
        
        Args:
            server_config: Server configuration dict
        
        Returns:
            Dict with all check results
        """
        results = {
            'name': server_config['name'],
            'host': server_config['host'],
            'timestamp': datetime.now().isoformat(),
            'checks': {}
        }
        
        checks = server_config.get('checks', ['ping'])
        
        if 'ping' in checks:
            results['checks']['ping'] = self.ping_server(server_config['host'])
        
        if 'port' in checks and 'port' in server_config:
            results['checks']['port'] = self.check_port(
                server_config['host'],
                server_config['port']
            )
        
        if 'http' in checks and 'http_url' in server_config:
            results['checks']['http'] = self.check_http(server_config['http_url'])
        
        # Determine overall status
        all_checks = results['checks'].values()
        if any(check.get('status') in ['down', 'closed', 'error', 'timeout'] 
               for check in all_checks):
            results['overall_status'] = 'down'
        else:
            results['overall_status'] = 'up'
        
        return results
    
    def send_alert(self, server_name: str, status: str, details: Dict) -> None:
        """
        Send email alert when server is down.
        
        Args:
            server_name: Name of the server
            status: Current status
            details: Check details
        """
        if not self.alert_config.get('enabled'):
            return
        
        email_config = self.alert_config.get('email', {})
        if not email_config:
            return
        
        try:
            subject = f"🔴 ALERT: {server_name} is {status}"
            body = f"""
Server Monitor Alert

Server: {server_name}
Status: {status}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Details:
{json.dumps(details, indent=2)}

This is an automated alert from Server Monitor.
            """
            
            msg = MIMEMultipart()
            msg['From'] = email_config['sender']
            msg['To'] = ', '.join(email_config['recipients'])
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['sender'], email_config['password'])
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Alert sent for {server_name}")
        
        except Exception as e:
            logging.error(f"Failed to send alert: {e}")
    
    def monitor_once(self) -> List[Dict]:
        """
        Run monitoring checks once for all configured servers.
        
        Returns:
            List of all check results
        """
        results = []
        
        for server in self.servers:
            logging.info(f"Checking {server['name']}...")
            result = self.check_server(server)
            results.append(result)
            
            # Track status history
            server_name = server['name']
            if server_name not in self.status_history:
                self.status_history[server_name] = []
            
            self.status_history[server_name].append({
                'timestamp': result['timestamp'],
                'status': result['overall_status']
            })
            
            # Keep only last 100 entries
            self.status_history[server_name] = self.status_history[server_name][-100:]
            
            # Send alert if server is down
            if result['overall_status'] == 'down':
                self.send_alert(server_name, 'down', result)
            
            # Log status
            status_emoji = '✅' if result['overall_status'] == 'up' else '❌'
            logging.info(f"{status_emoji} {server['name']}: {result['overall_status']}")
        
        return results
    
    def monitor_continuous(self, interval: int = 60) -> None:
        """
        Continuously monitor servers at specified interval.
        
        Args:
            interval: Check interval in seconds
        """
        logging.info(f"Starting continuous monitoring (interval: {interval}s)")
        logging.info("Press Ctrl+C to stop...")
        
        try:
            while True:
                self.monitor_once()
                logging.info(f"Waiting {interval} seconds until next check...\n")
                time.sleep(interval)
        
        except KeyboardInterrupt:
            logging.info("Monitoring stopped by user")
    
    def print_status_report(self, results: List[Dict]) -> None:
        """Print a formatted status report."""
        print("\n" + "="*60)
        print("SERVER HEALTH REPORT")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
        
        for result in results:
            status_emoji = '✅' if result['overall_status'] == 'up' else '❌'
            print(f"{status_emoji} {result['name']} ({result['host']})")
            print(f"   Overall Status: {result['overall_status'].upper()}")
            
            for check_type, check_result in result['checks'].items():
                status = check_result.get('status', 'unknown')
                response_time = check_result.get('response_time')
                
                print(f"   - {check_type.capitalize()}: {status}", end='')
                if response_time:
                    print(f" ({response_time}ms)", end='')
                print()
            
            print()


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Monitor server health with ping, port, and HTTP checks'
    )
    parser.add_argument(
        '--config',
        type=str,
        help='Path to JSON configuration file'
    )
    parser.add_argument(
        '--continuous',
        action='store_true',
        help='Run continuous monitoring'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=60,
        help='Check interval in seconds (default: 60)'
    )
    parser.add_argument(
        '--log-file',
        type=str,
        help='Path to log file'
    )
    
    args = parser.parse_args()
    
    setup_logging(args.log_file)
    
    # Initialize monitor
    config_path = Path(args.config) if args.config else None
    monitor = ServerMonitor(config_path)
    
    if not monitor.servers:
        logging.error("No servers configured. Please provide a config file.")
        return
    
    # Run monitoring
    if args.continuous:
        monitor.monitor_continuous(args.interval)
    else:
        results = monitor.monitor_once()
        monitor.print_status_report(results)


if __name__ == '__main__':
    main()