#!/usr/bin/env python3
"""
this literally saved my life once, I was drowning in logs and this script helped me make sense of it all. (also made me look like a hero, which I am by the way)
it does what you think it does, parses logs, gives you stats, finds anomalies, and even follows logs in real-time, pretty cool huh?

Aymen
"""

import re
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from collections import Counter, defaultdict
import argparse
import logging


# Common log patterns
LOG_PATTERNS = {
    'apache': re.compile(
        r'(?P<ip>[\d.]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<path>[^\s]+) '
        r'(?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+)'
    ),
    'nginx': re.compile(
        r'(?P<ip>[\d.]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<path>[^\s]+) '
        r'(?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+)'
    ),
    'syslog': re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+[\d:]+) (?P<hostname>\S+) (?P<service>\w+)(\[(?P<pid>\d+)\])?: '
        r'(?P<message>.*)'
    ),
    'generic': re.compile(
        r'(?P<timestamp>[\d\-:.\s]+)?\s*(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)?\s*'
        r'(?P<message>.*)'
    )
}


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


class LogParser:
    """Parse and analyze log files with various formats."""
    
    def __init__(self, log_format: str = 'generic'):
        """
        Initialize the log parser.
        
        Args:
            log_format: Log format type ('apache', 'nginx', 'syslog', 'generic')
        """
        self.log_format = log_format
        self.pattern = LOG_PATTERNS.get(log_format, LOG_PATTERNS['generic'])
        self.entries: List[Dict] = []
        self.statistics: Dict = {}
    
    def parse_file(self, file_path: Path, max_lines: Optional[int] = None) -> None:
        """
        Parse a log file and extract structured data.
        
        Args:
            file_path: Path to the log file
            max_lines: Maximum number of lines to parse (None for all)
        """
        logging.info(f"Parsing log file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if max_lines and i >= max_lines:
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    match = self.pattern.match(line)
                    if match:
                        entry = match.groupdict()
                        entry['raw'] = line
                        entry['line_number'] = i + 1
                        self.entries.append(entry)
            
            logging.info(f"Parsed {len(self.entries)} log entries")
        
        except Exception as e:
            logging.error(f"Error parsing file: {e}")
    
    def filter_by_level(self, level: str) -> List[Dict]:
        """
        Filter entries by log level.
        
        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
        Returns:
            List of filtered entries
        """
        return [e for e in self.entries if e.get('level') == level]
    
    def filter_by_timerange(self, start: datetime, end: datetime, 
                           timestamp_format: str = '%d/%b/%Y:%H:%M:%S') -> List[Dict]:
        """
        Filter entries by time range.
        
        Args:
            start: Start datetime
            end: End datetime
            timestamp_format: Format string for parsing timestamps
        
        Returns:
            List of filtered entries
        """
        filtered = []
        
        for entry in self.entries:
            if 'timestamp' not in entry or not entry['timestamp']:
                continue
            
            try:
                # Handle timezone info in timestamp
                ts_str = entry['timestamp'].split()[0]
                entry_time = datetime.strptime(ts_str, timestamp_format)
                
                if start <= entry_time <= end:
                    filtered.append(entry)
            except (ValueError, IndexError):
                continue
        
        return filtered
    
    def search_pattern(self, pattern: str, field: str = 'message') -> List[Dict]:
        """
        Search for a pattern in log entries.
        
        Args:
            pattern: Regex pattern to search for
            field: Field to search in
        
        Returns:
            List of matching entries
        """
        regex = re.compile(pattern, re.IGNORECASE)
        return [e for e in self.entries if field in e and regex.search(str(e[field]))]
    
    def compute_statistics(self) -> Dict:
        """
        Compute various statistics from parsed log entries.
        
        Returns:
            Dict containing statistics
        """
        stats = {
            'total_entries': len(self.entries),
            'timestamp': datetime.now().isoformat()
        }
        
        # Level distribution
        if any('level' in e for e in self.entries):
            levels = [e.get('level') for e in self.entries if e.get('level')]
            stats['level_distribution'] = dict(Counter(levels))
        
        # Status code distribution (for web logs)
        if any('status' in e for e in self.entries):
            statuses = [e.get('status') for e in self.entries if e.get('status')]
            stats['status_distribution'] = dict(Counter(statuses))
            
            # HTTP status categories
            stats['status_categories'] = {
                '2xx_success': sum(1 for s in statuses if s and s.startswith('2')),
                '3xx_redirect': sum(1 for s in statuses if s and s.startswith('3')),
                '4xx_client_error': sum(1 for s in statuses if s and s.startswith('4')),
                '5xx_server_error': sum(1 for s in statuses if s and s.startswith('5'))
            }
        
        # IP address statistics (for web logs)
        if any('ip' in e for e in self.entries):
            ips = [e.get('ip') for e in self.entries if e.get('ip')]
            ip_counter = Counter(ips)
            stats['unique_ips'] = len(ip_counter)
            stats['top_ips'] = dict(ip_counter.most_common(10))
        
        # Path statistics (for web logs)
        if any('path' in e for e in self.entries):
            paths = [e.get('path') for e in self.entries if e.get('path')]
            path_counter = Counter(paths)
            stats['top_paths'] = dict(path_counter.most_common(10))
        
        # Service statistics (for syslog)
        if any('service' in e for e in self.entries):
            services = [e.get('service') for e in self.entries if e.get('service')]
            stats['service_distribution'] = dict(Counter(services).most_common(10))
        
        # Error rate
        error_levels = ['ERROR', 'CRITICAL']
        error_count = sum(1 for e in self.entries if e.get('level') in error_levels)
        stats['error_count'] = error_count
        if stats['total_entries'] > 0:
            stats['error_rate'] = round(error_count / stats['total_entries'] * 100, 2)
        
        self.statistics = stats
        return stats
    
    def detect_anomalies(self, threshold: int = 10) -> List[Dict]:
        """
        Detect anomalies such as repeated errors or suspicious patterns.
        
        Args:
            threshold: Minimum count to consider as anomaly
        
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        # Repeated errors
        error_messages = [e.get('message', '') for e in self.entries 
                         if e.get('level') in ['ERROR', 'CRITICAL']]
        
        error_counter = Counter(error_messages)
        for msg, count in error_counter.most_common():
            if count >= threshold:
                anomalies.append({
                    'type': 'repeated_error',
                    'message': msg[:100],  # Truncate long messages
                    'count': count,
                    'severity': 'high'
                })
        
        # Failed login attempts (if applicable)
        failed_logins = self.search_pattern(r'failed|authentication.*failed|login.*failed')
        if len(failed_logins) >= threshold:
            ip_attempts = Counter([e.get('ip') for e in failed_logins if e.get('ip')])
            for ip, count in ip_attempts.most_common(5):
                if count >= threshold:
                    anomalies.append({
                        'type': 'repeated_failed_auth',
                        'ip': ip,
                        'count': count,
                        'severity': 'critical'
                    })
        
        # High error rate in time window
        if any('timestamp' in e for e in self.entries):
            # Check for spikes in errors
            error_entries = [e for e in self.entries if e.get('level') in ['ERROR', 'CRITICAL']]
            if len(error_entries) > threshold:
                anomalies.append({
                    'type': 'high_error_rate',
                    'count': len(error_entries),
                    'total_entries': len(self.entries),
                    'rate': round(len(error_entries) / len(self.entries) * 100, 2),
                    'severity': 'high' if len(error_entries) / len(self.entries) > 0.1 else 'medium'
                })
        
        return anomalies
    
    def generate_report(self, output_path: Optional[Path] = None) -> str:
        """
        Generate a formatted report of log analysis.
        
        Args:
            output_path: Optional path to save report
        
        Returns:
            Report as string
        """
        if not self.statistics:
            self.compute_statistics()
        
        report = []
        report.append("="*70)
        report.append("LOG ANALYSIS REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("="*70)
        report.append("")
        
        # Basic statistics
        report.append("BASIC STATISTICS")
        report.append("-"*70)
        report.append(f"Total Entries: {self.statistics.get('total_entries', 0):,}")
        
        if 'error_count' in self.statistics:
            report.append(f"Error Count: {self.statistics['error_count']:,}")
            report.append(f"Error Rate: {self.statistics.get('error_rate', 0)}%")
        
        if 'unique_ips' in self.statistics:
            report.append(f"Unique IP Addresses: {self.statistics['unique_ips']:,}")
        
        report.append("")
        
        # Level distribution
        if 'level_distribution' in self.statistics:
            report.append("LOG LEVEL DISTRIBUTION")
            report.append("-"*70)
            for level, count in sorted(self.statistics['level_distribution'].items()):
                percentage = (count / self.statistics['total_entries']) * 100
                report.append(f"  {level:15s}: {count:6,} ({percentage:5.2f}%)")
            report.append("")
        
        # Status code distribution
        if 'status_categories' in self.statistics:
            report.append("HTTP STATUS CODE SUMMARY")
            report.append("-"*70)
            for category, count in self.statistics['status_categories'].items():
                report.append(f"  {category:20s}: {count:6,}")
            report.append("")
        
        # Top IPs
        if 'top_ips' in self.statistics:
            report.append("TOP 10 IP ADDRESSES")
            report.append("-"*70)
            for ip, count in list(self.statistics['top_ips'].items())[:10]:
                report.append(f"  {ip:20s}: {count:6,} requests")
            report.append("")
        
        # Top paths
        if 'top_paths' in self.statistics:
            report.append("TOP 10 REQUESTED PATHS")
            report.append("-"*70)
            for path, count in list(self.statistics['top_paths'].items())[:10]:
                truncated_path = path[:50] + '...' if len(path) > 50 else path
                report.append(f"  {truncated_path:53s}: {count:6,}")
            report.append("")
        
        # Anomalies
        anomalies = self.detect_anomalies()
        if anomalies:
            report.append("DETECTED ANOMALIES")
            report.append("-"*70)
            for anomaly in anomalies:
                severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡'}.get(
                    anomaly['severity'], '⚪'
                )
                report.append(f"{severity_emoji} {anomaly['type'].upper().replace('_', ' ')}")
                for key, value in anomaly.items():
                    if key not in ['type', 'severity']:
                        report.append(f"    {key}: {value}")
                report.append("")
        
        report.append("="*70)
        report.append("End of Report")
        report.append("="*70)
        
        report_text = '\n'.join(report)
        
        # Save to file if requested
        if output_path:
            try:
                with open(output_path, 'w') as f:
                    f.write(report_text)
                logging.info(f"Report saved to {output_path}")
            except Exception as e:
                logging.error(f"Error saving report: {e}")
        
        return report_text
    
    def export_json(self, output_path: Path) -> None:
        """
        Export parsed data and statistics to JSON.
        
        Args:
            output_path: Path to save JSON file
        """
        data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'log_format': self.log_format,
                'total_entries': len(self.entries)
            },
            'statistics': self.statistics,
            'anomalies': self.detect_anomalies(),
            'entries': self.entries[:1000]  # Limit to first 1000 for file size
        }
        
        try:
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            logging.info(f"Data exported to {output_path}")
        except Exception as e:
            logging.error(f"Error exporting JSON: {e}")
    
    def tail_follow(self, file_path: Path, callback=None) -> None:
        """
        Follow a log file in real-time (like 'tail -f').
        
        Args:
            file_path: Path to the log file
            callback: Optional callback function for each new line
        """
        logging.info(f"Following log file: {file_path}")
        logging.info("Press Ctrl+C to stop...")
        
        try:
            with open(file_path, 'r') as f:
                # Go to end of file
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if line:
                        line = line.strip()
                        match = self.pattern.match(line)
                        
                        if match:
                            entry = match.groupdict()
                            entry['raw'] = line
                            
                            # Highlight errors
                            if entry.get('level') in ['ERROR', 'CRITICAL']:
                                print(f"🔴 {line}")
                            elif entry.get('status', '').startswith('5'):
                                print(f"🔴 {line}")
                            else:
                                print(line)
                            
                            if callback:
                                callback(entry)
                        else:
                            print(line)
                    else:
                        # No new lines, wait a bit
                        import time
                        time.sleep(0.1)
        
        except KeyboardInterrupt:
            logging.info("Stopped following log file")
        except Exception as e:
            logging.error(f"Error following file: {e}")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Parse and analyze log files with statistics and anomaly detection'
    )
    parser.add_argument(
        'logfile',
        type=str,
        help='Path to log file'
    )
    parser.add_argument(
        '--format',
        type=str,
        choices=['apache', 'nginx', 'syslog', 'generic'],
        default='generic',
        help='Log format type (default: generic)'
    )
    parser.add_argument(
        '--follow',
        action='store_true',
        help='Follow log file in real-time (like tail -f)'
    )
    parser.add_argument(
        '--max-lines',
        type=int,
        help='Maximum number of lines to parse'
    )
    parser.add_argument(
        '--search',
        type=str,
        help='Search for pattern in logs'
    )
    parser.add_argument(
        '--level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Filter by log level'
    )
    parser.add_argument(
        '--report',
        type=str,
        help='Generate report and save to file'
    )
    parser.add_argument(
        '--export-json',
        type=str,
        help='Export analysis to JSON file'
    )
    parser.add_argument(
        '--anomaly-threshold',
        type=int,
        default=10,
        help='Threshold for anomaly detection (default: 10)'
    )
    parser.add_argument(
        '--log-file',
        type=str,
        help='Path to application log file'
    )
    
    args = parser.parse_args()
    
    setup_logging(args.log_file)
    
    # Validate log file
    log_path = Path(args.logfile)
    if not log_path.exists():
        logging.error(f"Log file not found: {log_path}")
        return
    
    # Initialize parser
    log_parser = LogParser(args.format)
    
    # Follow mode
    if args.follow:
        log_parser.tail_follow(log_path)
        return
    
    # Parse log file
    log_parser.parse_file(log_path, args.max_lines)
    
    if not log_parser.entries:
        logging.warning("No log entries parsed. Check log format.")
        return
    
    # Apply filters
    entries = log_parser.entries
    
    if args.level:
        entries = log_parser.filter_by_level(args.level)
        logging.info(f"Filtered to {len(entries)} {args.level} entries")
    
    if args.search:
        entries = log_parser.search_pattern(args.search)
        logging.info(f"Found {len(entries)} entries matching '{args.search}'")
        
        # Print matching entries
        print(f"\nMatching entries ({len(entries)}):")
        print("-"*70)
        for entry in entries[:20]:  # Show first 20
            print(f"Line {entry['line_number']}: {entry['raw']}")
    
    # Compute statistics
    log_parser.compute_statistics()
    
    # Detect anomalies
    anomalies = log_parser.detect_anomalies(args.anomaly_threshold)
    if anomalies:
        print(f"\n⚠️  Detected {len(anomalies)} anomalies:")
        for anomaly in anomalies:
            print(f"  - {anomaly['type']}: {anomaly}")
    
    # Generate report
    if args.report:
        report = log_parser.generate_report(Path(args.report))
    else:
        report = log_parser.generate_report()
        print("\n" + report)
    
    # Export JSON
    if args.export_json:
        log_parser.export_json(Path(args.export_json))


if __name__ == '__main__':
    main()