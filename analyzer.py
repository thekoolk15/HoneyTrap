#!/usr/bin/env python3
"""
Log Analyzer for HoneyTrap

Analyzes honeypot logs to extract insights about:
- Attack frequency and timing patterns
- Source IP addresses and geographic distribution
- Common attack patterns and techniques
- Credential stuffing attempts

Usage:
    python analyzer.py                    # Analyze default log file
    python analyzer.py -f custom.log      # Analyze custom log file
    python analyzer.py --json             # Analyze JSON logs
"""

import json
import os
import argparse
from datetime import datetime
from collections import Counter
from typing import Dict, List
from config import LOG_FILE


def load_json_logs(filepath: str) -> List[dict]:
    """
    Load and parse JSON log file.
    
    Args:
        filepath: Path to the JSON log file
        
    Returns:
        List of log entry dictionaries
    """
    logs = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"❌ Log file not found: {filepath}")
    return logs


def load_text_logs(filepath: str) -> List[str]:
    """
    Load text-based log file.
    
    Args:
        filepath: Path to the log file
        
    Returns:
        List of log lines
    """
    try:
        with open(filepath, 'r') as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"❌ Log file not found: {filepath}")
        return []


def analyze_json_logs(logs: List[dict]) -> dict:
    """
    Analyze JSON-formatted logs for attack patterns.
    
    Args:
        logs: List of log entry dictionaries
        
    Returns:
        Dictionary containing analysis results
    """
    analysis = {
        'total_events': len(logs),
        'connections': 0,
        'unique_ips': set(),
        'ip_frequency': Counter(),
        'port_frequency': Counter(),
        'hourly_distribution': Counter(),
        'data_received_events': 0,
        'potential_credentials': []
    }
    
    for log in logs:
        event_type = log.get('event_type', '')
        
        if event_type == 'connection':
            if log.get('status') == 'connected':
                analysis['connections'] += 1
                ip = log.get('source_ip', 'unknown')
                port = log.get('target_port', 'unknown')
                analysis['unique_ips'].add(ip)
                analysis['ip_frequency'][ip] += 1
                analysis['port_frequency'][port] += 1
                
                # Extract hour for time distribution
                try:
                    timestamp = datetime.fromisoformat(log.get('timestamp', ''))
                    analysis['hourly_distribution'][timestamp.hour] += 1
                except:
                    pass
                    
        elif event_type == 'data_received':
            analysis['data_received_events'] += 1
            
            # Look for potential credential attempts
            decoded = log.get('data_decoded', '')
            if decoded and len(decoded) > 2:
                analysis['potential_credentials'].append({
                    'ip': log.get('source_ip', 'unknown'),
                    'port': log.get('target_port', 'unknown'),
                    'data': decoded[:100]
                })
    
    return analysis


def print_analysis_report(analysis: dict) -> None:
    """
    Print a formatted analysis report.
    
    Args:
        analysis: Dictionary containing analysis results
    """
    print("\n" + "=" * 60)
    print("🍯 HONEYTRAP LOG ANALYSIS REPORT")
    print("=" * 60)
    
    print(f"\n📊 OVERVIEW")
    print("-" * 40)
    print(f"  Total Events:        {analysis['total_events']}")
    print(f"  Total Connections:   {analysis['connections']}")
    print(f"  Unique IP Addresses: {len(analysis['unique_ips'])}")
    print(f"  Data Receive Events: {analysis['data_received_events']}")
    
    if analysis['port_frequency']:
        print(f"\n🪤 ATTACKS BY PORT")
        print("-" * 40)
        for port, count in analysis['port_frequency'].most_common():
            bar = "█" * min(count, 30)
            print(f"  Port {port:5} | {count:4} | {bar}")
    
    if analysis['ip_frequency']:
        print(f"\n🎯 TOP 10 SOURCE IPs")
        print("-" * 40)
        for ip, count in analysis['ip_frequency'].most_common(10):
            bar = "█" * min(count, 30)
            print(f"  {ip:20} | {count:4} | {bar}")
    
    if analysis['hourly_distribution']:
        print(f"\n⏰ ATTACK DISTRIBUTION BY HOUR (UTC)")
        print("-" * 40)
        for hour in range(24):
            count = analysis['hourly_distribution'].get(hour, 0)
            bar = "█" * min(count, 30)
            print(f"  {hour:02d}:00 | {count:4} | {bar}")
    
    if analysis['potential_credentials']:
        print(f"\n🔑 CAPTURED DATA (Sample)")
        print("-" * 40)
        for i, cred in enumerate(analysis['potential_credentials'][:10]):
            print(f"  [{i+1}] IP: {cred['ip']} | Port: {cred['port']}")
            print(f"      Data: {repr(cred['data'][:50])}")
            print()
    
    print("\n" + "=" * 60)
    print("📈 INSIGHTS")
    print("=" * 60)
    
    if analysis['connections'] > 0:
        avg_per_ip = analysis['connections'] / max(len(analysis['unique_ips']), 1)
        print(f"  • Average attempts per IP: {avg_per_ip:.1f}")
        
        if avg_per_ip > 5:
            print("  ⚠️  High repeat attempts suggest automated scanning/brute-forcing")
        
        if analysis['ip_frequency']:
            top_ip, top_count = analysis['ip_frequency'].most_common(1)[0]
            if top_count > 10:
                print(f"  ⚠️  IP {top_ip} shows aggressive behavior ({top_count} attempts)")
    
    print("\n" + "=" * 60)


def main():
    """Main entry point for the analyzer."""
    parser = argparse.ArgumentParser(
        description='Analyze HoneyTrap logs for attack patterns'
    )
    parser.add_argument(
        '-f', '--file',
        default=LOG_FILE,
        help='Path to log file (default: logs/honeytrap.log)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Analyze JSON log format instead of text'
    )
    
    args = parser.parse_args()
    
    print("\n🍯 HoneyTrap Log Analyzer")
    print(f"   Analyzing: {args.file}")
    
    if args.json:
        json_file = args.file.replace('.log', '.json')
        logs = load_json_logs(json_file)
        if logs:
            analysis = analyze_json_logs(logs)
            print_analysis_report(analysis)
    else:
        # Default to JSON analysis if JSON file exists
        json_file = args.file.replace('.log', '.json')
        if os.path.exists(json_file):
            logs = load_json_logs(json_file)
            if logs:
                analysis = analyze_json_logs(logs)
                print_analysis_report(analysis)
        else:
            print("❌ No JSON log file found. Run HoneyTrap first to generate logs.")
            print(f"   Expected location: {json_file}")


if __name__ == "__main__":
    main()