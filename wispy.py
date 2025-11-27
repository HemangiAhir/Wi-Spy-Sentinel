#!/usr/bin/env python3
"""
Wi-Spy Sentinel 2.0 - Master Control Script
Main interface for all operations
"""

import argparse
import sys
import sqlite3
import csv
import json
from pathlib import Path

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  ██     ██ ██       ███████ ██████  ██    ██                        ║
║  ██     ██ ██       ██      ██   ██  ██  ██                         ║
║  ██  █  ██ ██ █████ ███████ ██████    ████                          ║
║  ██ ███ ██ ██            ██ ██         ██                           ║
║   ███ ███  ██       ███████ ██         ██                           ║
║                                                                      ║
║              SENTINEL 2.0 - Wi-Fi Threat Detection                  ║
║          Detection of Hidden & Malicious Wi-Fi Activity             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Wi-Spy Sentinel 2.0 - Wi-Fi Security Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Operation mode')
    
    # SCAN command
    scan_parser = subparsers.add_parser('scan', help='Live Wi-Fi scanning')
    scan_parser.add_argument('--port', default='COM3', help='Serial port')
    scan_parser.add_argument('--baud', type=int, default=115200, help='Baud rate')
    scan_parser.add_argument('--db', default='wispy.db', help='Database file')
    scan_parser.add_argument('-l', '--location', default='Unknown', help='Location name')
    
    # ANALYZE command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze log file')
    analyze_parser.add_argument('-f', '--file', required=True, help='Log file')
    analyze_parser.add_argument('-l', '--location', default='Unknown', help='Location')
    analyze_parser.add_argument('--threats', action='store_true', help='Run threat detection')
    analyze_parser.add_argument('--db', default='wispy.db', help='Database file')
    
    # THREATS command
    threats_parser = subparsers.add_parser('threats', help='Run threat detection')
    threats_parser.add_argument('--db', default='wispy.db', help='Database file')
    threats_parser.add_argument('--export', help='Export to JSON')
    
    # REPORT command
    report_parser = subparsers.add_parser('report', help='Generate report')
    report_parser.add_argument('--db', default='wispy.db', help='Database file')
    
    # EXPORT command
    export_parser = subparsers.add_parser('export', help='Export data')
    export_parser.add_argument('--format', choices=['csv', 'json'], default='csv')
    export_parser.add_argument('--output', required=True, help='Output file')
    export_parser.add_argument('--db', default='wispy.db', help='Database file')
    
    # LIST command
    list_parser = subparsers.add_parser('list', help='List networks')
    list_parser.add_argument('--db', default='wispy.db', help='Database file')
    list_parser.add_argument('--hidden', action='store_true', help='Hidden only')
    list_parser.add_argument('--open', action='store_true', help='Open only')
    list_parser.add_argument('-l', '--location', help='Filter by location')
    
    # COMPARE command
    compare_parser = subparsers.add_parser('compare', help='Compare two scans')
    compare_parser.add_argument('--db', default='wispy.db', help='Database file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    # Execute commands
    if args.command == 'scan':
        try:
            from wifi_scanner import WiFiScanner
            scanner = WiFiScanner(port=args.port, baud=args.baud, db_path=args.db)
            scanner.scan_live(location=args.location)
        except Exception as e:
            print(f"[✗] Error: {e}")
    
    elif args.command == 'analyze':
        try:
            from log_analyzer import LogAnalyzer
            analyzer = LogAnalyzer(db_path=args.db)
            success = analyzer.parse_log_file(args.file, args.location)
            
            if success:
                analyzer.generate_report()
                
                if args.threats:
                    print("\n[*] Running threat detection...")
                    from threat_detector import ThreatDetector
                    detector = ThreatDetector(db_path=args.db)
                    detector.analyze_all_threats()
        except Exception as e:
            print(f"[✗] Error: {e}")
    
    elif args.command == 'threats':
        try:
            from threat_detector import ThreatDetector
            detector = ThreatDetector(db_path=args.db)
            threats = detector.analyze_all_threats()
            
            if args.export:
                with open(args.export, 'w') as f:
                    json.dump(threats, f, indent=2)
                print(f"\n[✓] Threats exported to {args.export}")
        except Exception as e:
            print(f"[✗] Error: {e}")
    
    elif args.command == 'report':
        try:
            from log_analyzer import LogAnalyzer
            analyzer = LogAnalyzer(db_path=args.db)
            analyzer.generate_report()
        except Exception as e:
            print(f"[✗] Error: {e}")
    
    elif args.command == 'export':
        try:
            conn = sqlite3.connect(args.db)
            
            if args.format == 'csv':
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM access_points')
                
                with open(args.output, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([desc[0] for desc in cursor.description])
                    writer.writerows(cursor.fetchall())
                
                print(f"[✓] Data exported to {args.output}")
            
            elif args.format == 'json':
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM access_points')
                columns = [desc[0] for desc in cursor.description]
                
                results = []
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
                
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                
                print(f"[✓] Data exported to {args.output}")
            
            conn.close()
        except Exception as e:
            print(f"[✗] Error: {e}")
    
    elif args.command == 'list':
        try:
            conn = sqlite3.connect(args.db)
            cursor = conn.cursor()
            
            query = 'SELECT essid, bssid, rssi, channel, encryption, is_hidden, threat_level, location FROM access_points WHERE 1=1'
            
            if args.hidden:
                query += ' AND is_hidden = 1'
            if args.open:
                query += " AND encryption = 'Open'"
            if args.location:
                query += f" AND location = '{args.location}'"
            
            query += ' ORDER BY rssi DESC'
            
            cursor.execute(query)
            
            print("\n" + "="*100)
            print(f"{'SSID':<30} {'BSSID':<20} {'RSSI':<8} {'Ch':<5} {'Encryption':<12} {'Threat':<10} {'Location':<15}")
            print("="*100)
            
            for row in cursor.fetchall():
                essid, bssid, rssi, channel, encryption, is_hidden, threat_level, location = row
                hidden_mark = "🔒" if is_hidden else "  "
                threat_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢', 'safe': '✅', 'unknown': '❓'}
                threat_display = f"{threat_emoji.get(threat_level, '?')} {threat_level}"
                
                print(f"{(essid or '[HIDDEN]'):<30} {bssid:<20} {rssi or 'N/A':<8} {channel or 'N/A':<5} {encryption or 'N/A':<12} {threat_display:<10} {location or 'Unknown':<15}")
            
            print("="*100 + "\n")
            
            conn.close()
        except Exception as e:
            print(f"[✗] Error: {e}")
    
    elif args.command == 'compare':
        try:
            print("\n[*] Launching comparison visualization...")
            import subprocess
            subprocess.run([sys.executable, 'compare_scans.py', '--db', args.db])
        except Exception as e:
            print(f"[✗] Error: {e}")
            print("[*] Make sure compare_scans.py is in the same directory")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
        sys.exit(0)