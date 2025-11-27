#!/usr/bin/env python3
"""
Wi-Spy Sentinel 2.0 - Log File Analyzer
Import and analyze Flipper Zero log files
"""

import re
import sqlite3
from datetime import datetime
from pathlib import Path
import argparse

class LogAnalyzer:
    def __init__(self, db_path="wispy.db"):
        self.db_path = db_path
        self.stats = {
            'aps_found': 0,
            'stations_found': 0,
            'hidden_networks': 0,
            'lines_processed': 0
        }
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Access Points table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                bssid TEXT NOT NULL,
                essid TEXT,
                channel INTEGER,
                rssi INTEGER,
                encryption TEXT,
                vendor TEXT,
                first_seen TEXT,
                last_seen TEXT,
                beacon_count INTEGER DEFAULT 1,
                is_hidden BOOLEAN DEFAULT 0,
                threat_level TEXT DEFAULT 'unknown',
                location TEXT
            )
        ''')
        
        # Stations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                station_mac TEXT NOT NULL,
                connected_to_bssid TEXT,
                rssi INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                location TEXT
            )
        ''')
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                bssid TEXT NOT NULL,
                essid TEXT,
                threat_type TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                description TEXT,
                resolved BOOLEAN DEFAULT 0,
                location TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def parse_log_file(self, log_file_path, location_name="Unknown"):
        """Parse Flipper Zero log file and import to database"""
        print(f"\n[*] Analyzing log file: {log_file_path}")
        print(f"[*] Location: {location_name}")
        
        if not Path(log_file_path).exists():
            print(f"[✗] File not found: {log_file_path}")
            return False
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()
        
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                self.stats['lines_processed'] += 1
                line = line.strip()
                
                if not line:
                    continue
                
                # Try parsing as Access Point
                ap_data = self.parse_ap_line(line)
                if ap_data:
                    self.save_ap_to_db(cursor, ap_data, timestamp, location_name)
                    self.stats['aps_found'] += 1
                    if ap_data.get('is_hidden'):
                        self.stats['hidden_networks'] += 1
                    continue
                
                # Try parsing as Station
                sta_data = self.parse_sta_line(line)
                if sta_data:
                    self.save_sta_to_db(cursor, sta_data, timestamp, location_name)
                    self.stats['stations_found'] += 1
        
        conn.commit()
        conn.close()
        
        # Print statistics
        print(f"\n[✓] Import complete!")
        print(f"    Lines processed: {self.stats['lines_processed']}")
        print(f"    Access Points:   {self.stats['aps_found']}")
        print(f"    Stations:        {self.stats['stations_found']}")
        print(f"    Hidden Networks: {self.stats['hidden_networks']}")
        
        return True
    
    def parse_ap_line(self, line):
        """Parse access point data from log line"""
        ap_data = {}
        
        # Look for BSSID
        bssid_match = re.search(r'BSSID:\s*([0-9a-fA-F:]{17})', line)
        if bssid_match:
            ap_data['bssid'] = bssid_match.group(1).lower()
        else:
            return None
        
        # Look for ESSID/SSID
        essid_match = re.search(r'(?:ESSID|SSID):\s*([^,\n]+)', line)
        if essid_match:
            essid = essid_match.group(1).strip()
            if essid.lower().replace(':', '') == ap_data['bssid'].replace(':', ''):
                ap_data['essid'] = "[HIDDEN]"
                ap_data['is_hidden'] = True
            else:
                ap_data['essid'] = essid
                ap_data['is_hidden'] = False
        
        # Look for RSSI
        rssi_match = re.search(r'RSSI:\s*(-?\d+)', line)
        if rssi_match:
            ap_data['rssi'] = int(rssi_match.group(1))
        
        # Look for Channel
        ch_match = re.search(r'Ch:\s*(\d+)', line)
        if ch_match:
            ap_data['channel'] = int(ch_match.group(1))
        
        # Look for encryption
        if 'WPA2' in line:
            ap_data['encryption'] = 'WPA2'
        elif 'WPA3' in line:
            ap_data['encryption'] = 'WPA3'
        elif 'WPA' in line:
            ap_data['encryption'] = 'WPA'
        elif 'WEP' in line:
            ap_data['encryption'] = 'WEP'
        elif 'Open' in line or 'OPEN' in line:
            ap_data['encryption'] = 'Open'
        
        return ap_data
    
    def parse_sta_line(self, line):
        """Parse station data from log line"""
        sta_data = {}
        
        sta_match = re.search(r'STA:\s*([0-9a-fA-F:]{17})', line)
        if sta_match:
            sta_data['station_mac'] = sta_match.group(1).lower()
        else:
            return None
        
        ap_match = re.search(r'AP:\s*([0-9a-fA-F:]{17})', line)
        if ap_match:
            sta_data['connected_to_bssid'] = ap_match.group(1).lower()
        
        rssi_match = re.search(r'RSSI:\s*(-?\d+)', line)
        if rssi_match:
            sta_data['rssi'] = int(rssi_match.group(1))
        
        return sta_data
    
    def save_ap_to_db(self, cursor, ap_data, timestamp, location):
        """Save access point to database"""
        cursor.execute('SELECT id FROM access_points WHERE bssid = ?', 
                      (ap_data['bssid'],))
        existing = cursor.fetchone()
        
        if not existing:
            cursor.execute('''
                INSERT INTO access_points 
                (timestamp, bssid, essid, channel, rssi, encryption, first_seen, last_seen, is_hidden, location)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, ap_data['bssid'], ap_data.get('essid'), 
                  ap_data.get('channel'), ap_data.get('rssi'), 
                  ap_data.get('encryption'), timestamp, timestamp,
                  ap_data.get('is_hidden', False), location))
    
    def save_sta_to_db(self, cursor, sta_data, timestamp, location):
        """Save station to database"""
        cursor.execute('SELECT id FROM stations WHERE station_mac = ?', 
                      (sta_data['station_mac'],))
        existing = cursor.fetchone()
        
        if not existing:
            cursor.execute('''
                INSERT INTO stations 
                (timestamp, station_mac, connected_to_bssid, rssi, first_seen, last_seen, location)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, sta_data['station_mac'], 
                  sta_data.get('connected_to_bssid'), sta_data.get('rssi'),
                  timestamp, timestamp, location))
    
    def generate_report(self):
        """Generate comprehensive report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        print("\n" + "="*70)
        print("📊 Wi-Spy Sentinel - Network Summary Report")
        print("="*70)
        
        cursor.execute('SELECT COUNT(*) FROM access_points')
        total_aps = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM access_points WHERE is_hidden = 1')
        hidden_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM access_points WHERE encryption = 'Open'")
        open_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM stations')
        total_stations = cursor.fetchone()[0]
        
        print(f"\n📡 Total Access Points: {total_aps}")
        print(f"🔒 Hidden Networks: {hidden_count}")
        print(f"⚠️  Open Networks (No Encryption): {open_count}")
        print(f"📱 Total Devices Detected: {total_stations}")
        
        print("\n📶 Channel Distribution:")
        cursor.execute('''
            SELECT channel, COUNT(*) as count 
            FROM access_points 
            WHERE channel IS NOT NULL
            GROUP BY channel 
            ORDER BY channel
        ''')
        for row in cursor.fetchall():
            channel, count = row
            bar = '█' * min(count, 50)
            print(f"   Ch {channel:2d}: {bar} ({count})")
        
        print("\n💪 Top 5 Strongest Signals:")
        cursor.execute('''
            SELECT essid, bssid, rssi, channel
            FROM access_points
            ORDER BY rssi DESC
            LIMIT 5
        ''')
        for i, row in enumerate(cursor.fetchall(), 1):
            essid, bssid, rssi, channel = row
            print(f"   {i}. {essid or '[HIDDEN]':30s} | {bssid} | {rssi} dBm | Ch {channel}")
        
        print("\n" + "="*70 + "\n")
        
        conn.close()


def main():
    parser = argparse.ArgumentParser(description='Wi-Spy Sentinel - Analyze Wi-Fi log files')
    parser.add_argument('-f', '--file', help='Log file to analyze')
    parser.add_argument('-l', '--location', default='Unknown', help='Location name')
    parser.add_argument('-a', '--analyze', action='store_true', help='Run threat analysis')
    parser.add_argument('-r', '--report', action='store_true', help='Generate report')
    parser.add_argument('--db', default='wispy.db', help='Database path')
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer(db_path=args.db)
    
    if args.file:
        success = analyzer.parse_log_file(args.file, args.location)
        if success and args.analyze:
            from threat_detector import ThreatDetector
            detector = ThreatDetector(db_path=args.db)
            detector.analyze_all_threats()
    
    if args.report:
        analyzer.generate_report()
    
    if not args.file and not args.report:
        parser.print_help()


if __name__ == "__main__":
    main()