#!/usr/bin/env python3
"""
Wi-Spy Sentinel 2.0 - Wi-Fi Scanner Module
Real-time scanning from Flipper Zero
"""

import serial
import sqlite3
from datetime import datetime
import re

class WiFiScanner:
    def __init__(self, port="/dev/ttyUSB0", baud=115200, db_path="wispy.db"):
        self.port = port
        self.baud = baud
        self.db_path = db_path
        self.serial_conn = None
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for storing scan results"""
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
        
        # Stations (connected devices) table
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
        
        # Threat alerts table
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
        print("[✓] Database initialized")
    
    def connect_serial(self):
        """Connect to Flipper Zero via serial"""
        try:
            self.serial_conn = serial.Serial(self.port, self.baud, timeout=1)
            print(f"[✓] Connected to {self.port} at {self.baud} baud")
            return True
        except Exception as e:
            print(f"[✗] Failed to connect: {e}")
            return False
    
    def parse_ap_line(self, line):
        """Parse access point data from serial output"""
        ap_data = {}
        
        # Look for BSSID
        bssid_match = re.search(r'BSSID:\s*([0-9a-fA-F:]{17})', line)
        if bssid_match:
            ap_data['bssid'] = bssid_match.group(1).lower()
        
        # Look for ESSID/SSID
        essid_match = re.search(r'(?:ESSID|SSID):\s*([^,\n]+)', line)
        if essid_match:
            essid = essid_match.group(1).strip()
            if essid.lower().replace(':', '') == ap_data.get('bssid', '').replace(':', ''):
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
        
        return ap_data if ap_data else None
    
    def parse_sta_line(self, line):
        """Parse station (client device) data from serial output"""
        sta_data = {}
        
        sta_match = re.search(r'STA:\s*([0-9a-fA-F:]{17})', line)
        if sta_match:
            sta_data['station_mac'] = sta_match.group(1).lower()
        
        ap_match = re.search(r'AP:\s*([0-9a-fA-F:]{17})', line)
        if ap_match:
            sta_data['connected_to_bssid'] = ap_match.group(1).lower()
        
        rssi_match = re.search(r'RSSI:\s*(-?\d+)', line)
        if rssi_match:
            sta_data['rssi'] = int(rssi_match.group(1))
        
        return sta_data if sta_data else None
    
    def save_ap_to_db(self, ap_data, location="Unknown"):
        """Save or update access point in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()
        
        cursor.execute('SELECT id, beacon_count FROM access_points WHERE bssid = ?', 
                      (ap_data['bssid'],))
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute('''
                UPDATE access_points 
                SET last_seen = ?, rssi = ?, beacon_count = ?, essid = ?
                WHERE bssid = ?
            ''', (timestamp, ap_data.get('rssi'), existing[1] + 1, 
                  ap_data.get('essid'), ap_data['bssid']))
        else:
            cursor.execute('''
                INSERT INTO access_points 
                (timestamp, bssid, essid, channel, rssi, first_seen, last_seen, is_hidden, location)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, ap_data['bssid'], ap_data.get('essid'), 
                  ap_data.get('channel'), ap_data.get('rssi'), 
                  timestamp, timestamp, ap_data.get('is_hidden', False), location))
        
        conn.commit()
        conn.close()
    
    def save_sta_to_db(self, sta_data, location="Unknown"):
        """Save or update station in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()
        
        cursor.execute('SELECT id FROM stations WHERE station_mac = ?', 
                      (sta_data['station_mac'],))
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute('''
                UPDATE stations 
                SET last_seen = ?, rssi = ?, connected_to_bssid = ?
                WHERE station_mac = ?
            ''', (timestamp, sta_data.get('rssi'), 
                  sta_data.get('connected_to_bssid'), sta_data['station_mac']))
        else:
            cursor.execute('''
                INSERT INTO stations 
                (timestamp, station_mac, connected_to_bssid, rssi, first_seen, last_seen, location)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, sta_data['station_mac'], 
                  sta_data.get('connected_to_bssid'), sta_data.get('rssi'),
                  timestamp, timestamp, location))
        
        conn.commit()
        conn.close()
    
    def scan_live(self, location="Unknown"):
        """Start live scanning from Flipper Zero"""
        if not self.connect_serial():
            return
        
        print("\n[*] Starting live Wi-Fi scan...")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            while True:
                if self.serial_conn.in_waiting:
                    line = self.serial_conn.readline().decode(errors='ignore').strip()
                    
                    if not line:
                        continue
                    
                    ap_data = self.parse_ap_line(line)
                    if ap_data:
                        self.save_ap_to_db(ap_data, location)
                        essid_display = ap_data.get('essid', 'N/A')
                        rssi_display = ap_data.get('rssi', 'N/A')
                        print(f"[AP] {essid_display:30s} | {ap_data['bssid']} | RSSI: {rssi_display}")
                        continue
                    
                    sta_data = self.parse_sta_line(line)
                    if sta_data:
                        self.save_sta_to_db(sta_data, location)
                        print(f"[STA] {sta_data['station_mac']} -> {sta_data.get('connected_to_bssid', 'N/A')}")
                        
        except KeyboardInterrupt:
            print("\n\n[*] Scan stopped by user")
        finally:
            if self.serial_conn:
                self.serial_conn.close()
                print("[✓] Serial connection closed")


if __name__ == "__main__":
    scanner = WiFiScanner()
    scanner.scan_live()