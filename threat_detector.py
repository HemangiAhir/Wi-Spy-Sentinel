#!/usr/bin/env python3
"""
Wi-Spy Sentinel 2.0 - Threat Detection Engine
Analyzes Wi-Fi networks for malicious indicators
"""

import sqlite3
import re
from datetime import datetime, timedelta
from collections import defaultdict

class ThreatDetector:
    def __init__(self, db_path="wispy.db"):
        self.db_path = db_path
        
        # Suspicious SSID patterns (case-insensitive)
        self.suspicious_patterns = [
            r'free.*wifi',
            r'free.*internet',
            r'airport.*wifi',
            r'hotel.*wifi',
            r'starbucks',
            r'mcdonalds',
            r'xfinitywifi',
            r'attwifi',
            r'guest.*network',
            r'public.*wifi',
            r'windows.*update',
            r'iphone.*setup',
            r'android.*setup',
            r'\.\.+',
            r'test',
            r'default',
            r'linksys',
            r'netgear\d+',
            r'dlink',
            r'freeman',
        ]
        
        # Known legitimate enterprise networks (whitelist)
        self.whitelist = [
            'eduroam',
            'govwifi',
        ]
        
        # MAC address vendor prefixes
        self.common_vendors = {
            '00:50:f2': 'Microsoft',
            '00:0c:29': 'VMware',
            '08:00:27': 'VirtualBox',
            'dc:a6:32': 'Raspberry Pi',
            'b8:27:eb': 'Raspberry Pi Foundation',
        }
    
    def get_mac_vendor(self, mac):
        """Identify MAC address vendor from OUI"""
        prefix = ':'.join(mac.split(':')[:3]).lower()
        return self.common_vendors.get(prefix, 'Unknown')
    
    def check_suspicious_ssid(self, ssid):
        """Check if SSID matches suspicious patterns"""
        if not ssid or ssid == "[HIDDEN]":
            return False
        
        ssid_lower = ssid.lower()
        
        # Check whitelist first
        for safe in self.whitelist:
            if safe in ssid_lower:
                return False
        
        # Check suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, ssid_lower):
                return True
        
        return False
    
    def detect_evil_twin(self):
        """Detect potential evil twin attacks"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT essid, COUNT(DISTINCT bssid) as count, GROUP_CONCAT(bssid) as bssids
            FROM access_points
            WHERE essid IS NOT NULL AND essid != '[HIDDEN]'
            GROUP BY essid
            HAVING count > 1
        ''')
        
        threats = []
        for row in cursor.fetchall():
            essid, count, bssids = row
            bssid_list = bssids.split(',')
            
            if self.check_suspicious_ssid(essid):
                threats.append({
                    'type': 'evil_twin',
                    'level': 'high',
                    'essid': essid,
                    'bssids': bssid_list,
                    'description': f'Multiple access points ({count}) broadcasting same SSID: {essid}'
                })
            else:
                threats.append({
                    'type': 'possible_evil_twin',
                    'level': 'medium',
                    'essid': essid,
                    'bssids': bssid_list,
                    'description': f'{count} APs with identical SSID (may be legitimate mesh/repeater)'
                })
        
        conn.close()
        return threats
    
    def detect_hidden_networks(self):
        """Detect hidden networks"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT bssid, rssi, channel, first_seen
            FROM access_points
            WHERE is_hidden = 1
        ''')
        
        threats = []
        for row in cursor.fetchall():
            bssid, rssi, channel, first_seen = row
            threats.append({
                'type': 'hidden_network',
                'level': 'low',
                'bssid': bssid,
                'essid': '[HIDDEN]',
                'description': f'Hidden network detected (BSSID: {bssid}, Ch: {channel})'
            })
        
        conn.close()
        return threats
    
    def detect_signal_anomalies(self):
        """Detect unusual signal strength patterns"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT bssid, essid, rssi, channel
            FROM access_points
            WHERE rssi > -30
        ''')
        
        threats = []
        for row in cursor.fetchall():
            bssid, essid, rssi, channel = row
            threats.append({
                'type': 'strong_signal_anomaly',
                'level': 'medium',
                'bssid': bssid,
                'essid': essid,
                'description': f'Unusually strong signal (RSSI: {rssi} dBm) - AP may be very close or using high power'
            })
        
        conn.close()
        return threats
    
    def detect_deauth_attacks(self):
        """Detect potential deauthentication attacks"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT station_mac, COUNT(*) as connection_count
            FROM stations
            WHERE timestamp > datetime('now', '-5 minutes')
            GROUP BY station_mac
            HAVING connection_count > 10
        ''')
        
        threats = []
        for row in cursor.fetchall():
            station_mac, count = row
            threats.append({
                'type': 'possible_deauth_attack',
                'level': 'high',
                'station_mac': station_mac,
                'description': f'Station {station_mac} reconnecting frequently ({count} times in 5 min) - possible deauth attack'
            })
        
        conn.close()
        return threats
    
    def analyze_all_threats(self):
        """Run all threat detection algorithms"""
        print("\n" + "="*70)
        print("🔍 Wi-Spy Sentinel - Threat Analysis Report")
        print("="*70)
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        all_threats = []
        threat_counts = {'high': 0, 'medium': 0, 'low': 0}
        
        # Run all detections
        print("[*] Checking for suspicious SSIDs...")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = 'SELECT bssid, essid, rssi, channel, location FROM access_points WHERE essid IS NOT NULL'
        
        cursor.execute(query)
        
        for row in cursor.fetchall():
            bssid, essid, rssi, channel, location = row
            if self.check_suspicious_ssid(essid):
                threat = {
                    'type': 'suspicious_ssid',
                    'level': 'high',
                    'bssid': bssid,
                    'essid': essid,
                    'location': location,
                    'description': f'Suspicious network name pattern detected: "{essid}"'
                }
                all_threats.append(threat)
                threat_counts['high'] += 1
        conn.close()
        
        print("[*] Detecting evil twin attacks...")
        evil_twins = self.detect_evil_twin()
        for threat in evil_twins:
            all_threats.append(threat)
            threat_counts[threat['level']] += 1
        
        print("[*] Detecting hidden networks...")
        hidden = self.detect_hidden_networks()
        for threat in hidden:
            all_threats.append(threat)
            threat_counts[threat['level']] += 1
        
        print("[*] Analyzing signal anomalies...")
        signal_threats = self.detect_signal_anomalies()
        for threat in signal_threats:
            all_threats.append(threat)
            threat_counts[threat['level']] += 1
        
        print("[*] Checking for deauth attacks...")
        deauth_threats = self.detect_deauth_attacks()
        for threat in deauth_threats:
            all_threats.append(threat)
            threat_counts[threat['level']] += 1
        
        # Display results
        print("\n" + "-"*70)
        print("📊 THREAT SUMMARY")
        print("-"*70)
        print(f"🔴 High Severity:   {threat_counts['high']}")
        print(f"🟡 Medium Severity: {threat_counts['medium']}")
        print(f"🟢 Low Severity:    {threat_counts['low']}")
        print(f"   Total Threats:   {len(all_threats)}")
        
        if all_threats:
            print("\n" + "-"*70)
            print("⚠️  DETECTED THREATS")
            print("-"*70)
            
            severity_order = {'high': 0, 'medium': 1, 'low': 2}
            all_threats.sort(key=lambda x: severity_order[x['level']])
            
            for i, threat in enumerate(all_threats, 1):
                level_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}
                print(f"\n{i}. {level_emoji[threat['level']]} {threat['type'].upper().replace('_', ' ')}")
                print(f"   {threat['description']}")
                if 'essid' in threat:
                    print(f"   SSID: {threat['essid']}")
                if 'bssid' in threat:
                    print(f"   BSSID: {threat['bssid']}")
                if 'bssids' in threat:
                    print(f"   BSSIDs: {', '.join(threat['bssids'][:3])}{'...' if len(threat['bssids']) > 3 else ''}")
        else:
            print("\n✅ No threats detected. All networks appear safe.")
        
        print("\n" + "="*70 + "\n")
        
        # Save threats to database
        self.save_threats_to_db(all_threats)
        
        return all_threats
    
    def save_threats_to_db(self, threats):
        """Save detected threats to database and update access_points threat_level"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()
        
        # First, reset all threat levels to 'safe'
        cursor.execute("UPDATE access_points SET threat_level = 'safe'")
        
        # Save threats and update access_points
        for threat in threats:
            # Insert into threats table
            cursor.execute('''
                INSERT INTO threats (timestamp, bssid, essid, threat_type, threat_level, description, location)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, 
                  threat.get('bssid', 'N/A'),
                  threat.get('essid', 'N/A'),
                  threat['type'],
                  threat['level'],
                  threat['description'],
                  threat.get('location', 'Unknown')))
            
            # Update threat_level in access_points table
            if 'bssid' in threat and threat['bssid'] != 'N/A':
                cursor.execute('''
                    UPDATE access_points 
                    SET threat_level = ? 
                    WHERE bssid = ?
                ''', (threat['level'], threat['bssid']))
            elif 'essid' in threat and threat['essid'] != 'N/A':
                cursor.execute('''
                    UPDATE access_points 
                    SET threat_level = ? 
                    WHERE essid = ?
                ''', (threat['level'], threat['essid']))
        
        conn.commit()
        conn.close()
        
        print(f"[✓] Updated threat levels in database")


if __name__ == "__main__":
    detector = ThreatDetector()
    detector.analyze_all_threats()