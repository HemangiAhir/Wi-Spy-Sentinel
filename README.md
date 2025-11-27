Wi-Spy Sentinel 2.0 
Wi-Fi Threat Detection System using Flipper Zero & Raspberry Pi
A security tool that scans Wi-Fi networks to detect malicious access points, evil twin attacks, hidden networks, and other wireless threats.
________________________________________
Overview
Wi-Spy Sentinel analyzes Wi-Fi networks in your area and identifies security threats using pattern matching and heuristic analysis. Compare the safety of different locations (home vs public WiFi) with visual reports.
Key Features
•	 Real-time scanning from Flipper Zero
•	Threat detection - Identifies 5 types of attacks
•	Log file analysis - Analyze saved scans
•	Visual comparisons - Compare locations with charts
•	 Threat classification - High/Medium/Low severity
•	Database storage - Track networks over time
________________________________________
Hardware Requirements
•	Flipper Zero with ESP32 Wi-Fi board
•	Computer (Windows/Linux/Mac)
•	USB Cable (optional - for live scanning)
________________________________________
 Installation
1. Install Python Libraries
pip install pyserial matplotlib
2. Download Files
Save these 5 files in the same folder:
•	wifi_scanner.py
•	threat_detector.py
•	log_analyzer.py
•	wispy.py
•	compare_scans.py
________________________________________
Quick Start
Analyze a Flipper Zero Log File
# Import home scan
py wispy.py analyze -f flipper_scan.log -l "Home Area" --threats

# Import public WiFi scan
py wispy.py analyze -f public_scan.log -l "Coffee Shop" --threats

# Compare the two locations
py compare_scans.py
Live Scanning (Flipper connected via USB)
py wispy.py scan --port COM3 -l "Office"
________________________________________
What It Detects
1. Suspicious Network Names - HIGH
Networks with names designed to trick users:
•	"Free WiFi", "Airport WiFi"
•	Default router names: "NETGEAR25", "Linksys"
•	Social engineering: "Windows Update"
2. Evil Twin Attacks - HIGH
Multiple routers broadcasting the same network name (one is fake).
3. Hidden Networks - LOW
Networks that don't broadcast their name (sometimes used to hide).
4. Signal Anomalies - MEDIUM
Unusually strong signals (RSSI > -30 dBm) indicating a device very close to you.
5. Deauth Attacks - HIGH
Devices being kicked off WiFi repeatedly (reconnecting 10+ times in 5 minutes).
________________________________________
How Threat Detection Works
No Machine Learning - Uses Rule-Based Detection
The system uses heuristic pattern matching and threshold detection:
1. Pattern Matching (Regex)
Suspicious patterns = ["free.*wifi", "netgear\d+", "airport.*wifi"]
If network name matches → FLAG as suspicious
2. Threshold Detection
If signal strength > -30 dBm → TOO STRONG (suspicious)
If device reconnects > 10 times/5min → Possible attack
3. Duplicate Detection
If multiple MAC addresses broadcast same name → Evil twin
4. Whitelist Filtering
Known safe networks = ["eduroam", "govwifi"]
Ignore these from flagging
Why No Machine Learning?
Faster - Instant detection without training
Transparent - You can see exactly why something is flagged
 Reliable - No false positives from model drift
Lightweight - Runs on any device
Future versions could add ML for anomaly detection based on historical patterns.
________________________________________
 Project Structure
wifi-sentinel/
├── wifi_scanner.py          # Real-time scanner
├── threat_detector.py       # Threat analysis engine
├── log_analyzer.py          # Log file parser
├── wispy.py                 # Main control script
├── compare_scans.py         # Visualization tool
├── wispy.db                 # SQLite database (auto-created)
└── README.md               # This file
________________________________________
Usage Examples
Example 1: Home Security Audit
py wispy.py analyze -f home_scan.log -l "Home" --threats
py wispy.py list
Example 2: Public WiFi Safety Check
py wispy.py analyze -f airport_scan.log -l "Airport" --threats
py wispy.py list --open  # Show unencrypted networks
Example 3: Compare Two Locations
py wispy.py analyze -f home.log -l "Home" --threats
py wispy.py analyze -f mall.log -l "Mall" --threats
py compare_scans.py
Example 4: Export Data
py wispy.py export --format csv --output results.csv
py wispy.py threats --export threats.json
________________________________________
Understanding the Results
Threat Report Example
 THREAT SUMMARY
─────────────────────
High Severity:   5
Medium Severity: 2
Low Severity:    1
   Total Threats:   8

DETECTED THREATS
─────────────────────
1.	SUSPICIOUS SSID
   Suspicious network name: "Free Airport WiFi"
   BSSID: aa:bb:cc:dd:ee:ff
Comparison Chart
The visualization creates 6 charts showing:
•	Threat level comparison (bar chart)
•	Security status (pie charts)
•	Channel congestion
•	Signal strength distribution
•	Key metrics table
________________________________________
Real-World Results
Example: Home vs Public WiFi
Home Area:
•	20 networks scanned
•	0 threats found (0%)
•	All networks legitimate
Coffee Shop:
•	25 networks scanned
•	5 threats found (20%)
•	NETGEAR routers with default names
•	Suspicious "Freeman WiFi" network
Verdict: Public WiFi is 20% more dangerous than home!
________________________________________
Limitations
What It CAN Detect:
	Suspicious network names
	Evil twin attacks (duplicate names)
	Hidden network
	Signal strength anomalies
	Reconnection patterns
What It CANNOT Detect:
	Man-in-the-middle attacks in progress
	DNS hijacking
	SSL certificate spoofing
	Actual malicious traffic content
	 Zero-day attacks
This tool is ONE layer of security. Always use VPN on public Wi-Fi!
________________________________________
Customization
Add Custom Suspicious Patterns
Edit threat_detector.py:
self.suspicious_patterns = [
    r'free.*wifi',
    r'your_pattern_here',  # Add your own
]
Whitelist Legitimate Networks
self.whitelist = [
    'eduroam',
    'YourCompanyWiFi',  # Won't be flagged
]
Adjust Signal Threshold
# In detect_signal_anomalies()
WHERE rssi > -25  # Change from -30 to -25
________________________________________
 Technical Details
Detection Algorithms
Algorithm 1: SSID Pattern Matching
Time: O(n*m) where n=networks, m=patterns
Space: O(1)
Method: Regex matching
Algorithm 2: Evil Twin Detection
Time: O(n log n) for grouping
Space: O(n)
Method: SQL GROUP BY with COUNT
Algorithm 3: Signal Analysis
Time: O(n)
Space: O(1)
Method: Simple threshold check
Algorithm 4: Deauth Detection
Time: O(n)
Space: O(k) where k=unique devices
Method: Connection frequency analysis
Database Schema
access_points (
    bssid TEXT,           -- MAC address
    essid TEXT,           -- Network name
    rssi INTEGER,         -- Signal strength
    channel INTEGER,      -- WiFi channel
    threat_level TEXT,    -- high/medium/low/safe
    location TEXT         -- Scan location
)
________________________________________
 Security & Ethics
Legal Use Only
	Scanning your own network
	Educational research in controlled environment
	Authorized security auditing
	Scanning networks without permission
	Interfering with others' WiFi
	Using for malicious purposes
This tool is for defensive security only.
________________________________________
Troubleshooting
Common Issues
"Module not found: pyserial"
pip install pyserial
"matplotlib not found"
pip install matplotlib
"No locations found"
# You forgot --threats flag
py wispy.py analyze -f scan.log -l "Location" --threats
Serial port not found
# Windows: Check Device Manager for COM port
# Linux: Use /dev/ttyUSB0 or /dev/ttyACM0
________________________________________
Performance
•	Scan speed: ~1000 networks/minute
•	Analysis time: <1 second for 100 networks
•	Database size: ~1MB per 10,000 networks
•	Memory usage: <50MB
•	CPU usage: Minimal (<5%)
________________________________________
👥 Contributing
Contributions welcome! Areas to improve:
•	Additional threat patterns
•	Better visualization
•	Performance optimization
•	Documentation
•	Testing

icense
Educational use only. Use responsibly and ethically.
Disclaimer: The author is not responsible for the misuse of this tool. Always comply with local laws regarding wireless network monitoring.
________________________________________
 Acknowledgments
•	Flipper Zero community
•	ESP32 Marauder project
•	WiFi security research community
________________________________________

