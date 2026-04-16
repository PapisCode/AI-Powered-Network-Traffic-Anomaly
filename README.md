AI-Powered Network Traffic Anomaly Detector
Overview

This project captures real-time network traffic using Python and Scapy, processes the data into structured features, and applies machine learning to detect anomalous behavior.

The system is designed to identify suspicious network patterns such as:

Port scanning
DDoS-like traffic spikes
Unusual protocol or traffic distributions
Features Implemented
Phase 1: Packet Capture 
Real-time packet sniffing using Scapy
Supports TCP, UDP, and ICMP protocols
Extracts:
Source IP
Destination IP
Source/Destination ports
Phase 2: Feature Extraction 
Aggregates traffic into 5-second time windows
Converts raw packets into structured data
Extracted features:
Total packet count
TCP/UDP/ICMP counts
Unique source IPs
Unique destination IPs
Unique destination ports
Phase 3: Anomaly Detection (Machine Learning) 
Uses Isolation Forest (unsupervised ML model)
Learns normal traffic patterns from live data
Performs real-time classification:
NORMAL traffic
ANOMALY (potential suspicious activity)
Example Output
Training Phase
Collecting training data... (1/10)
packet_count: 40
tcp_count: 40
udp_count: 0
icmp_count: 0
After Training
=== Traffic Analysis (5s window) ===
packet_count: 31
tcp_count: 30
udp_count: 1
icmp_count: 0
unique_src_ips: 5
unique_dst_ips: 6
unique_dst_ports: 7
result: NORMAL
Technologies Used
Python 3
Scapy (packet capture)
NumPy / Pandas (data processing)
Scikit-learn (machine learning)
Matplotlib (future visualization)
Project Structure
AI-Powered-Network-Traffic-Anomaly/
│
├── src/
│   ├── main.py          # Entry point
│   ├── capture.py       # Packet capture + ML pipeline
│   ├── features.py      # Feature extraction logic
│   ├── model.py         # Anomaly detection model
│
├── data/                # Future data storage
├── models/              # Saved ML models (future)
├── reports/             # Screenshots / documentation
│
├── requirements.txt
├── README.md
└── .gitignore

How It Works
Captures live network packets using Scapy
Aggregates traffic into 5-second windows
Extracts key traffic features
Collects initial data to train the model
Uses Isolation Forest to detect anomalies in real time

How to Run
1. Activate environment
C:\venvs\ai-traffic-detector\Scripts\activate
2. Install dependencies
pip install -r requirements.txt
3. Run the detector
python src/main.py
4. Generate traffic
Browse websites
OR:
ping google.com
Current Status
- Packet capture implemented
- Feature extraction implemented
- Real-time anomaly detection implemented

Future Improvements
Detect specific attacks (port scanning, DDoS)
Log traffic data to CSV
Real-time dashboard visualization
Alert system for suspicious activity
Improve model accuracy with more features
Notes
Requires Npcap on Windows for packet sniffing
Must run with appropriate permissions
Initial training uses live traffic, so normal usage is recommended
Author







