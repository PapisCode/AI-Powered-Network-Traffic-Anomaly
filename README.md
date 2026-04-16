# AI-Powered Network Traffic Anomaly Detector

## Overview
This project captures real-time network using Scapy and applies machine learning to detect anomalies such as DDoS attacks and port scanning.

The goal is to detect suspicious network behaviour such as:
- Port scanning
- DDoS-like traffic patterns
- Unusual protocol activity

## Technologies
- Python
- Scapy
- Pandas
- NumPy
- Scikit-learn

## Status & Completion
Phase 1: Project setup and packet capture / packet capture implemented and tested (completed)
- Real-time packet sniffing using Scappy
- Supports TCP, UDP, and ICMP protocols
- Extracts:
    - Source IP
    - Destination IP
    - Source/Destination ports

Phase 2: Feature Extraction (completed)
- Aggregates traffic into time windows (5 seconds)
- Covnerts raw packets into structured data
- Extracted features:
    - Total packet count
    - TCP/UDP/ICMP counts
    - Unique source IPs
    - Unique destination IPs
    - Unique destination ports

## Example outputs:
=== Traffic Summary (5s window) ===
packet_count: 199
tcp_count: 118
udp_count: 81
icmp_count: 0
unique_src_ips: 9
unique_dst_ips: 9
unique_dst_ports: 12

=== Traffic Summary (5s window) ===
packet_count: 182
tcp_count: 71
udp_count: 111
icmp_count: 0
unique_src_ips: 12
unique_dst_ips: 12
unique_dst_ports: 18
==================================






