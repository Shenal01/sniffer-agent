# Sniffer Components Explanation

This document provides a brief explanation of the key Python scripts and the Java-based `sniffer_dnsAbuse` directory used for network traffic analysis and feature extraction.

## Python Sniffers

### `sniffer_dga&c2.py`
A lightweight Python script using Scapy to capture and analyze plain DNS queries (UDP port 53). Its primary purpose is to extract and normalize the queried domain names (reducing subdomains, stripping trailing dots) to be used as features for Machine Learning models designed to detect Domain Generation Algorithms (DGA) and Command & Control (C2) communication. It logs the timestamp, source IP, raw query, and the normalized feature to a local CSV file.

### `sniffer_tunneling.py`
A unified Python sniffing script that captures both plain DNS traffic (port 53) and HTTPS/DoH (DNS over HTTPS) flows (TCP port 443). 
- For **Plain DNS**, it extracts structural and lexical features of the domain name.
- For **DoH/HTTPS flows**, it maintains a stateful flow tracker that calculates 29 statistical features (e.g., packet length variance, inter-arrival times, bytes sent/received) once a flow is completed (TCP FIN/RST or timeout).
It writes the normalized data directly into two tabs (`plain_raw_query` and `doh_raw_query`) of a specified Google Sheet.

---

## The `sniffer_dnsAbuse` Directory (Java Project)
This directory contains a Java-based application built around `pcap4j` for advanced, high-performance network analysis. It focuses on flow-based aggregation and Deep Packet Inspection (DPI) to detect infrastructure abuse, such as DNS amplification attacks and query floods.

### `main/java/com/antigravity/traffic/`

- **`CicFlowMeter.java`**
  The main entry point (CLI application) of the project. It handles opening network interfaces for live capture or reading from PCAP files. It manages the main packet loop, passes packets to the `FlowManager`, and handles shutdown hooks to ensure all flows are properly exported to CSV or Google Sheets upon exit.

- **`FlowManager.java`**
  The central supervisor for active network flows. It receives raw packets, identifies their 5-tuple key, and routes them to the corresponding `Flow` object. It also runs periodic timeout checks to expire inactive flows (default 2 minutes) and exports completed flows to the writers.

- **`Flow.java`**
  Represents a single bidirectional network connection. It calculates general flow statistics such as Inter-Arrival Times (IAT), packet size distribution, and payload sizes for both forward and backward directions. It detects TLS handshakes (for encrypted DNS) and delegates deep inspection of port 53 traffic to the `DnsFeatureExtractor`.

- **`FlowKey.java`**
  A simple data structure that defines the unique 5-tuple identifier for a network flow: Source IP, Destination IP, Source Port, Destination Port, and Protocol (TCP/UDP).

- **`DnsFeatureExtractor.java`**
  Performs Deep Packet Inspection (DPI) on unencrypted DNS payloads. It extracts DNS-specific features such as query/response counts, query type distributions (e.g., measuring ANY or TXT records), DNS amplification factors (ratio of response size to query size), and response time variance.

- **`BasicStats.java`**
  A mathematical utility class utilizing Apache Commons Math. It is used to keep running calculations of Min, Max, Mean, Standard Deviation, and Variance for streams of values like packet lengths and inter-arrival times without storing every value in memory.

- **`GoogleSheetsWriter.java`**
  Provides integration with the Google Sheets API. It uses a service account JSON file to authenticate, automatically determines whether to create a new spreadsheet or append to an existing one, and batches flow records (e.g., every 100 rows) before sending them over the network to reduce API quota consumption.

### `main/java/com/antigravity/traffic/encrypted/`

- **`DnsProtocol.java`**
  An enumeration and detection utility that identifies the specific DNS protocol variant used in a flow. By analyzing the ports and the presence of TLS/SNI data, it classifies the flow as Traditional DNS (Port 53), DNS over TLS (DoT - Port 853), or DNS over HTTPS (DoH - Port 443).

- **`DoHServerDatabase.java`**
  A static, hardcoded signature database containing known public DNS over HTTPS (DoH) servers. It includes popular providers like Google (8.8.8.8), Cloudflare (1.1.1.1), and Quad9, checking against both destination IPs and SNI hostnames to confidently classify port 443 traffic as DoH.
