# Exfiltrap Unified Sniffer Agent

A comprehensive network traffic analysis and detection system designed for monitoring DNS tunneling, DGA (Domain Generation Algorithms), and DNS abuse. This project consolidates multiple sniffing capabilities into a single, high-performance C++ agent with Python-based data aggregation and Google Sheets/MySQL integration.

## 📂 Project Structure

- `unified_sniffer_agent/`: The core C++ agent source code and build system.
- `sniffer_dnsAbuse/`: Java-based flow analysis and DNS DPI tools.
- `tunneling_event_aggregator/`: Python scripts for real-time event aggregation and processing.
- `exfiltrap_v2.0-sniffer_agent/`: Legacy Python-based sniffer components.
- `scripts/`: Utility scripts for database setup and environment configuration.

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

1.  **C++ Build Tools**: Visual Studio 2022 (with "Desktop development with C++") is recommended for Windows.
2.  **CMake**: Version 3.20 or higher.
3.  **Npcap**: Install the latest [Npcap driver](https://nmap.org/npcap/) and download the **Npcap SDK**.
4.  **MySQL Server**: For local data storage (Version 8.0+).
5.  **Python 3.x**: Required for the data uploader and aggregator scripts.
6.  **Git**: For version control.

## ⚙️ Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/sayu-gtss/sniffer-agent.git
cd sniffer-agent
```

### 2. Configure Credentials (CRITICAL)
The project requires a Google Service Account to upload data to Google Sheets.
- Obtain a `service-account.json` file from your Google Cloud Console.
- Place it in the root directory of this project.
> [!WARNING]
> This file is ignored by Git for security. Do NOT share your credentials.

### 3. Database Initialization
Run the provided SQL script to create the necessary tables in your MySQL database:
```bash
mysql -u your_user -p < table-creation-query.sql
```

## 🔨 Building the Agent

Navigate to the `unified_sniffer_agent` directory and use the automated build scripts:

1.  **Install Dependencies**:
    ```powershell
    .\installer\windows\Install-Prereqs.ps1
    ```
2.  **Build the Project**:
    ```powershell
    .\installer\windows\Build-Agent.ps1
    ```

The compiled executable will be located in `unified_sniffer_agent/bin/`.

## 🚀 Running the Agent

1.  **Configuration**: Edit `unified_sniffer_agent/config/agent.prod.config.json` with your network interface ID and database credentials.
2.  **Start Sniffing**:
    ```powershell
    .\installer\windows\Run-Agent.ps1
    ```

## 📄 Documentation

- [Introduction to Features](file:///sniffer_explanations.md)
- [DNS Feature Analysis](file:///dns_features.md)
- [Database Schema Details](file:///database_tables.md)
- [Theory & Architecture](file:///unified_sniffer_architecture_theory.md)
