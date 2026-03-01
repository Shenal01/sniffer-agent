============================================================
Exfiltrap Unified Sniffer Agent v2.0
============================================================

Quick Setup Guide:
------------------

1. PREREQUISITES:
   - Install Npcap: Download from https://npcap.com/#download
     (Ensure "WinPcap Compatible Mode" is checked during install).
   - Visual C++ Redistributable: https://aka.ms/vs/17/release/vc_redist.x64.exe
     (Required if you see "VCRUNTIME140.dll" errors).

2. INSTALLATION:
   - Copy this entire folder (exfiltrap_v2.0-sniffer_agent) to the target machine.
   - Files included:
     - exfiltrap_v2.0-sniffer_agent.exe (The Agent)
     - libmariadb.dll (Database Connector)

3. RUNNING THE AGENT:
   - Right-click 'exfiltrap_v2.0-sniffer_agent.exe' and choose "Run as Administrator".
   - A setup window will appear.
   - Select your network adapter from the list.
   - Click "Start Sniffing".
   - The window will disappear, and the agent will run silently in the background.

4. MONITORING & STOPPING:
   - To confirm it is running: Open Task Manager -> Details -> look for 'exfiltrap_v2.0-sniffer_agent.exe'.
   - To STOP the agent (Task Manager):
     - Press Ctrl + Shift + Esc.
     - Go to the "Details" tab.
     - Right-click 'exfiltrap_v2.0-sniffer_agent.exe' and select "End Task".
   - To STOP the agent (PowerShell):
     - Run: Stop-Process -Name "exfiltrap_v2.0-sniffer_agent" -Force

5. DATABASE:
   - Data is sent to the 'exfiltrap' database on 127.0.0.1.
   - Ensure the MySQL server is running and accessible from the endpoint.

------------------------------------------------------------
Designed for High-Performance Network Traffic Analysis.
============================================================
