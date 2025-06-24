# 🛰️ Network Packet Analyzer

A lightweight and educational packet analysis tool for Windows. Designed for real-time monitoring of incoming and outgoing network packets, this tool helps users understand protocol-level data flow across interfaces.

> ⚠️ **Educational Use Only**: This tool is intended strictly for learning and research. Always ensure you have appropriate permissions before capturing or analyzing network traffic.

---

##  Features

- ✅ Live network packet capture
- ✅ Logs source and destination IP addresses
- ✅ Detects protocols (TCP, UDP, ICMP, etc.)
- ✅ Displays packet metadata in real-time
- ✅ Easy to use — just run the executable
- ✅ Developed in Python, compiled with PyInstaller

---

##  Getting Started

###  Prerequisites
- **Windows OS**
- Administrator privileges (required to access raw sockets)
- Internet connection (for live packet monitoring)

###  Running the Executable

1. Right-click on **PowerShell** and choose **Run as Administrator**.
2. Run the following command:
   ```powershell
   ./Code.exe

📁 Project Root
│
├── Code.exe                   # Compiled executable
├── NETWORK PACKETS ANALYZER.py  # Original Python source code
├── README.md                  # This file


Built With:
1. Python 3.11
2. scapy / socket libraries (depending on your source code)
3. PyInstaller (for .exe compilation)

Contributing
Pull requests are welcome! If you find a bug or have a feature suggestion, feel free to open an issue or fork and improve the project.
