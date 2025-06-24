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

## ⚙ Working

The **Network Packet Analyzer** captures live network traffic by opening a raw socket on the selected network interface. Here's how it works:

1. **Start of Execution**

   * On launch, the tool displays a legal disclaimer and begins capturing packets.
   * It attempts to access low-level network interfaces, which **requires administrator privileges** on Windows.

2. **Packet Sniffing**

   * The tool uses Python’s `socket` or `scapy` libraries to listen for incoming/outgoing traffic.
   * Each packet is intercepted at the network layer before it is handled by the OS or application.

3. **Packet Parsing**

   * Extracts key metadata from each packet:

     * **Protocol** (TCP, UDP, ICMP, etc.)
     * **Source IP** and **Destination IP**
     * **Port numbers**, **packet size**, and possibly **payload data** (if enabled)

4. **Logging & Output**

   * Each captured packet is printed in real-time to the console.
   * Optionally, packets can be logged to a file or filtered by protocol type.

5. **Stopping the Capture**

   * The process can be stopped at any time using `Ctrl + C`.
   * A graceful exit ensures all resources are released.

---

### 📌 Example Output

```
[+] Packet Captured:
    Protocol: TCP
    Source IP: 192.168.1.2
    Destination IP: 142.250.183.78
    Source Port: 55642
    Destination Port: 443
    Packet Length: 60 bytes
```

Let me know if you'd like the output visualized in a GUI or logged to CSV/JSON for further analysis — I can help extend the functionality too.


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
