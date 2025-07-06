# ARP-Spoof-Sniff

Python toolkit for ARP spoofing, HTTP sniffing, and network scanning on local networks.

---

##  Overview

**arp-spoof-sniff** demonstrates how ARP cache poisoning can be used to intercept traffic between devices on a local network.  
It includes:

- An ARP spoofer that poisons ARP caches of the victim and gateway
- A network scanner to discover live hosts
- An HTTP sniffer that extracts visited URLs and possible credentials

** For educational and authorized security testing only.**

---

##  Features

- Realtime ARP spoofing with auto ARP table restoration  
- HTTP packet capture with URL and credential extraction  
- Simple ARP network scanner  
- Flexible command-line interface (`argparse`)  
- Clean modular codebase (`utils.py` for shared functions)

---

##  Legal Disclaimer

This project is provided for **educational purposes only.**  
Unauthorized use against networks you do not own or without explicit permission is **illegal and unethical.**

---

##  Installation

1️ Clone the repository:
git clone https://github.com/YOUR_USERNAME/arp-spoof-sniff.git
cd arp-spoof-sniff

2️ Install dependencies:
pip install -r requirements.txt



-Quick Start: How to Run Everything
Below is a recommended flow to test this toolkit in your lab network.

1️ Identify Live Hosts (Network Scanner)
Scan your subnet to discover devices:
sudo python3 scanner.py -r 192.168.1.0/24 -i eth0

2️ Enable IP Forwarding
IMPORTANT:
Enable IP forwarding so your machine will forward packets between victim and gateway:
echo 1 > /proc/sys/net/ipv4/ip_forward

3️ Start the ARP Spoofer
Run the spoofer with target and gateway IPs:
sudo python3 spoofer.py -t <TARGET_IP> -g <GATEWAY_IP> -i eth0
This continuously poisons the ARP tables.

4️ Start the HTTP Sniffer
Open a new terminal and run the sniffer:
sudo python3 sniffer.py -i eth0

5️ Stopping the Attack
Press CTRL+C in the spoofer terminal.
The tool will automatically restore ARP tables.
Press CTRL+C in the sniffer to stop capturing.

##  Screenshots

**ARP Spoofer Running:**
![ARP Spoofer]

**HTTP Sniffer Capturing Credentials:**
![HTTP Sniffer]

 Project Structure
arp-spoof-sniff/
├── scanner.py      # Network scanner
├── sniffer.py      # HTTP sniffer
├── spoofer.py      # ARP spoofer
├── utils.py        # Shared helper functions
├── requirements.txt
