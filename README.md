# CodeAlpha Network Sniffer

Python/scapy packet sniffer for CodeAlpha Cyber Security Internship, Task 1.

Shows source/destination IPs, protocol (TCP/UDP/ICMP/DNS), ports, TCP flags, DNS queries and a short payload preview. Can save captures to `.pcap` for Wireshark.

## Usage
```bash
pip install -r requirements.txt
sudo python3 sniffer.py -c 20
sudo python3 sniffer.py -f "tcp port 80" -w capture.pcap
sudo python3 sniffer.py -i eth0 -f udp
```
On Windows install Npcap and run the terminal as Administrator.

## How it works
Ethernet frames carry IP packets, which carry TCP/UDP/ICMP segments. scapy parses each layer; the script reads those layers and prints the fields. Payloads (e.g. plain HTTP) are readable because they are unencrypted, which is why HTTPS matters.

## Legal note
Capture only on networks you own or have written permission to test.
