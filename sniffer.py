#!/usr/bin/env python3
"""Basic network sniffer (CodeAlpha Task 1). Use only on networks you own or are authorised to test."""
import argparse
import sys
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw

packets_saved = []
counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "OTHER": 0}


def preview(pkt, n=60):
    if Raw in pkt:
        data = bytes(pkt[Raw].load)[:n]
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return ""


def handle(pkt):
    ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    if ip is None:
        counts["OTHER"] += 1
        return
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {ip.src} -> {ip.dst}"
    if DNS in pkt and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        counts["DNS"] += 1
        line += f" DNS query: {pkt[DNSQR].qname.decode(errors='replace')}"
    elif TCP in pkt:
        counts["TCP"] += 1
        t = pkt[TCP]
        line += f" TCP {t.sport}->{t.dport} flags={t.sprintf('%flags%')} len={len(pkt)}"
    elif UDP in pkt:
        counts["UDP"] += 1
        u = pkt[UDP]
        line += f" UDP {u.sport}->{u.dport} len={len(pkt)}"
    elif ICMP in pkt:
        counts["ICMP"] += 1
        line += f" ICMP type={pkt[ICMP].type}"
    else:
        counts["OTHER"] += 1
        line += f" proto={ip.proto if hasattr(ip, 'proto') else 'ipv6'}"
    p = preview(pkt)
    if p:
        line += f"\n    payload: {p}"
    print(line)
    packets_saved.append(pkt)


def main():
    ap = argparse.ArgumentParser(description="Simple packet sniffer")
    ap.add_argument("-i", "--iface", help="interface (default: scapy default)")
    ap.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = unlimited)")
    ap.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    ap.add_argument("-w", "--write", help="save capture to .pcap file")
    a = ap.parse_args()
    print("Sniffing... press Ctrl+C to stop (needs root/Administrator)")
    try:
        sniff(iface=a.iface, filter=a.filter, prn=handle, count=a.count, store=False)
    except PermissionError:
        sys.exit("Permission denied: run with sudo / as Administrator.")
    except KeyboardInterrupt:
        pass
    print("\nSummary:", ", ".join(f"{k}={v}" for k, v in counts.items()))
    if a.write and packets_saved:
        wrpcap(a.write, packets_saved)
        print(f"Saved {len(packets_saved)} packets to {a.write}")


if __name__ == "__main__":
    main()
