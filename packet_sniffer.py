#!/usr/bin/env python3
"""
Basic Network Sniffer
----------------------
Captures live network packets and displays useful information:
source/destination IPs, protocol, ports, and a preview of the payload.

Requirements:
    pip install scapy

Usage:
    sudo python3 packet_sniffer.py            # sniff all traffic
    sudo python3 packet_sniffer.py -i eth0    # sniff a specific interface
    sudo python3 packet_sniffer.py -f "tcp"   # apply a BPF filter
    sudo python3 packet_sniffer.py -c 50      # stop after 50 packets

NOTE: Packet sniffing requires elevated privileges.
    - Linux/Mac: run with sudo
    - Windows: run as Administrator (and install Npcap first)
Only capture traffic on networks you own or have explicit permission to monitor.
"""

import argparse
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def get_protocol_name(packet):
    """Return a human-readable protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def get_payload_preview(packet, max_len=64):
    """Extract a safe, printable preview of the raw payload, if any."""
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        # Try to decode as text; fall back to hex if it's binary data
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            text = text.replace("\n", "\\n").replace("\r", "\\r")
        except Exception:
            text = raw_bytes.hex()
        return text[:max_len] + ("..." if len(text) > max_len else "")
    return "(no payload)"


def packet_count_state(count_holder):
    """Closure to keep a running count of packets seen (for display numbering)."""
    def _increment():
        count_holder[0] += 1
        return count_holder[0]
    return _increment


def make_packet_handler():
    counter = [0]
    increment = packet_count_state(counter)

    def handle_packet(packet):
        pkt_num = increment()
        timestamp = datetime.now().strftime("%H:%M:%S")

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = get_protocol_name(packet)

            # Port info if TCP/UDP
            src_port = dst_port = None
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            port_info = f"{src_port} -> {dst_port}" if src_port else "N/A"
            payload_preview = get_payload_preview(packet)
            length = len(packet)

            print(f"[{pkt_num:04d}] {timestamp} | {protocol:5s} | "
                  f"{src_ip}:{src_port if src_port else '-':<6} -> "
                  f"{dst_ip}:{dst_port if dst_port else '-':<6} | "
                  f"len={length}")
            print(f"         Payload: {payload_preview}")
            print("-" * 90)
        else:
            # Non-IP packet (e.g., ARP) — show a minimal summary
            print(f"[{pkt_num:04d}] {timestamp} | Non-IP packet: {packet.summary()}")
            print("-" * 90)

    return handle_packet


def main():
    parser = argparse.ArgumentParser(description="Basic Python Network Sniffer")
    parser.add_argument("-i", "--interface", default=None,
                         help="Network interface to sniff on (default: scapy auto-selects)")
    parser.add_argument("-f", "--filter", default="",
                         help='BPF filter string, e.g. "tcp", "udp port 53", "icmp"')
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = infinite, stop with Ctrl+C)")
    args = parser.parse_args()

    print("=" * 90)
    print(" Basic Network Sniffer — Ctrl+C to stop")
    print(f" Interface: {args.interface or 'auto'} | Filter: '{args.filter or 'none'}' | "
          f"Count: {'infinite' if args.count == 0 else args.count}")
    print("=" * 90)

    handler = make_packet_handler()

    try:
        sniff(
            iface=args.interface,
            filter=args.filter if args.filter else None,
            prn=handler,
            store=False,          # don't keep packets in memory, just process & discard
            count=args.count if args.count > 0 else 0,
        )
    except PermissionError:
        print("\n[ERROR] Permission denied. Try running with sudo (Linux/Mac) "
              "or as Administrator (Windows).")
    except KeyboardInterrupt:
        print("\n[INFO] Sniffing stopped by user.")


if __name__ == "__main__":
    main()
