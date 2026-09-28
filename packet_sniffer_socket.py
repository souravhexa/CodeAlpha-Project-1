#!/usr/bin/env python3
"""
Basic Network Sniffer (raw socket version)
-------------------------------------------
Uses Python's built-in `socket` module (no external libraries) to capture
packets and manually parse the Ethernet/IP/TCP/UDP headers. This is more
verbose than scapy, but shows exactly how packet structure works at the
byte level — useful for learning.

LIMITATIONS:
    - Linux only (uses AF_PACKET raw sockets to see full Ethernet frames).
    - Must be run as root: sudo python3 packet_sniffer_socket.py
    - On Windows/Mac, use packet_sniffer.py (scapy version) instead.

Only capture traffic on networks you own or have explicit permission to monitor.
"""

import socket
import struct
from datetime import datetime


def format_mac(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)


def parse_ethernet_header(raw_data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", raw_data[:14])
    return format_mac(dest_mac), format_mac(src_mac), socket.htons(proto), raw_data[14:]


def parse_ipv4_header(raw_data):
    version_header_len = raw_data[0]
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(target)
    return proto, ttl, src_ip, dst_ip, raw_data[header_len:]


def parse_tcp_header(raw_data):
    (src_port, dst_port, seq, ack, offset_flags) = struct.unpack("! H H L L H", raw_data[:14])
    offset = (offset_flags >> 12) * 4
    return src_port, dst_port, raw_data[offset:]


def parse_udp_header(raw_data):
    src_port, dst_port, length, _ = struct.unpack("! H H H H", raw_data[:8])
    return src_port, dst_port, raw_data[8:]


def preview_payload(data, max_len=64):
    if not data:
        return "(no payload)"
    try:
        text = data.decode("utf-8", errors="replace").replace("\n", "\\n").replace("\r", "\\r")
    except Exception:
        text = data.hex()
    return text[:max_len] + ("..." if len(text) > max_len else "")


def main():
    try:
        # AF_PACKET + ETH_P_ALL captures every frame on the wire, raw.
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("[ERROR] Permission denied. Run this with: sudo python3 packet_sniffer_socket.py")
        return
    except AttributeError:
        print("[ERROR] AF_PACKET is not available on this OS. "
              "This script works on Linux only — use packet_sniffer.py (scapy) instead.")
        return

    print("=" * 90)
    print(" Basic Network Sniffer (raw socket) — Ctrl+C to stop")
    print("=" * 90)

    pkt_num = 0
    try:
        while True:
            raw_data, _ = sock.recvfrom(65535)
            pkt_num += 1
            timestamp = datetime.now().strftime("%H:%M:%S")

            dest_mac, src_mac, eth_proto, eth_payload = parse_ethernet_header(raw_data)

            # 0x0800 = IPv4
            if eth_proto != 0x0800:
                print(f"[{pkt_num:04d}] {timestamp} | Non-IPv4 frame "
                      f"(ethertype=0x{eth_proto:04x}) {src_mac} -> {dest_mac}")
                print("-" * 90)
                continue

            proto, ttl, src_ip, dst_ip, ip_payload = parse_ipv4_header(eth_payload)

            if proto == 6:  # TCP
                src_port, dst_port, payload = parse_tcp_header(ip_payload)
                proto_name = "TCP"
            elif proto == 17:  # UDP
                src_port, dst_port, payload = parse_udp_header(ip_payload)
                proto_name = "UDP"
            elif proto == 1:  # ICMP
                proto_name = "ICMP"
                src_port = dst_port = None
                payload = ip_payload[8:]  # skip ICMP header
            else:
                proto_name = f"PROTO-{proto}"
                src_port = dst_port = None
                payload = ip_payload

            port_info = f"{src_port} -> {dst_port}" if src_port else "N/A"
            print(f"[{pkt_num:04d}] {timestamp} | {proto_name:5s} | "
                  f"{src_ip}:{src_port if src_port else '-':<6} -> "
                  f"{dst_ip}:{dst_port if dst_port else '-':<6} | TTL={ttl}")
            print(f"         Payload: {preview_payload(payload)}")
            print("-" * 90)

    except KeyboardInterrupt:
        print("\n[INFO] Sniffing stopped by user.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
