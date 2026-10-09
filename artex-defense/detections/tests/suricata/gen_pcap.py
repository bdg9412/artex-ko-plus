#!/usr/bin/env python3
"""Deterministic pcap generator for the ARTEX Suricata rule tests.

Synthesizes N independent plaintext HTTP request/response flows from a single
source, each carrying a chosen User-Agent, so `suricata -r` can be run offline
to prove the rules in ../../suricata/artex.rules fire (or stay silent) exactly
as documented. Output is regenerated on every run and is never committed -- the
test ships as source, not as a binary capture.

Usage:
    gen_pcap.py <out.pcap> <user-agent> [num_flows] [interval_seconds]

The capture is fully deterministic: fixed addresses, ports derived from the
flow index, a fixed base timestamp, and flows spaced `interval_seconds` apart.
Nothing here sends a packet or touches a network -- it only writes a file.
"""
import sys

from scapy.all import Ether, IP, TCP, Raw, wrpcap

# Fixed, private, non-routable endpoints. One source so Suricata's
# `detection_filter ... track by_src` on sid 1000002 counts per source.
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"
SRC_IP = "10.10.10.9"
DST_IP = "10.10.10.80"
DST_PORT = 80
BASE_EPOCH = 1_760_000_000.0  # fixed so timestamps never depend on wall clock
CLIENT_ISN = 1000
SERVER_ISN = 2000


def http_request(user_agent: str) -> bytes:
    return (
        "GET /products?category=all HTTP/1.1\r\n"
        "Host: shop.example.test\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()


HTTP_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 13\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<html></html>"
).encode()


def flow(index: int, user_agent: str, t0: float):
    """One complete TCP+HTTP conversation; returns a list of timestamped packets."""
    sport = 40000 + index
    eth_c = Ether(src=SRC_MAC, dst=DST_MAC)
    eth_s = Ether(src=DST_MAC, dst=SRC_MAC)
    ip_c = IP(src=SRC_IP, dst=DST_IP)
    ip_s = IP(src=DST_IP, dst=SRC_IP)

    req = http_request(user_agent)
    rlen = len(req)
    slen = len(HTTP_RESPONSE)

    pkts = []

    def add(pkt, offset):
        pkt.time = t0 + offset
        pkts.append(pkt)

    # Handshake
    add(eth_c / ip_c / TCP(sport=sport, dport=DST_PORT, flags="S", seq=CLIENT_ISN), 0.000)
    add(eth_s / ip_s / TCP(sport=DST_PORT, dport=sport, flags="SA", seq=SERVER_ISN, ack=CLIENT_ISN + 1), 0.001)
    add(eth_c / ip_c / TCP(sport=sport, dport=DST_PORT, flags="A", seq=CLIENT_ISN + 1, ack=SERVER_ISN + 1), 0.002)
    # Request
    add(eth_c / ip_c / TCP(sport=sport, dport=DST_PORT, flags="PA", seq=CLIENT_ISN + 1, ack=SERVER_ISN + 1) / Raw(req), 0.003)
    add(eth_s / ip_s / TCP(sport=DST_PORT, dport=sport, flags="A", seq=SERVER_ISN + 1, ack=CLIENT_ISN + 1 + rlen), 0.004)
    # Response
    add(eth_s / ip_s / TCP(sport=DST_PORT, dport=sport, flags="PA", seq=SERVER_ISN + 1, ack=CLIENT_ISN + 1 + rlen) / Raw(HTTP_RESPONSE), 0.005)
    add(eth_c / ip_c / TCP(sport=sport, dport=DST_PORT, flags="A", seq=CLIENT_ISN + 1 + rlen, ack=SERVER_ISN + 1 + slen), 0.006)
    # Teardown
    add(eth_c / ip_c / TCP(sport=sport, dport=DST_PORT, flags="FA", seq=CLIENT_ISN + 1 + rlen, ack=SERVER_ISN + 1 + slen), 0.007)
    add(eth_s / ip_s / TCP(sport=DST_PORT, dport=sport, flags="A", seq=SERVER_ISN + 1 + slen, ack=CLIENT_ISN + 2 + rlen), 0.008)
    add(eth_s / ip_s / TCP(sport=DST_PORT, dport=sport, flags="FA", seq=SERVER_ISN + 1 + slen, ack=CLIENT_ISN + 2 + rlen), 0.009)
    add(eth_c / ip_c / TCP(sport=sport, dport=DST_PORT, flags="A", seq=CLIENT_ISN + 2 + rlen, ack=SERVER_ISN + 2 + slen), 0.010)
    return pkts


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    out = sys.argv[1]
    user_agent = sys.argv[2]
    num_flows = int(sys.argv[3]) if len(sys.argv) > 3 else 35
    interval = float(sys.argv[4]) if len(sys.argv) > 4 else 1.0

    packets = []
    for i in range(num_flows):
        packets.extend(flow(i, user_agent, BASE_EPOCH + i * interval))

    wrpcap(out, packets)
    print(f"wrote {len(packets)} packets across {num_flows} flows to {out} (UA={user_agent!r})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
