"""
Unit tests for packet_parser.parse_packet.

Uses Scapy to *craft* packets in memory rather than sniffing live traffic,
so these tests run anywhere (CI, container, no admin/root needed) and don't
depend on a real network interface.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether

from packet_capture.models import Protocol
from packet_capture.packet_parser import parse_packet


def _eth(pkt):
    return Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / pkt


def test_parse_tcp_syn_packet():
    pkt = _eth(IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) / TCP(sport=51000, dport=22, flags="S"))
    data = parse_packet(pkt)

    assert data is not None
    assert data.protocol == Protocol.TCP
    assert data.src_ip == "10.0.0.1"
    assert data.dst_ip == "10.0.0.2"
    assert data.src_port == 51000
    assert data.dst_port == 22
    assert data.ttl == 64
    assert data.tcp_flags == "SYN"
    assert data.src_mac == "aa:bb:cc:dd:ee:01"


def test_parse_tcp_syn_ack_flags():
    pkt = _eth(IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=22, dport=51000, flags="SA"))
    data = parse_packet(pkt)
    assert data.tcp_flags == "SYN,ACK"


def test_parse_udp_packet():
    pkt = _eth(IP(src="10.0.0.5", dst="8.8.8.8", ttl=128) / UDP(sport=53211, dport=53))
    data = parse_packet(pkt)

    assert data is not None
    assert data.protocol == Protocol.UDP
    assert data.dst_port == 53
    assert data.ttl == 128


def test_parse_icmp_packet():
    pkt = _eth(IP(src="10.0.0.1", dst="10.0.0.254") / ICMP(type=8))
    data = parse_packet(pkt)

    assert data is not None
    assert data.protocol == Protocol.ICMP
    assert data.src_ip == "10.0.0.1"
    assert data.dst_ip == "10.0.0.254"


def test_parse_arp_request():
    pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="10.0.0.1", pdst="10.0.0.254"
    )
    data = parse_packet(pkt)

    assert data is not None
    assert data.protocol == Protocol.ARP
    assert data.arp_op == "who-has"
    assert data.src_ip == "10.0.0.1"
    assert data.dst_ip == "10.0.0.254"


def test_parse_arp_reply():
    pkt = Ether() / ARP(op=2, psrc="10.0.0.254", pdst="10.0.0.1")
    data = parse_packet(pkt)
    assert data.arp_op == "is-at"


def test_parse_non_ip_non_arp_returns_none():
    # A bare Ether frame with an unsupported ethertype payload
    from scapy.packet import Raw

    pkt = Ether() / Raw(load=b"not-ip-or-arp")
    data = parse_packet(pkt)
    assert data is None


def test_packet_size_matches_wire_length():
    pkt = _eth(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"))
    data = parse_packet(pkt)
    assert data.packet_size == len(pkt)


def test_to_dict_serializes_cleanly():
    pkt = _eth(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"))
    data = parse_packet(pkt)
    d = data.to_dict()
    assert d["protocol"] == "TCP"
    assert d["src_ip"] == "10.0.0.1"
    assert isinstance(d["timestamp"], str)
    # Stage 5: payload fields round-trip through to_dict (as hex previews).
    assert "tcp_payload_preview" in d
    assert "udp_payload_preview" in d


# -- Stage 5: payload extraction ---------------------------------------------

def test_parse_tcp_with_raw_payload():
    """A TCP packet carrying a Raw layer exposes its bytes on tcp_payload."""
    from scapy.packet import Raw

    body = b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\n"
    pkt = _eth(
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=80, flags="PA")
        / Raw(load=body)
    )
    data = parse_packet(pkt)
    assert data is not None
    assert data.tcp_payload == body
    assert data.payload_length == len(body)


def test_parse_udp_with_raw_payload():
    from scapy.packet import Raw

    body = b"\x12\x34hello-dns-query-payload"
    pkt = _eth(
        IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=53211, dport=53)
        / Raw(load=body)
    )
    data = parse_packet(pkt)
    assert data is not None
    assert data.udp_payload == body


def test_parse_tcp_without_payload_has_empty_bytes():
    """A bare SYN has no application bytes; tcp_payload must be b'' not None."""
    pkt = _eth(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=80, flags="S"))
    data = parse_packet(pkt)
    assert data.tcp_payload == b""
    assert data.udp_payload == b""


def test_parse_payload_capped_at_4096_bytes():
    """Large payloads are truncated to PAYLOAD_MAX_BYTES to bound memory."""
    from scapy.packet import Raw

    body = b"A" * 8000
    pkt = _eth(
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=80, flags="PA")
        / Raw(load=body)
    )
    data = parse_packet(pkt)
    assert len(data.tcp_payload) == 4096
    # payload_length (the on-wire size) is still the full 8000
    assert data.payload_length == 8000
