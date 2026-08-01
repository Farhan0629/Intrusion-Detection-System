"""
Packet Parser.

Pure translation layer: Scapy packet -> PacketData. Deliberately has zero
knowledge of sniffing, threads, or interfaces, so it can be unit tested with
hand-crafted packets and reused unchanged if the capture backend ever changes
(e.g. Scapy -> PyShark).

Stage 5: also extracts the first N bytes of any TCP/UDP application-layer
payload so payload-signature rules can match against the bytes (e.g. detect
SQL injection strings in HTTP requests).
"""

from __future__ import annotations

from datetime import datetime, timezone

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from .models import PacketData, Protocol

# Cap per-packet payload storage. 4 KiB is enough to cover the entire HTTP
# request line + headers of any single GET — including every signature in
# the simulator (the longest literal is ~70 bytes). Anything larger is
# either a multi-packet stream we can't reassemble yet (future stage), or
# bulk data we have no rule for.
PAYLOAD_MAX_BYTES = 4096


def _tcp_flags_to_str(flags: int) -> str:
    # Scapy exposes TCP flags as a FlagValue; str() already gives "SA" style.
    # We translate to readable comma-separated names for alert readability.
    names = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }
    return ",".join(names.get(c, c) for c in str(flags))


def _extract_payload_bytes(layer) -> bytes:
    """Pull application bytes off a TCP/UDP layer, capped at PAYLOAD_MAX_BYTES."""
    # Scapy wraps the application payload as a sub-layer of TCP/UDP; we
    # serialise that sub-layer back to bytes so the same bytes-on-the-wire
    # match what's in our regex matcher. For the common case of a single
    # `Raw` sub-layer, this is just the raw bytes directly.
    try:
        if not layer.payload:
            return b""
        # If there's a Raw layer, prefer its bytes verbatim — they match
        # what a regex would match against the wire payload.
        if isinstance(layer.payload, Raw):
            return bytes(layer.payload.load)[:PAYLOAD_MAX_BYTES]
        # Otherwise serialise the sub-layer (handles DNS, etc.) but cap.
        return bytes(layer.payload)[:PAYLOAD_MAX_BYTES]
    except Exception:
        return b""


def parse_packet(pkt: Packet, store_raw_summary: bool = False) -> PacketData | None:
    """
    Convert a raw Scapy packet into a normalized PacketData.
    Returns None for protocols we don't yet support (safe to ignore upstream).
    """
    ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc) if hasattr(pkt, "time") else datetime.now(timezone.utc)
    size = len(pkt)

    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None

    raw_summary = pkt.summary() if store_raw_summary else ""

    # ARP has no IP layer, handle first
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = "who-has" if arp.op == 1 else "is-at" if arp.op == 2 else str(arp.op)
        return PacketData(
            timestamp=ts,
            protocol=Protocol.ARP,
            src_ip=arp.psrc,
            dst_ip=arp.pdst,
            src_mac=src_mac,
            dst_mac=dst_mac,
            packet_size=size,
            arp_op=op,
            raw_summary=raw_summary,
        )

    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    payload_len = len(ip.payload.payload) if ip.payload and ip.payload.payload else 0

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        return PacketData(
            timestamp=ts,
            protocol=Protocol.TCP,
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            src_mac=src_mac,
            dst_mac=dst_mac,
            ttl=int(ip.ttl),
            packet_size=size,
            payload_length=payload_len,
            tcp_flags=_tcp_flags_to_str(tcp.flags),
            tcp_payload=_extract_payload_bytes(tcp),
            raw_summary=raw_summary,
        )

    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        return PacketData(
            timestamp=ts,
            protocol=Protocol.UDP,
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=int(udp.sport),
            dst_port=int(udp.dport),
            src_mac=src_mac,
            dst_mac=dst_mac,
            ttl=int(ip.ttl),
            packet_size=size,
            payload_length=payload_len,
            udp_payload=_extract_payload_bytes(udp),
            raw_summary=raw_summary,
        )

    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        return PacketData(
            timestamp=ts,
            protocol=Protocol.ICMP,
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ttl=int(ip.ttl),
            packet_size=size,
            payload_length=payload_len,
            raw_summary=raw_summary,
        )

    # IP packet with an unsupported transport protocol (e.g. GRE, ESP)
    return PacketData(
        timestamp=ts,
        protocol=Protocol.OTHER,
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_mac=src_mac,
        dst_mac=dst_mac,
        ttl=int(ip.ttl),
        packet_size=size,
        payload_length=payload_len,
        raw_summary=raw_summary,
    )
