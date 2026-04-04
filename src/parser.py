"""
parser.py – Convert raw Scapy packets into structured Python dataclasses.

Supports protocol dissection for:
  Ethernet, IPv4, TCP, UDP, ICMP, DNS, and basic HTTP detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Parsed packet dataclass
# ---------------------------------------------------------------------------

@dataclass
class ParsedPacket:
    """Structured representation of a single network packet."""

    timestamp: float          # Unix epoch with sub-second precision
    length: int               # Total packet length in bytes
    src_ip: Optional[str]     # Source IP address
    dst_ip: Optional[str]     # Destination IP address
    protocol: str             # Top-level protocol label (TCP / UDP / ICMP / …)
    src_port: Optional[int]   # Source port (TCP/UDP only)
    dst_port: Optional[int]   # Destination port (TCP/UDP only)
    info: str                 # Human-readable summary line
    eth_src: Optional[str] = field(default=None)  # Source MAC address
    eth_dst: Optional[str] = field(default=None)  # Destination MAC address
    ttl: Optional[int] = field(default=None)       # IPv4 TTL
    flags: Optional[str] = field(default=None)     # TCP flags (e.g. 'S', 'SA')
    dns_query: Optional[str] = field(default=None) # DNS queried name
    http_method: Optional[str] = field(default=None) # HTTP verb if detected

    @property
    def datetime(self) -> datetime:
        """Return the packet timestamp as a :class:`datetime` object."""
        return datetime.fromtimestamp(self.timestamp)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_get(pkt, layer_name: str):
    """Return the requested Scapy layer, or None if not present."""
    try:
        if pkt.haslayer(layer_name):
            return pkt.getlayer(layer_name)
    except Exception:
        pass
    return None


def _tcp_flags(flags_value) -> str:
    """Convert Scapy TCP flags to a compact string (e.g. 'SA')."""
    try:
        return str(flags_value)
    except Exception:
        return ""


def _detect_http(tcp_layer) -> Optional[str]:
    """
    Attempt to detect HTTP method from TCP payload.

    Returns the HTTP verb (GET, POST, …) or None.
    """
    HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                    b"OPTIONS ", b"PATCH ", b"HTTP/")
    try:
        payload = bytes(tcp_layer.payload)
        for method in HTTP_METHODS:
            if payload.startswith(method):
                first_line = payload.split(b"\r\n")[0].decode("utf-8", errors="replace")
                return first_line[:80]  # truncate for safety
    except Exception:
        pass
    return None


def _dns_query_name(dns_layer) -> Optional[str]:
    """Extract the first DNS question name from a DNS layer."""
    try:
        if dns_layer.qd:
            return dns_layer.qd.qname.decode("utf-8", errors="replace").rstrip(".")
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Public parsing function
# ---------------------------------------------------------------------------

def parse_packet(raw_packet) -> Optional[ParsedPacket]:
    """
    Parse a single Scapy packet into a :class:`ParsedPacket`.

    Parameters
    ----------
    raw_packet : A Scapy packet object.

    Returns
    -------
    :class:`ParsedPacket` or None if the packet cannot be parsed.
    """
    try:
        # Timestamp & length
        ts = float(raw_packet.time) if hasattr(raw_packet, "time") else 0.0
        length = len(raw_packet)

        # Ethernet
        eth = _safe_get(raw_packet, "Ether")
        eth_src = eth.src if eth else None
        eth_dst = eth.dst if eth else None

        # IPv4
        ip = _safe_get(raw_packet, "IP")
        src_ip = ip.src if ip else None
        dst_ip = ip.dst if ip else None
        ttl = ip.ttl if ip else None

        # Determine top-level protocol & transport fields
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        flags: Optional[str] = None
        dns_query: Optional[str] = None
        http_method: Optional[str] = None
        protocol = "OTHER"

        tcp = _safe_get(raw_packet, "TCP")
        udp = _safe_get(raw_packet, "UDP")
        icmp = _safe_get(raw_packet, "ICMP")
        dns = _safe_get(raw_packet, "DNS")

        if tcp:
            protocol = "TCP"
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = _tcp_flags(tcp.flags)
            http_method = _detect_http(tcp)
            if http_method:
                protocol = "HTTP"
        elif udp:
            protocol = "UDP"
            src_port = udp.sport
            dst_port = udp.dport
        elif icmp:
            protocol = "ICMP"

        if dns:
            protocol = "DNS"
            dns_query = _dns_query_name(dns)

        # Build the summary info line
        if protocol == "DNS" and dns_query:
            info_str = f"DNS Query: {dns_query}"
        elif protocol == "HTTP" and http_method:
            info_str = f"HTTP: {http_method}"
        elif protocol in ("TCP", "UDP"):
            info_str = f"{protocol} {src_ip}:{src_port} → {dst_ip}:{dst_port}"
        elif protocol == "ICMP":
            info_str = f"ICMP {src_ip} → {dst_ip}"
        else:
            info_str = f"{protocol} len={length}"

        return ParsedPacket(
            timestamp=ts,
            length=length,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            info=info_str,
            eth_src=eth_src,
            eth_dst=eth_dst,
            ttl=ttl,
            flags=flags,
            dns_query=dns_query,
            http_method=http_method,
        )

    except Exception:
        return None


def parse_packets(raw_packets: list) -> list[ParsedPacket]:
    """
    Parse a list of raw Scapy packets into structured :class:`ParsedPacket` objects.

    Silently skips packets that cannot be parsed.
    """
    results = []
    for pkt in raw_packets:
        parsed = parse_packet(pkt)
        if parsed is not None:
            results.append(parsed)
    return results
