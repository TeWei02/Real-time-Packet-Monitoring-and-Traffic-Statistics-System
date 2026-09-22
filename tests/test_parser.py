"""
tests/test_parser.py – Unit tests for the protocol dissection module.

Run with:
    python -m pytest tests/ -v
"""

from __future__ import annotations

import pytest

from src.parser import parse_packet, parse_packets

pytest.importorskip("scapy", reason="Scapy is required for the parsing tests")

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether  # noqa: E402


def _pkt(payload, ts: float = 1_700_000_000.0):
    """Attach a timestamp to a Scapy packet so parse_packet sees a stable clock."""
    payload.time = ts
    return payload


# ---------------------------------------------------------------------------
# Layer-by-layer dissection
# ---------------------------------------------------------------------------

def test_ethernet_and_ipv4_fields_are_extracted():
    raw = _pkt(Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
               / IP(src="192.168.1.5", dst="93.184.216.34", ttl=57)
               / TCP(sport=51000, dport=443, flags="S"))
    pkt = parse_packet(raw)

    assert pkt is not None
    assert pkt.eth_src == "aa:bb:cc:dd:ee:ff"
    assert pkt.eth_dst == "11:22:33:44:55:66"
    assert pkt.src_ip == "192.168.1.5"
    assert pkt.dst_ip == "93.184.216.34"
    assert pkt.ttl == 57
    assert pkt.protocol == "TCP"
    assert pkt.src_port == 51000
    assert pkt.dst_port == 443
    assert pkt.flags == "S"


def test_udp_packet_is_classified_as_udp():
    raw = _pkt(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=5353))
    pkt = parse_packet(raw)

    assert pkt is not None
    assert pkt.protocol == "UDP"
    assert pkt.dst_port == 5353
    assert "10.0.0.1:12345" in pkt.info


def test_icmp_packet_is_classified_as_icmp():
    raw = _pkt(Ether() / IP(src="172.16.0.1", dst="172.16.0.9") / ICMP())
    pkt = parse_packet(raw)

    assert pkt is not None
    assert pkt.protocol == "ICMP"
    assert pkt.src_port is None
    assert "172.16.0.1" in pkt.info


def test_dns_query_name_is_extracted():
    # Serialised and re-dissected so the recorded bytes travel the same path
    # a capture file does.
    raw = _pkt(
        Ether(bytes(
            Ether()
            / IP(src="192.168.1.7", dst="1.1.1.1")
            / UDP(sport=40000, dport=53)
            / DNS(rd=1, qd=[DNSQR(qname="example.org")])
        ))
    )
    pkt = parse_packet(raw)

    assert pkt is not None
    assert pkt.protocol == "DNS"
    assert pkt.dns_query == "example.org"
    assert "example.org" in pkt.info


def test_http_request_line_is_detected():
    raw = _pkt(
        Ether()
        / IP(src="192.168.1.7", dst="93.184.216.34")
        / TCP(sport=40001, dport=80)
        / b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n"
    )
    pkt = parse_packet(raw)

    assert pkt is not None
    assert pkt.protocol == "HTTP"
    assert pkt.http_method.startswith("GET /index.html")
    assert pkt.info.startswith("HTTP:")


def test_non_ip_traffic_falls_back_to_other():
    raw = _pkt(Ether() / b"\x00\x01\x02\x03")
    pkt = parse_packet(raw)

    assert pkt is not None
    assert pkt.protocol == "OTHER"
    assert pkt.src_ip is None
    assert pkt.info.startswith("OTHER")


def test_packet_length_reflects_captured_frame_size():
    raw = _pkt(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2))
    pkt = parse_packet(raw)

    assert pkt is not None
    assert pkt.length == len(bytes(raw))


def test_timestamp_is_preserved_as_float():
    raw = _pkt(Ether() / IP() / TCP(), ts=1_600_000_000.25)
    pkt = parse_packet(raw)

    assert pkt is not None
    assert pkt.timestamp == pytest.approx(1_600_000_000.25)
    assert pkt.datetime.year == 2020


def test_unparsable_input_is_skipped_without_raising():
    parsed = parse_packets([None, _pkt(Ether() / IP() / TCP()), 42])
    types = [type(p).__name__ for p in parsed]

    assert len(parsed) == 1
    assert types == ["ParsedPacket"]
