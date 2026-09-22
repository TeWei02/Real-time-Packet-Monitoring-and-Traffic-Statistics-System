"""
tests/test_capture.py – Unit tests for the unified packet source.

These tests cover the offline path against the bundled sample capture and
guard against a regression in which an incomplete Scapy layer import left the
link-type registry empty, so that every record was handed back as an
undissected ``Raw`` object and the whole capture collapsed into a single
``OTHER`` bucket.

Run with:
    python -m pytest tests/ -v
"""

from __future__ import annotations

import pytest

from src.capture import load_pcap
from src.utils import SAMPLE_DIR

pytest.importorskip("scapy", reason="Scapy is required for the capture tests")

from src.parser import parse_packets  # noqa: E402

DEMO_PCAP = SAMPLE_DIR / "demo.pcap"


@pytest.fixture(scope="module")
def demo_packets():
    if not DEMO_PCAP.exists():
        pytest.skip("sample_data/demo.pcap is not present")
    return load_pcap(DEMO_PCAP)


def test_sample_capture_is_present(demo_packets):
    assert len(demo_packets) > 0


def test_records_are_dissected_down_to_the_link_layer(demo_packets):
    """Every record must carry a link-layer header, not a bare payload."""
    undissected = [p for p in demo_packets if p.__class__.__name__ == "Raw"]
    assert undissected == [], f"{len(undissected)} records were not dissected"


def test_capture_dissects_into_multiple_protocols(demo_packets):
    parsed = parse_packets(demo_packets)
    protocols = {p.protocol for p in parsed}

    assert len(parsed) == len(demo_packets)
    assert protocols != {"OTHER"}, f"capture collapsed to a single bucket: {protocols}"
    assert {"TCP", "UDP", "DNS"} <= protocols
    assert all(p.src_ip for p in parsed)


def test_limit_truncates_the_capture(demo_packets):
    limited = load_pcap(DEMO_PCAP, limit=25)

    assert len(limited) == 25
    assert [bytes(p) for p in limited] == [bytes(p) for p in demo_packets[:25]]


def test_missing_file_exits_with_an_error():
    with pytest.raises(SystemExit):
        load_pcap(SAMPLE_DIR / "does-not-exist.pcap")
