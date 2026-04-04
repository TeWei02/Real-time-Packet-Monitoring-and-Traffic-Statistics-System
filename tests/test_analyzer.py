"""
tests/test_analyzer.py – Unit tests for the analyzer module.

Run with:
    python -m pytest tests/ -v
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pandas as pd
import pytest

from src.parser import ParsedPacket
from src.analyzer import build_dataframe, compute_statistics, _empty_stats


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_packet(
    ts_offset: float = 0.0,
    length: int = 100,
    src_ip: str = "192.168.1.1",
    dst_ip: str = "8.8.8.8",
    protocol: str = "TCP",
    src_port: int = 54321,
    dst_port: int = 80,
    info: str = "TCP test",
) -> ParsedPacket:
    """Create a minimal ParsedPacket for testing."""
    return ParsedPacket(
        timestamp=1_700_000_000.0 + ts_offset,
        length=length,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        info=info,
    )


@pytest.fixture
def sample_packets() -> list[ParsedPacket]:
    """A small list of diverse packets."""
    return [
        _make_packet(0.0, 60,  "192.168.1.1", "8.8.8.8",   "TCP",  54321, 80),
        _make_packet(0.5, 120, "192.168.1.1", "1.1.1.1",   "UDP",  43210, 53),
        _make_packet(1.0, 40,  "10.0.0.2",    "8.8.8.8",   "ICMP", None,  None),
        _make_packet(1.5, 80,  "10.0.0.2",    "192.168.1.1","TCP", 12345, 443),
        _make_packet(2.0, 200, "192.168.1.1", "8.8.8.8",   "DNS",  9999,  53),
    ]


# ---------------------------------------------------------------------------
# build_dataframe tests
# ---------------------------------------------------------------------------

class TestBuildDataframe:
    def test_returns_dataframe(self, sample_packets):
        df = build_dataframe(sample_packets)
        assert isinstance(df, pd.DataFrame)

    def test_row_count_matches_input(self, sample_packets):
        df = build_dataframe(sample_packets)
        assert len(df) == len(sample_packets)

    def test_expected_columns_present(self, sample_packets):
        df = build_dataframe(sample_packets)
        required = {"timestamp", "length", "src_ip", "dst_ip", "protocol", "src_port", "dst_port"}
        assert required.issubset(set(df.columns))

    def test_empty_input_returns_empty_df(self):
        df = build_dataframe([])
        assert df.empty

    def test_length_values_preserved(self, sample_packets):
        df = build_dataframe(sample_packets)
        expected_lengths = [p.length for p in sample_packets]
        assert list(df["length"]) == expected_lengths


# ---------------------------------------------------------------------------
# compute_statistics tests
# ---------------------------------------------------------------------------

class TestComputeStatistics:
    def test_total_packets(self, sample_packets):
        df = build_dataframe(sample_packets)
        stats = compute_statistics(df)
        assert stats["total_packets"] == len(sample_packets)

    def test_total_bytes(self, sample_packets):
        df = build_dataframe(sample_packets)
        stats = compute_statistics(df)
        expected = sum(p.length for p in sample_packets)
        assert stats["total_bytes"] == expected

    def test_avg_pkt_size(self, sample_packets):
        df = build_dataframe(sample_packets)
        stats = compute_statistics(df)
        expected = round(sum(p.length for p in sample_packets) / len(sample_packets), 2)
        assert stats["avg_pkt_size"] == pytest.approx(expected, abs=0.01)

    def test_pps_is_positive(self, sample_packets):
        df = build_dataframe(sample_packets)
        stats = compute_statistics(df)
        assert stats["pps"] > 0

    def test_protocol_counts_keys(self, sample_packets):
        df = build_dataframe(sample_packets)
        stats = compute_statistics(df)
        proto_counts = stats["proto_counts"]
        # The sample contains TCP, UDP, ICMP, DNS
        assert "TCP" in proto_counts
        assert "UDP" in proto_counts
        assert "ICMP" in proto_counts
        assert "DNS" in proto_counts

    def test_protocol_counts_sum_equals_total(self, sample_packets):
        df = build_dataframe(sample_packets)
        stats = compute_statistics(df)
        assert sum(stats["proto_counts"].values()) == stats["total_packets"]

    def test_top_src_ips_type(self, sample_packets):
        df = build_dataframe(sample_packets)
        stats = compute_statistics(df)
        assert isinstance(stats["top_src_ips"], list)

    def test_top_dst_ips_most_common_first(self, sample_packets):
        df = build_dataframe(sample_packets)
        stats = compute_statistics(df)
        if len(stats["top_dst_ips"]) > 1:
            counts = [c for _, c in stats["top_dst_ips"]]
            assert counts == sorted(counts, reverse=True)

    def test_empty_df_returns_zero_stats(self):
        stats = compute_statistics(pd.DataFrame())
        assert stats["total_packets"] == 0
        assert stats["total_bytes"] == 0
        assert stats["pps"] == 0.0

    def test_peak_pps_with_clustered_packets(self):
        """Peak PPS should be ≥ avg PPS when packets cluster within a single second."""
        # All 5 packets land in the same second → peak == 5, avg == 5/1 == 5.0
        base = 1_700_000_000.0
        pkts = [_make_packet(ts_offset=i * 0.1) for i in range(5)]
        df = build_dataframe(pkts)
        stats = compute_statistics(df)
        assert stats["peak_pps"] >= stats["pps"]

    def test_human_bytes_present(self, sample_packets):
        df = build_dataframe(sample_packets)
        stats = compute_statistics(df)
        assert isinstance(stats["total_bytes_human"], str)
        assert len(stats["total_bytes_human"]) > 0


# ---------------------------------------------------------------------------
# _empty_stats tests
# ---------------------------------------------------------------------------

class TestEmptyStats:
    def test_structure(self):
        s = _empty_stats()
        required_keys = {
            "total_packets", "total_bytes", "pps", "proto_counts",
            "top_src_ips", "top_dst_ips", "peak_pps", "peak_time",
        }
        assert required_keys.issubset(set(s.keys()))

    def test_zeros(self):
        s = _empty_stats()
        assert s["total_packets"] == 0
        assert s["total_bytes"] == 0
        assert s["pps"] == 0.0
        assert s["proto_counts"] == {}
