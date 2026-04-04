"""
analyzer.py – Traffic statistics aggregation.

Computes flow-level statistics and traffic profiling metrics from a list
of ParsedPacket objects, returning both a pandas DataFrame and a summary dict.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

import pandas as pd

from src.parser import ParsedPacket
from src.utils import proto_name, human_bytes


# ---------------------------------------------------------------------------
# Core aggregation
# ---------------------------------------------------------------------------

def build_dataframe(packets: list[ParsedPacket]) -> pd.DataFrame:
    """
    Convert a list of :class:`ParsedPacket` objects into a :class:`pandas.DataFrame`.

    Each row represents one packet with all parsed fields as columns.
    """
    if not packets:
        return pd.DataFrame()

    rows = [
        {
            "timestamp": pkt.timestamp,
            "datetime": pkt.datetime,
            "length": pkt.length,
            "src_ip": pkt.src_ip or "",
            "dst_ip": pkt.dst_ip or "",
            "protocol": pkt.protocol,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "info": pkt.info,
            "eth_src": pkt.eth_src or "",
            "eth_dst": pkt.eth_dst or "",
            "ttl": pkt.ttl,
            "flags": pkt.flags or "",
            "dns_query": pkt.dns_query or "",
            "http_method": pkt.http_method or "",
        }
        for pkt in packets
    ]
    df = pd.DataFrame(rows)
    df["datetime"] = pd.to_datetime(df["datetime"])
    return df


def compute_statistics(df: pd.DataFrame) -> dict[str, Any]:
    """
    Compute comprehensive traffic statistics from the packet DataFrame.

    Parameters
    ----------
    df : DataFrame produced by :func:`build_dataframe`.

    Returns
    -------
    A dict containing all key metrics ready for dashboard and report use.
    """
    if df.empty:
        return _empty_stats()

    total_packets = len(df)
    total_bytes = int(df["length"].sum())
    avg_pkt_size = float(df["length"].mean())

    # Duration & PPS
    t_min = df["timestamp"].min()
    t_max = df["timestamp"].max()
    duration_sec = max(t_max - t_min, 1.0)  # avoid divide-by-zero
    pps = total_packets / duration_sec

    # Protocol distribution
    proto_counts: dict[str, int] = df["protocol"].value_counts().to_dict()

    # Top source / destination IPs (filter out empty strings)
    src_ips = df.loc[df["src_ip"] != "", "src_ip"]
    dst_ips = df.loc[df["dst_ip"] != "", "dst_ip"]
    top_src_ips: list[tuple[str, int]] = (
        src_ips.value_counts().head(10).items() if not src_ips.empty else []
    )
    top_dst_ips: list[tuple[str, int]] = (
        dst_ips.value_counts().head(10).items() if not dst_ips.empty else []
    )

    # Top ports
    src_ports = df.loc[df["src_port"].notna(), "src_port"].astype(int)
    dst_ports = df.loc[df["dst_port"].notna(), "dst_port"].astype(int)
    top_src_ports: list[tuple[int, int]] = (
        src_ports.value_counts().head(10).items() if not src_ports.empty else []
    )
    top_dst_ports: list[tuple[int, int]] = (
        dst_ports.value_counts().head(10).items() if not dst_ports.empty else []
    )

    # Peak traffic second
    df_copy = df.copy()
    df_copy["second"] = df_copy["datetime"].dt.floor("s")
    pkt_per_second = df_copy.groupby("second").size()
    peak_time = pkt_per_second.idxmax() if not pkt_per_second.empty else None
    peak_pps = int(pkt_per_second.max()) if not pkt_per_second.empty else 0

    # Time series for charts (1-second buckets)
    time_series = pkt_per_second.reset_index()
    time_series.columns = ["second", "count"]

    # DNS queries
    dns_df = df.loc[df["dns_query"] != "", "dns_query"]
    top_dns: list[tuple[str, int]] = (
        dns_df.value_counts().head(5).items() if not dns_df.empty else []
    )

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "total_bytes_human": human_bytes(total_bytes),
        "avg_pkt_size": round(avg_pkt_size, 2),
        "duration_sec": round(duration_sec, 2),
        "pps": round(pps, 2),
        "proto_counts": proto_counts,
        "top_src_ips": list(top_src_ips),
        "top_dst_ips": list(top_dst_ips),
        "top_src_ports": list(top_src_ports),
        "top_dst_ports": list(top_dst_ports),
        "peak_time": str(peak_time) if peak_time else "N/A",
        "peak_pps": peak_pps,
        "time_series": time_series,
        "top_dns": list(top_dns),
    }


def _empty_stats() -> dict[str, Any]:
    """Return a zeroed statistics dictionary when no packets are available."""
    return {
        "total_packets": 0,
        "total_bytes": 0,
        "total_bytes_human": "0 B",
        "avg_pkt_size": 0.0,
        "duration_sec": 0.0,
        "pps": 0.0,
        "proto_counts": {},
        "top_src_ips": [],
        "top_dst_ips": [],
        "top_src_ports": [],
        "top_dst_ports": [],
        "peak_time": "N/A",
        "peak_pps": 0,
        "time_series": pd.DataFrame(columns=["second", "count"]),
        "top_dns": [],
    }
