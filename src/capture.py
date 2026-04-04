"""
capture.py – Unified packet capture interface.

Provides two modes:
  - Offline: read packets from a .pcap file via Scapy.
  - Live:    capture packets from a network interface.
             Falls back gracefully when permissions are insufficient.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Generator, Iterable

from src.utils import warn, error, info


# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

RawPacket = object  # Scapy packet objects are untyped; keep it flexible.


# ---------------------------------------------------------------------------
# Offline mode – read .pcap
# ---------------------------------------------------------------------------

def load_pcap(path: str | Path, limit: int | None = None) -> list[RawPacket]:
    """
    Load packets from a .pcap file using Scapy.

    Parameters
    ----------
    path  : Path to the .pcap file.
    limit : Maximum number of packets to read (None = all).

    Returns
    -------
    A list of Scapy packet objects.
    """
    try:
        from scapy.utils import rdpcap
    except ImportError:
        error("Scapy is not installed. Run: pip install scapy", exit_code=1)

    pcap_path = Path(path)
    if not pcap_path.exists():
        error(f"PCAP file not found: {pcap_path}", exit_code=1)

    info(f"Loading packets from {pcap_path} …")
    try:
        packets = rdpcap(str(pcap_path))
        if limit:
            packets = packets[:limit]
        info(f"Loaded {len(packets)} packets.")
        return list(packets)
    except Exception as exc:
        error(f"Failed to read PCAP file: {exc}", exit_code=1)


# ---------------------------------------------------------------------------
# Live capture mode
# ---------------------------------------------------------------------------

def live_capture(
    iface: str | None = None,
    limit: int | None = 500,
    timeout: int = 30,
) -> list[RawPacket]:
    """
    Capture live packets from a network interface using Scapy.

    Parameters
    ----------
    iface   : Interface name (None lets Scapy choose the default).
    limit   : Stop after this many packets (None = capture until timeout).
    timeout : Stop after this many seconds.

    Returns
    -------
    A list of Scapy packet objects, or an empty list if capture fails.
    """
    try:
        from scapy.all import sniff
    except ImportError:
        warn("Scapy is not installed. Cannot perform live capture.")
        return []

    iface_desc = iface or "default interface"
    info(f"Starting live capture on {iface_desc} (limit={limit}, timeout={timeout}s) …")
    info("Press Ctrl+C to stop early.")

    try:
        kwargs: dict = {"timeout": timeout}
        if limit:
            kwargs["count"] = limit
        if iface:
            kwargs["iface"] = iface

        packets = sniff(**kwargs)
        info(f"Captured {len(packets)} packets.")
        return list(packets)

    except PermissionError:
        warn(
            "Permission denied for live capture. "
            "Try running with sudo (Linux/macOS) or as Administrator (Windows)."
        )
        return []
    except OSError as exc:
        warn(f"Network interface error: {exc}")
        return []
    except KeyboardInterrupt:
        info("Capture interrupted by user.")
        return []
    except Exception as exc:
        warn(f"Live capture failed unexpectedly: {exc}")
        return []


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def get_packets(
    mode: str,
    pcap: str | Path | None = None,
    iface: str | None = None,
    limit: int | None = None,
) -> list[RawPacket]:
    """
    Unified packet source.

    Parameters
    ----------
    mode  : 'offline' or 'live'.
    pcap  : Path to .pcap file (required for offline mode).
    iface : Network interface (optional for live mode).
    limit : Maximum packet count.

    Returns
    -------
    List of raw Scapy packet objects.
    """
    if mode == "offline":
        if not pcap:
            error("--pcap is required for offline mode.", exit_code=1)
        return load_pcap(pcap, limit=limit)

    elif mode == "live":
        pkts = live_capture(iface=iface, limit=limit or 500)
        if not pkts:
            warn("No packets captured in live mode. Falling back to offline demo.")
            demo_pcap = Path(__file__).resolve().parent.parent / "sample_data" / "demo.pcap"
            if demo_pcap.exists():
                info(f"Using demo PCAP: {demo_pcap}")
                return load_pcap(demo_pcap, limit=limit)
            else:
                warn("No demo PCAP found either. Returning empty packet list.")
                return []
        return pkts

    else:
        error(f"Unknown mode: {mode!r}. Choose 'offline' or 'live'.", exit_code=1)
