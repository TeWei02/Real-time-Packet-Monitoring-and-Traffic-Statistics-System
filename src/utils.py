"""
utils.py – Shared utility functions for packet-monitor.
"""

from __future__ import annotations

import os
import sys
import socket
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT_DIR / "output"
SAMPLE_DIR = ROOT_DIR / "sample_data"


def ensure_output_dir() -> Path:
    """Create the output directory if it does not exist."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR


def ensure_sample_dir() -> Path:
    """Create the sample_data directory if it does not exist."""
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    return SAMPLE_DIR


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

PROTO_MAP: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


def proto_name(proto_number: int) -> str:
    """Return a human-readable protocol name for an IP protocol number."""
    return PROTO_MAP.get(proto_number, f"OTHER({proto_number})")


PORT_SERVICE_MAP: dict[int, str] = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
}


def port_service(port: int | None) -> str:
    """Return a service label for a well-known port, or the port number."""
    if port is None:
        return "-"
    return PORT_SERVICE_MAP.get(port, str(port))


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def human_bytes(n: int) -> str:
    """Convert byte count to a human-readable string (KB / MB / GB)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def now_str() -> str:
    """Return current timestamp as a compact string for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ---------------------------------------------------------------------------
# Logging / messaging helpers
# ---------------------------------------------------------------------------

def info(msg: str) -> None:
    """Print an informational message to stdout."""
    print(f"[INFO]  {msg}")


def warn(msg: str) -> None:
    """Print a warning message to stderr."""
    print(f"[WARN]  {msg}", file=sys.stderr)


def error(msg: str, exit_code: int = 0) -> None:
    """Print an error message.  If *exit_code* > 0, exit the process."""
    print(f"[ERROR] {msg}", file=sys.stderr)
    if exit_code:
        sys.exit(exit_code)
