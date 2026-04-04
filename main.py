#!/usr/bin/env python3
"""
main.py – CLI entry point for the Real-time Packet Monitoring and Traffic
Statistics System.

Usage examples:
    python main.py --mode offline --pcap sample_data/demo.pcap
    python main.py --mode offline --pcap sample_data/demo.pcap --export
    python main.py --mode live --iface eth0 --limit 200
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure project root is on sys.path so `src.*` imports work when invoked
# directly as `python main.py` from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.capture import get_packets
from src.parser import parse_packets
from src.analyzer import build_dataframe, compute_statistics
from src.dashboard import render_dashboard
from src.report import export_csv, export_charts, export_markdown
from src.utils import info, warn, ensure_output_dir, SAMPLE_DIR


# ---------------------------------------------------------------------------
# Demo PCAP generation (fallback)
# ---------------------------------------------------------------------------

def _generate_demo_pcap(path: Path) -> bool:
    """
    Generate a small synthetic demo.pcap using Scapy.

    Returns True on success, False otherwise.
    """
    try:
        from scapy.all import (
            Ether, IP, TCP, UDP, ICMP, DNS, DNSQR,
            wrpcap, RandShort
        )
        import random, time

        info("Generating synthetic demo.pcap …")
        path.parent.mkdir(parents=True, exist_ok=True)

        base_time = time.time() - 60  # start 60 seconds ago
        pkts = []

        ips = [
            ("192.168.1.10", "8.8.8.8"),
            ("192.168.1.20", "1.1.1.1"),
            ("10.0.0.5",     "172.217.0.1"),
            ("192.168.1.10", "192.168.1.20"),
            ("10.0.0.5",     "8.8.8.8"),
        ]

        for i in range(200):
            src, dst = random.choice(ips)
            ts = base_time + i * 0.3 + random.uniform(0, 0.2)
            ptype = random.choices(
                ["tcp", "udp", "icmp", "dns"], weights=[40, 30, 15, 15]
            )[0]

            if ptype == "tcp":
                pkt = (
                    Ether()
                    / IP(src=src, dst=dst, ttl=random.randint(32, 128))
                    / TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 22, 8080]))
                )
            elif ptype == "udp":
                pkt = (
                    Ether()
                    / IP(src=src, dst=dst, ttl=random.randint(32, 128))
                    / UDP(sport=random.randint(1024, 65535), dport=random.choice([53, 123, 5353]))
                )
            elif ptype == "icmp":
                pkt = Ether() / IP(src=src, dst=dst) / ICMP()
            else:
                # DNS
                pkt = (
                    Ether()
                    / IP(src=src, dst="8.8.8.8")
                    / UDP(sport=random.randint(1024, 65535), dport=53)
                    / DNS(rd=1, qd=DNSQR(qname=random.choice([
                        "example.com", "google.com", "github.com", "openai.com"
                    ])))
                )

            pkt.time = ts
            pkts.append(pkt)

        wrpcap(str(path), pkts)
        info(f"demo.pcap written to {path} ({len(pkts)} packets).")
        return True

    except Exception as exc:
        warn(f"Could not generate demo PCAP: {exc}")
        return False


def _ensure_demo_pcap() -> Path:
    """Return path to demo.pcap, generating it if absent."""
    demo = SAMPLE_DIR / "demo.pcap"
    if not demo.exists():
        _generate_demo_pcap(demo)
    return demo


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packet-monitor",
        description=(
            "Real-time Packet Monitoring and Traffic Statistics System\n"
            "Supports offline (.pcap) analysis and live capture modes."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["offline", "live"],
        default="offline",
        help="Capture mode: 'offline' reads a .pcap file; 'live' sniffs a network interface.",
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        help="Path to .pcap file (required for --mode offline).",
    )
    parser.add_argument(
        "--iface",
        metavar="INTERFACE",
        help="Network interface for live capture (e.g. eth0, Wi-Fi).",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export results: CSV, PNG charts, and Markdown report.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Maximum number of packets to analyse (default: all).",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate a synthetic demo.pcap and run offline analysis on it.",
    )
    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # ── Demo shortcut ────────────────────────────────────────────────────────
    if args.demo or (args.mode == "offline" and not args.pcap):
        info("No --pcap specified; using demo mode.")
        pcap_path = _ensure_demo_pcap()
        args.mode = "offline"
        args.pcap = str(pcap_path)

    ensure_output_dir()

    # ── Packet acquisition ───────────────────────────────────────────────────
    raw_packets = get_packets(
        mode=args.mode,
        pcap=args.pcap,
        iface=args.iface,
        limit=args.limit,
    )

    if not raw_packets:
        warn("No packets to analyse. Exiting.")
        sys.exit(0)

    # ── Parsing & analysis ───────────────────────────────────────────────────
    info("Parsing packets …")
    parsed = parse_packets(raw_packets)

    if not parsed:
        warn("No packets could be parsed. Check that the file contains valid IP traffic.")
        sys.exit(0)

    info(f"Parsed {len(parsed)} packets successfully.")

    df = build_dataframe(parsed)
    stats = compute_statistics(df)

    # ── Dashboard ────────────────────────────────────────────────────────────
    render_dashboard(stats)

    # ── Export (optional) ────────────────────────────────────────────────────
    if args.export:
        info("Exporting results …")
        export_csv(df)
        export_charts(stats)
        export_markdown(stats)
        info("All exports complete. Check the output/ directory.")


if __name__ == "__main__":
    main()
