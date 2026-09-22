#!/usr/bin/env python3
"""
build_web_data.py – Regenerate the data that the browser demo ships with.

The browser build dissects and aggregates a capture entirely on the client.
To keep that build verifiable, this script copies the bundled reference
capture into ``docs/data/`` and writes ``reference.json`` containing the
statistics the Python pipeline produces for the very same file.  The demo
compares its own client-side numbers against that reference at load time, so
a divergence is visible instead of silent.

Usage
-----
    python tools/build_web_data.py
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.analyzer import build_dataframe, compute_statistics  # noqa: E402
from src.capture import load_pcap  # noqa: E402
from src.parser import parse_packets  # noqa: E402
from src.utils import PORT_SERVICE_MAP  # noqa: E402

CAPTURE = ROOT / "sample_data" / "demo.pcap"
DOCS_DATA = ROOT / "docs" / "data"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def build_reference() -> dict:
    """Recompute the Python reference for the bundled capture."""
    packets = parse_packets(load_pcap(CAPTURE))
    stats = compute_statistics(build_dataframe(packets))

    return {
        "capture": "sample_data/demo.pcap",
        "capture_sha256": sha256(CAPTURE),
        "capture_bytes": CAPTURE.stat().st_size,
        "produced_by": "python main.py --demo --export",
        "total_packets": stats["total_packets"],
        "total_bytes": stats["total_bytes"],
        "total_bytes_human": stats["total_bytes_human"],
        "avg_pkt_size": stats["avg_pkt_size"],
        "duration_sec": stats["duration_sec"],
        "pps": stats["pps"],
        "peak_pps": stats["peak_pps"],
        "peak_time": stats["peak_time"],
        "proto_counts": stats["proto_counts"],
        "top_src_ips": stats["top_src_ips"],
        "top_dst_ips": stats["top_dst_ips"],
        "top_src_ports": stats["top_src_ports"],
        "top_dst_ports": stats["top_dst_ports"],
        "top_dns": stats["top_dns"],
        "port_services": {str(k): v for k, v in PORT_SERVICE_MAP.items()},
        "time_series": [
            {"second": str(row["second"]), "count": int(row["count"])}
            for _, row in stats["time_series"].iterrows()
        ],
    }


def check() -> int:
    """Verify the committed browser assets still match the bundled capture."""
    # Round-trip through JSON so tuples/lists compare like the committed file does.
    reference = json.loads(json.dumps(build_reference(), ensure_ascii=False))
    target = DOCS_DATA / "demo.pcap"
    out = DOCS_DATA / "reference.json"
    problems: list[str] = []

    if not target.exists():
        problems.append(f"missing {target.relative_to(ROOT)}")
    elif sha256(target) != reference["capture_sha256"]:
        problems.append(
            f"{target.relative_to(ROOT)} differs from {CAPTURE.relative_to(ROOT)} "
            "(re-run: python tools/build_web_data.py)"
        )

    if not out.exists():
        problems.append(f"missing {out.relative_to(ROOT)}")
    else:
        committed = json.loads(out.read_text(encoding="utf-8"))
        for key, value in reference.items():
            if committed.get(key) != value:
                problems.append(
                    f"{out.relative_to(ROOT)} field '{key}' is stale "
                    "(re-run: python tools/build_web_data.py)"
                )

    if problems:
        for problem in problems:
            print(f"[ERROR] {problem}")
        return 1

    print(f"[OK] {target.relative_to(ROOT)} matches {CAPTURE.relative_to(ROOT)} "
          f"({reference['capture_sha256'][:12]})")
    print(f"[OK] {out.relative_to(ROOT)} matches the pipeline "
          f"({reference['total_packets']} packets, {len(reference['proto_counts'])} protocols)")
    return 0


def main() -> int:
    if not CAPTURE.exists():
        print(f"[ERROR] reference capture not found: {CAPTURE}")
        print("        run: python main.py --demo")
        return 1

    if "--check" in sys.argv[1:]:
        return check()

    DOCS_DATA.mkdir(parents=True, exist_ok=True)
    target = DOCS_DATA / "demo.pcap"
    shutil.copyfile(CAPTURE, target)
    reference = build_reference()

    out = DOCS_DATA / "reference.json"
    out.write_text(json.dumps(reference, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[OK] {target.relative_to(ROOT)}  ({reference['capture_bytes']} bytes)")
    print(f"[OK] {out.relative_to(ROOT)}  ({reference['total_packets']} packets, "
          f"{len(reference['proto_counts'])} protocols)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
