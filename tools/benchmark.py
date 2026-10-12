#!/usr/bin/env python3
"""Reproducible performance benchmark for the analysis pipeline.

The README states that no measurement results are reported anywhere in this
project. This tool fills that gap, and it is deliberately narrow about what it
measures: **the cost of the tool itself**, never the network. There is no live
traffic involved, no bandwidth figure and no claim about any real network. The
only inputs are captures this script generates itself from a fixed seed plus the
committed ``sample_data/demo.pcap``.

What it measures
----------------
1. Stage cost (load → parse → DataFrame → statistics → export) for the bundled
   200-packet capture, reported as the median of repeated runs.
2. Parse throughput as the capture grows, over synthetic captures built from a
   fixed seed so two runs on the same machine are comparable.
3. Peak traced memory for the largest capture.

Absolute numbers depend on the machine. The script records the environment it
ran on so a reader can judge how comparable a figure is; the scaling behaviour
across capture sizes is the part that carries over between machines.

Usage
-----
    python tools/benchmark.py            # measure, write docs/data/benchmark.json
    python tools/benchmark.py --quick    # smaller sizes, for a quick check
    python tools/benchmark.py --stdout   # print the JSON instead of writing it
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import random
import statistics
import sys
import time
import tracemalloc
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.analyzer import build_dataframe, compute_statistics  # noqa: E402
from src.capture import load_pcap  # noqa: E402
from src.parser import parse_packets  # noqa: E402
from src.report import export_charts, export_csv, export_markdown  # noqa: E402
from src.utils import ensure_output_dir  # noqa: E402

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

SEED = 20261013
BUNDLED = ROOT / "sample_data" / "demo.pcap"
SIZES_FULL = [200, 1_000, 5_000, 20_000]
SIZES_QUICK = [200, 1_000]

# The same mix the bundled demo capture uses, so the synthetic captures exercise
# the same parser paths (TCP, UDP, DNS, ICMP) instead of one trivial branch.
ENDPOINTS = [
    ("192.168.1.10", "8.8.8.8"),
    ("192.168.1.20", "1.1.1.1"),
    ("10.0.0.5", "172.217.0.1"),
    ("192.168.1.10", "192.168.1.20"),
    ("10.0.0.5", "8.8.8.8"),
]
DOMAINS = ["example.com", "github.com", "cloudflare.com", "wikipedia.org"]

# 明確給 MAC，否則 scapy 會為了 Ether()/IP() 逐封包查 ARP，
# 既噴警告、又讓耗時取決於環境而不是程式本身。
MAC_SRC = "02:00:00:00:00:02"
MAC_DST = "02:00:00:00:00:01"


def synth_capture(path: Path, count: int, seed: int = SEED) -> Path:
    """Write a synthetic capture of ``count`` packets built from ``seed``."""
    from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, wrpcap

    rng = random.Random(seed)
    base_time = 1_760_000_000.0  # fixed epoch: two runs must be byte-comparable
    packets = []
    for index in range(count):
        src, dst = ENDPOINTS[index % len(ENDPOINTS)]
        stamp = base_time + index * 0.05
        kind = index % 4
        if kind == 0:
            layer = TCP(sport=rng.randint(1024, 65535), dport=rng.choice([80, 443]), flags="S")
        elif kind == 1:
            layer = UDP(sport=rng.randint(1024, 65535), dport=53) / DNS(
                rd=1, qd=DNSQR(qname=rng.choice(DOMAINS))
            )
        elif kind == 2:
            layer = ICMP(type=8)
        else:
            # 注意："/" 與 "*" 同優先序且左結合，這裡的括號不能省，
            # 否則會變成 (UDP(...) / b"x") * 24 —— 一個 24 元素的串列。
            layer = UDP(sport=rng.randint(1024, 65535), dport=443) / (b"x" * 24)
        packets.append(Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=src, dst=dst) / layer)
        packets[-1].time = stamp

    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    return path


def median_time(fn: Callable[[], Any], repeat: int) -> float:
    """Median wall-clock seconds over ``repeat`` runs."""
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def environment() -> dict[str, Any]:
    cpu = platform.processor() or platform.machine()
    try:  # macOS and Linux expose the marketing name here
        if sys.platform == "darwin":
            import subprocess

            cpu = (
                subprocess.run(
                    ["sysctl", "-n", "machdep.cpu.brand_string"],
                    capture_output=True,
                    text=True,
                    check=False,
                ).stdout.strip()
                or cpu
            )
    except Exception:  # pragma: no cover - best effort only
        pass
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu": cpu,
        "cpu_count": os_cpu_count(),
    }


def os_cpu_count() -> int:
    import os

    return os.cpu_count() or 0


def stage_profile(capture: Path, repeat: int) -> dict[str, float]:
    """Median seconds for each stage of the pipeline on one capture."""
    raw = load_pcap(str(capture))
    parsed = parse_packets(raw)
    frame = build_dataframe(parsed)
    stats = compute_statistics(frame)

    def run_export() -> None:
        out = ensure_output_dir()
        export_csv(frame, out)
        export_charts(stats, out)
        export_markdown(stats, out)

    return {
        "load_s": median_time(lambda: load_pcap(str(capture)), repeat),
        "parse_s": median_time(lambda: parse_packets(raw), repeat),
        "dataframe_s": median_time(lambda: build_dataframe(parsed), repeat),
        "statistics_s": median_time(lambda: compute_statistics(frame), repeat),
        "export_s": median_time(run_export, max(1, repeat // 2)),
    }


def scaling(sizes: list[int], repeat: int, workdir: Path) -> list[dict[str, Any]]:
    """End-to-end cost per capture size, with throughput derived from it."""
    rows = []
    for size in sizes:
        capture = synth_capture(workdir / f"bench-{size}.pcap", size)
        stages = stage_profile(capture, repeat)
        analysis = sum(stages[key] for key in ("load_s", "parse_s", "dataframe_s", "statistics_s"))
        rows.append(
            {
                "packets": size,
                "capture_bytes": capture.stat().st_size,
                **{key: round(value, 6) for key, value in stages.items()},
                "analysis_s": round(analysis, 6),
                "total_s": round(analysis + stages["export_s"], 6),
                # 只以分析階段計算吞吐量；export_s 幾乎都是 matplotlib 繪圖，
                # 混進來會讓這個數字變成在量繪圖而不是量解析。
                "analysis_packets_per_sec": round(size / analysis, 1) if analysis else None,
            }
        )
        capture.unlink(missing_ok=True)
    return rows


def peak_memory(size: int, workdir: Path) -> dict[str, Any]:
    """Peak traced memory for the full pipeline on the largest capture."""
    capture = synth_capture(workdir / f"bench-mem-{size}.pcap", size)
    tracemalloc.start()
    raw = load_pcap(str(capture))
    parsed = parse_packets(raw)
    frame = build_dataframe(parsed)
    compute_statistics(frame)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    capture.unlink(missing_ok=True)
    return {
        "packets": size,
        "peak_mb": round(peak / 1024 / 1024, 2),
        "retained_mb": round(current / 1024 / 1024, 2),
    }


def run(args: argparse.Namespace) -> int:
    workdir = ensure_output_dir()
    sizes = SIZES_QUICK if args.quick else SIZES_FULL
    repeat = 3 if args.quick else 5

    if not BUNDLED.is_file():
        print(
            f"找不到 {BUNDLED}；先執行 python main.py --demo 產生它。",
            file=sys.stderr,
        )
        return 1

    result: dict[str, Any] = {
        "generated_by": "python tools/benchmark.py",
        "measured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": (
            "Measures the cost of this tool's own pipeline on captures it "
            "generates. No network traffic was captured or measured, and no "
            "figure here describes a real network."
        ),
        "methodology": {
            "timing": "median of repeated runs, wall clock, time.perf_counter",
            "repeat": repeat,
            "synthetic_seed": SEED,
            "note": (
                "Absolute times depend on the machine below; the scaling across "
                "capture sizes is what transfers between machines."
            ),
        },
        "environment": environment(),
        "bundled_capture": {
            "path": str(BUNDLED.relative_to(ROOT)),
            "bytes": BUNDLED.stat().st_size,
            "stages": {k: round(v, 6) for k, v in stage_profile(BUNDLED, repeat).items()},
        },
        "scaling": scaling(sizes, repeat, workdir),
        "memory": peak_memory(sizes[-1], workdir),
    }

    payload = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.stdout:
        print(payload)
        return 0

    target = ROOT / "docs" / "data" / "benchmark.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload, encoding="utf-8")

    env = result["environment"]
    print(f"環境：{env['cpu']} / {env['cpu_count']} cores / Python {env['python']}")
    print(f"重複次數：{repeat}（取中位數）\n")
    print(
        f"{'封包數':>8}  {'載入':>8}  {'解析':>8}  {'DataFrame':>10}  {'統計':>8}  "
        f"{'分析合計':>10}  {'分析 封包/秒':>13}  {'匯出(含繪圖)':>13}"
    )
    print("-" * 96)
    for row in result["scaling"]:
        print(
            f"{row['packets']:>8,}  {row['load_s']:>8.4f}  {row['parse_s']:>8.4f}  "
            f"{row['dataframe_s']:>10.4f}  {row['statistics_s']:>8.4f}  "
            f"{row['analysis_s']:>10.4f}  {row['analysis_packets_per_sec']:>13,.1f}  "
            f"{row['export_s']:>13.4f}"
        )
    mem = result["memory"]
    print(f"\n尖峰記憶體（{mem['packets']:,} 封包）：{mem['peak_mb']} MB")
    print(f"已寫入 {target.relative_to(ROOT)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quick", action="store_true", help="較小的規模，開發時用")
    parser.add_argument("--stdout", action="store_true", help="印出 JSON，不寫檔")
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
