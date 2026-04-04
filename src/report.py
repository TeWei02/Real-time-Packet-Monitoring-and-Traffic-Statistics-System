"""
report.py – Export traffic analysis results.

Supports three output formats:
  1. CSV  – full packet-level DataFrame (traffic_summary.csv)
  2. PNG  – protocol distribution pie chart + top-endpoint bar charts
  3. Markdown – academic-style summary report (report.md)
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from src.utils import ensure_output_dir, now_str, port_service, human_bytes


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def export_csv(df: pd.DataFrame, output_dir: Path | None = None) -> Path:
    """
    Export the packet DataFrame to a CSV file.

    Parameters
    ----------
    df         : DataFrame from :func:`src.analyzer.build_dataframe`.
    output_dir : Destination directory (defaults to project output/).

    Returns
    -------
    Path of the written CSV file.
    """
    out = output_dir or ensure_output_dir()
    path = out / "traffic_summary.csv"
    df.to_csv(path, index=False)
    print(f"[INFO]  CSV exported → {path}")
    return path


# ---------------------------------------------------------------------------
# PNG charts
# ---------------------------------------------------------------------------

def export_charts(stats: dict[str, Any], output_dir: Path | None = None) -> list[Path]:
    """
    Generate and save traffic analysis charts as PNG files.

    Produces:
      - protocol_distribution.png  (pie chart)
      - top_endpoints.png          (bar charts for top IPs)

    Parameters
    ----------
    stats      : Statistics dict from :func:`src.analyzer.compute_statistics`.
    output_dir : Destination directory.

    Returns
    -------
    List of Paths for the written PNG files.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")  # non-interactive backend for headless environments
        import matplotlib.pyplot as plt
        import matplotlib.gridspec as gridspec
    except ImportError:
        print("[WARN]  matplotlib not installed; skipping chart export.")
        return []

    out = output_dir or ensure_output_dir()
    paths: list[Path] = []

    # ── Protocol distribution pie chart ─────────────────────────────────────
    proto_counts = stats.get("proto_counts", {})
    if proto_counts:
        fig, ax = plt.subplots(figsize=(7, 5))
        labels = list(proto_counts.keys())
        sizes = list(proto_counts.values())
        ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
        ax.set_title("Protocol Distribution", fontsize=14, fontweight="bold")
        pie_path = out / "protocol_distribution.png"
        fig.tight_layout()
        fig.savefig(pie_path, dpi=150)
        plt.close(fig)
        paths.append(pie_path)
        print(f"[INFO]  Chart exported → {pie_path}")

    # ── Top endpoints bar chart ──────────────────────────────────────────────
    top_src = stats.get("top_src_ips", [])[:8]
    top_dst = stats.get("top_dst_ips", [])[:8]

    if top_src or top_dst:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.suptitle("Top Endpoints", fontsize=14, fontweight="bold")

        for ax, title, data in [
            (axes[0], "Top Source IPs", top_src),
            (axes[1], "Top Destination IPs", top_dst),
        ]:
            if data:
                ips, counts = zip(*data)
                ax.barh(ips[::-1], counts[::-1], color="#4C72B0")
                ax.set_xlabel("Packet Count")
                ax.set_title(title)
                ax.tick_params(axis="y", labelsize=8)
            else:
                ax.set_visible(False)

        bar_path = out / "top_endpoints.png"
        fig.tight_layout()
        fig.savefig(bar_path, dpi=150)
        plt.close(fig)
        paths.append(bar_path)
        print(f"[INFO]  Chart exported → {bar_path}")

    return paths


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

_MD_TEMPLATE = """\
# 即時封包監測與流量統計系統 — 分析報告

> **Real-time Packet Monitoring and Traffic Statistics System – Analysis Report**
>
> Generated: {generated_at}

---

## 1. 執行摘要 (Executive Summary)

本次分析共擷取 **{total_packets:,}** 個封包，傳輸總量為 **{total_bytes_human}**，
分析持續時間約 **{duration_sec} 秒**，平均每秒封包數（PPS）為 **{pps:.2f} pkt/s**。

---

## 2. 關鍵統計指標 (Key Metrics)

| 指標 | 數值 |
|------|------|
| 總封包數 (Total Packets) | {total_packets:,} |
| 總傳輸量 (Total Bytes) | {total_bytes_human} |
| 平均封包大小 (Avg Packet Size) | {avg_pkt_size} bytes |
| 分析持續時間 (Duration) | {duration_sec} s |
| 平均 PPS | {pps:.2f} pkt/s |
| 尖峰 PPS (Peak PPS) | {peak_pps} pkt/s |
| 尖峰時間點 (Peak Time) | `{peak_time}` |

---

## 3. 協定分布 (Protocol Distribution)

{proto_table}

> 詳細圓餅圖請參閱：`output/protocol_distribution.png`

---

## 4. Top Source IPs

{src_ip_table}

---

## 5. Top Destination IPs

{dst_ip_table}

---

## 6. Top Source Ports

{src_port_table}

---

## 7. Top Destination Ports

{dst_port_table}

---

## 8. DNS 查詢 (DNS Queries)

{dns_section}

---

## 9. 技術說明 (Technical Notes)

- 封包解析採用 **Scapy** 進行 protocol dissection，支援 Ethernet / IPv4 / TCP / UDP / ICMP / DNS / HTTP。
- 統計彙整使用 **pandas** 進行 flow-level statistics 計算。
- 終端機儀表板透過 **Rich** 實現 real-time packet inspection 顯示。
- 圖表輸出採用 **Matplotlib**，適合嵌入書面報告。
- 系統設計採 lightweight network observability 原則，模組化可擴充。

---

## 10. 可延伸方向 (Future Work)

1. 整合 **Elasticsearch + Kibana** 建立長期 traffic profiling 儲存與查詢介面。
2. 加入 **異常流量偵測**（IP flood / port scan detection）。
3. 支援 **IPv6** 封包解析。
4. 加入 Web UI（Flask / FastAPI）以實現瀏覽器端即時監測。
5. 與 **Zeek / Suricata** 整合進行 deep packet inspection。

---

*此報告由 packet-monitor 自動產生。*
"""


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    """Build a Markdown table string."""
    sep = " | ".join(["---"] * len(headers))
    header_row = " | ".join(headers)
    body = "\n".join(f"| {' | '.join(r)} |" for r in rows)
    return f"| {header_row} |\n|{sep}|\n{body}"


def export_markdown(stats: dict[str, Any], output_dir: Path | None = None) -> Path:
    """
    Generate a Markdown academic summary report.

    Parameters
    ----------
    stats      : Statistics dict from :func:`src.analyzer.compute_statistics`.
    output_dir : Destination directory.

    Returns
    -------
    Path of the written Markdown file.
    """
    out = output_dir or ensure_output_dir()
    path = out / "report.md"

    # Protocol table
    proto_rows = [
        [proto, f"{count:,}", f"{count / max(stats['total_packets'], 1) * 100:.1f}%"]
        for proto, count in sorted(stats["proto_counts"].items(), key=lambda x: -x[1])
    ]
    proto_table = _md_table(["Protocol", "Packets", "Share"], proto_rows)

    # Top IP tables
    src_ip_rows = [[ip, f"{cnt:,}"] for ip, cnt in stats["top_src_ips"][:8]]
    dst_ip_rows = [[ip, f"{cnt:,}"] for ip, cnt in stats["top_dst_ips"][:8]]
    src_ip_table = _md_table(["Source IP", "Packets"], src_ip_rows) if src_ip_rows else "_No data_"
    dst_ip_table = _md_table(["Destination IP", "Packets"], dst_ip_rows) if dst_ip_rows else "_No data_"

    # Port tables
    sp_rows = [[str(p), port_service(p), f"{c:,}"] for p, c in stats["top_src_ports"][:8]]
    dp_rows = [[str(p), port_service(p), f"{c:,}"] for p, c in stats["top_dst_ports"][:8]]
    src_port_table = _md_table(["Port", "Service", "Packets"], sp_rows) if sp_rows else "_No data_"
    dst_port_table = _md_table(["Port", "Service", "Packets"], dp_rows) if dp_rows else "_No data_"

    # DNS section
    dns_section: str
    if stats.get("top_dns"):
        dns_rows = [[name, f"{cnt:,}"] for name, cnt in stats["top_dns"]]
        dns_section = _md_table(["Query", "Count"], dns_rows)
    else:
        dns_section = "_No DNS queries detected._"

    content = _MD_TEMPLATE.format(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_packets=stats["total_packets"],
        total_bytes_human=stats["total_bytes_human"],
        duration_sec=stats["duration_sec"],
        pps=stats["pps"],
        avg_pkt_size=stats["avg_pkt_size"],
        peak_pps=stats["peak_pps"],
        peak_time=stats["peak_time"],
        proto_table=proto_table,
        src_ip_table=src_ip_table,
        dst_ip_table=dst_ip_table,
        src_port_table=src_port_table,
        dst_port_table=dst_port_table,
        dns_section=dns_section,
    )

    path.write_text(content, encoding="utf-8")
    print(f"[INFO]  Markdown report → {path}")
    return path
