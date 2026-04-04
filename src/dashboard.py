"""
dashboard.py – Rich-based terminal dashboard for packet statistics.

Renders a live summary panel using the `rich` library, including:
  - Key metrics (total packets, bytes, PPS, …)
  - Protocol distribution table
  - Top source / destination IPs
  - Top ports
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box

from src.utils import port_service


console = Console()


# ---------------------------------------------------------------------------
# Individual panel builders
# ---------------------------------------------------------------------------

def _metrics_panel(stats: dict[str, Any]) -> Panel:
    """Build the key-metrics panel."""
    lines = [
        f"[bold cyan]Total Packets   :[/bold cyan]  {stats['total_packets']:,}",
        f"[bold cyan]Total Bytes     :[/bold cyan]  {stats['total_bytes_human']}",
        f"[bold cyan]Avg Packet Size :[/bold cyan]  {stats['avg_pkt_size']} bytes",
        f"[bold cyan]Duration        :[/bold cyan]  {stats['duration_sec']} s",
        f"[bold cyan]Avg PPS         :[/bold cyan]  {stats['pps']:.2f} pkt/s",
        f"[bold cyan]Peak PPS        :[/bold cyan]  {stats['peak_pps']} pkt/s",
        f"[bold cyan]Peak Time       :[/bold cyan]  {stats['peak_time']}",
    ]
    return Panel("\n".join(lines), title="[bold green]📊 Traffic Summary[/bold green]", box=box.ROUNDED)


def _proto_table(proto_counts: dict[str, int]) -> Table:
    """Build the protocol distribution table."""
    table = Table(title="Protocol Distribution", box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Protocol", style="bold magenta", min_width=10)
    table.add_column("Packets", justify="right", style="yellow")
    table.add_column("Share", justify="right", style="cyan")

    total = sum(proto_counts.values()) or 1
    for proto, count in sorted(proto_counts.items(), key=lambda x: -x[1]):
        share = count / total * 100
        table.add_row(proto, f"{count:,}", f"{share:.1f}%")
    return table


def _ip_table(title: str, top_ips: list[tuple[str, int]]) -> Table:
    """Build a top-IP table."""
    table = Table(title=title, box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("IP Address", style="bold white", min_width=18)
    table.add_column("Packets", justify="right", style="yellow")

    for ip, count in top_ips[:5]:
        table.add_row(ip, f"{count:,}")
    return table


def _port_table(title: str, top_ports: list[tuple[int, int]]) -> Table:
    """Build a top-port table."""
    table = Table(title=title, box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Port", style="bold white", min_width=8)
    table.add_column("Service", style="cyan", min_width=12)
    table.add_column("Packets", justify="right", style="yellow")

    for port, count in top_ports[:5]:
        table.add_row(str(port), port_service(port), f"{count:,}")
    return table


def _dns_table(top_dns: list[tuple[str, int]]) -> Table | None:
    """Build a top DNS queries table, or return None if empty."""
    if not top_dns:
        return None
    table = Table(title="Top DNS Queries", box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Query", style="bold white", min_width=30)
    table.add_column("Count", justify="right", style="yellow")
    for name, count in top_dns:
        table.add_row(name, f"{count:,}")
    return table


# ---------------------------------------------------------------------------
# Main render function
# ---------------------------------------------------------------------------

def render_dashboard(stats: dict[str, Any]) -> None:
    """
    Render the full terminal dashboard.

    Parameters
    ----------
    stats : Statistics dict from :func:`src.analyzer.compute_statistics`.
    """
    console.rule("[bold blue]🔍 Real-time Packet Monitoring & Traffic Statistics[/bold blue]")
    console.print()

    # Key metrics
    console.print(_metrics_panel(stats))
    console.print()

    # Protocol distribution
    console.print(_proto_table(stats["proto_counts"]))
    console.print()

    # Top IPs side by side
    src_tbl = _ip_table("Top Source IPs", stats["top_src_ips"])
    dst_tbl = _ip_table("Top Destination IPs", stats["top_dst_ips"])
    console.print(Columns([src_tbl, dst_tbl]))
    console.print()

    # Top ports side by side
    sp_tbl = _port_table("Top Source Ports", stats["top_src_ports"])
    dp_tbl = _port_table("Top Destination Ports", stats["top_dst_ports"])
    console.print(Columns([sp_tbl, dp_tbl]))
    console.print()

    # DNS (optional)
    dns_tbl = _dns_table(stats.get("top_dns", []))
    if dns_tbl:
        console.print(dns_tbl)
        console.print()

    console.rule("[bold blue]End of Report[/bold blue]")
