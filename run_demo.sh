#!/usr/bin/env bash
# run_demo.sh – One-command demo runner for Linux / macOS
# Usage: bash run_demo.sh
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   Real-time Packet Monitoring & Traffic Statistics System    ║${RESET}"
echo -e "${BOLD}║          Admissions / Portfolio Demo Runner (Linux/macOS)    ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  This script will:"
echo -e "    1. Verify your Python installation"
echo -e "    2. Create an isolated virtual environment (${BOLD}./venv${RESET})"
echo -e "    3. Install the required Python packages"
echo -e "    4. Generate a synthetic demo.pcap (200 packets, no root needed)"
echo -e "    5. Run a full offline analysis and export all results"
echo ""
echo -e "  Output files will be saved to: ${BOLD}./output/${RESET}"
echo -e "    • traffic_summary.csv      – packet-level dataset"
echo -e "    • protocol_distribution.png – protocol pie chart"
echo -e "    • top_endpoints.png         – top source/destination bar chart"
echo -e "    • report.md                – Markdown analysis report"
echo ""
echo -e "──────────────────────────────────────────────────────────────────────"
echo ""

# ── Locate Python 3 ───────────────────────────────────────────────────────────
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$((10#$major))" -ge 3 ] && [ "$((10#$minor))" -ge 11 ]; then
            PYTHON="$candidate"
            ok "Found $("$candidate" --version) at $(command -v "$candidate")"
            break
        else
            warn "$candidate version $version found but Python 3.11+ is required."
        fi
    fi
done

[ -n "$PYTHON" ] || die "Python 3.11+ not found. Please install it from https://www.python.org/ and re-run this script."

# ── Virtual environment ────────────────────────────────────────────────────────
VENV_DIR="$(dirname "$0")/venv"

if [ -d "$VENV_DIR" ]; then
    info "Virtual environment already exists at $VENV_DIR — reusing it."
else
    info "Creating virtual environment at $VENV_DIR …"
    "$PYTHON" -m venv "$VENV_DIR" || die "Failed to create virtual environment."
    ok "Virtual environment created."
fi

# Activate
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate" || die "Could not activate virtual environment."
ok "Virtual environment activated."

# ── Install dependencies ───────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REQ="$SCRIPT_DIR/requirements.txt"

[ -f "$REQ" ] || die "requirements.txt not found at $REQ"

info "Installing dependencies from requirements.txt (this may take a minute on first run) …"
pip install --quiet --upgrade pip
pip install --quiet -r "$REQ" || die "Dependency installation failed. Check your internet connection."
ok "All dependencies installed."

echo ""
echo -e "──────────────────────────────────────────────────────────────────────"
info "Starting demo analysis …"
echo -e "──────────────────────────────────────────────────────────────────────"
echo ""

# ── Run the demo ───────────────────────────────────────────────────────────────
cd "$SCRIPT_DIR"
python main.py --demo --export || die "Demo run failed. See error output above."

echo ""
echo -e "──────────────────────────────────────────────────────────────────────"
echo -e "${GREEN}${BOLD}  Demo completed successfully.${RESET}"
echo ""
echo -e "  Review the generated outputs in ${BOLD}./output/${RESET}:"
echo -e "    • traffic_summary.csv"
echo -e "    • protocol_distribution.png"
echo -e "    • top_endpoints.png"
echo -e "    • report.md"
echo ""
echo -e "  To explore further, try:"
echo -e "    ${BOLD}python main.py --mode offline --pcap sample_data/demo.pcap --export${RESET}"
echo -e "    ${BOLD}python main.py --help${RESET}"
echo -e "──────────────────────────────────────────────────────────────────────"
echo ""
