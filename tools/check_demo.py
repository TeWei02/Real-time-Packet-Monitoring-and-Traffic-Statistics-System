#!/usr/bin/env python3
"""Headless-Chrome check of the browser console in ``docs/``.

The page dissects the bundled capture in JavaScript and compares its own
numbers against the Python reference committed as ``docs/data/reference.json``.
This script drives that page in headless Chrome over the DevTools protocol and
asserts on the machine-readable status the page exposes as ``window.RPM.status()``:

1. the bundled capture loads and every applicable parity check passes;
2. the browser's protocol counts, packet total and record count equal the
   committed Python reference;
3. the CSV and Markdown exports can be built from the loaded state;
4. the synthetic (simulated) stream path also runs to completion;
5. a service worker is registered, so the site is installable / offline-capable.

It works against a local server or the deployed GitHub Pages site:

    python3 -m http.server 8000 &
    python3 tools/check_demo.py http://127.0.0.1:8000/docs/
    python3 tools/check_demo.py https://tewei02.github.io/Real-time-Packet-Monitoring-and-Traffic-Statistics-System/

Requires Google Chrome and ``pip install websocket-client``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import websocket
except ImportError:  # pragma: no cover - dependency hint
    sys.exit("websocket-client is required: pip install websocket-client")

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome",
    "chromium",
    "chromium-browser",
]
PORT = 9337
DEFAULT_URL = "http://127.0.0.1:8000/docs/"

RESULTS: list[tuple[bool, str]] = []


def record(ok: bool, label: str) -> None:
    RESULTS.append((bool(ok), label))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}")


def find_chrome() -> str:
    for candidate in CHROME_CANDIDATES:
        if candidate.startswith("/"):
            if os.path.exists(candidate):
                return candidate
        else:
            found = shutil.which(candidate)
            if found:
                return found
    sys.exit("Google Chrome not found; install Chrome or add it to PATH")


class Browser:
    """Minimal CDP client: navigate, evaluate JavaScript, wait for a predicate."""

    def __init__(self, url: str, timeout: float = 90.0) -> None:
        self.url = url
        self.timeout = timeout
        self.profile = tempfile.mkdtemp(prefix="rpm-check-")
        self.proc = subprocess.Popen(
            [
                find_chrome(),
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--user-data-dir=" + self.profile,
                f"--remote-debugging-port={PORT}",
                "--remote-allow-origins=*",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.ws = None
        self.msg_id = 0

    def __enter__(self) -> Browser:
        ws_url = self._wait_for_target()
        self.ws = websocket.create_connection(ws_url, timeout=self.timeout)
        self.call("Page.enable")
        self.call("Runtime.enable")
        self.call("Page.navigate", {"url": self.url})
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self.ws is not None:
                self.ws.close()
        except Exception:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)

    def _wait_for_target(self) -> str:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list", timeout=2) as resp:
                    for target in json.load(resp):
                        if target.get("type") == "page" and target.get("webSocketDebuggerUrl"):
                            return target["webSocketDebuggerUrl"]
            except Exception:
                pass
            time.sleep(0.3)
        raise RuntimeError("no DevTools page target appeared")

    def call(self, method: str, params: dict | None = None) -> dict:
        self.msg_id += 1
        self.ws.send(json.dumps({"id": self.msg_id, "method": method, "params": params or {}}))
        while True:
            data = json.loads(self.ws.recv())
            if data.get("id") == self.msg_id:
                return data

    def evaluate(self, expression: str):
        """Evaluate a JS expression; async expressions are awaited."""
        res = self.call(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
        )
        result = res.get("result", {})
        if "exceptionDetails" in result:
            raise RuntimeError(f"JS error: {str(result['exceptionDetails'])[:300]}")
        return result.get("result", {}).get("value")

    def wait_for(self, expression: str, timeout: float = 45.0, interval: float = 0.4):
        """Poll ``expression`` until it is truthy; returns the last value."""
        deadline = time.time() + timeout
        value = None
        while time.time() < deadline:
            try:
                value = self.evaluate(expression)
            except Exception:
                value = None
            if value:
                return value
            time.sleep(interval)
        raise TimeoutError(f"condition never became true: {expression} (last value: {value!r})")


def fetch_reference(base_url: str) -> dict | None:
    """Load the committed Python reference served next to the page."""
    target = urllib.parse.urljoin(base_url, "data/reference.json")
    try:
        with urllib.request.urlopen(target, timeout=20) as resp:
            return json.load(resp)
    except Exception as exc:  # pragma: no cover - network dependent
        print(f"[WARN] could not fetch {target}: {exc}")
        return None


def main(argv: list[str]) -> int:
    url = argv[1] if len(argv) > 1 else DEFAULT_URL
    if not url.endswith("/"):
        url += "/"
    print(f"Checking {url}")

    reference = fetch_reference(url)
    local_pcap = Path(__file__).resolve().parents[1] / "docs" / "data" / "demo.pcap"

    with Browser(url) as browser:
        try:
            browser.wait_for("window.RPM && window.RPM.status().status !== 'pending'", timeout=60)
        except TimeoutError as exc:
            record(False, f"page reached a finished run ({exc})")
            return report_and_exit()

        status = browser.evaluate("JSON.parse(JSON.stringify(window.RPM.status()))")
        print("page status: " + json.dumps(status, ensure_ascii=False))

        record(status["status"] == "ready",
               f"bundled capture run finished cleanly (status={status['status']})")
        record(status["checks_total"] >= 17 and status["checks_passed"] == status["checks_total"],
               f"parity vs the Python pipeline: {status['checks_passed']}/{status['checks_total']} checks passed")
        record(not status["mismatches"],
               f"no mismatch rows ({status['mismatches']})")
        record(status["records"] == status["packets"] == 200,
               f"200 packets dissected into {status['records']} records")
        record(status["protocols"] == 4,
               f"4 protocols detected ({status['proto_counts']})")

        if reference:
            record(status["proto_counts"] == reference["proto_counts"],
                   "protocol counts equal docs/data/reference.json "
                   f"({status['proto_counts']} vs {reference['proto_counts']})")
            record(status["packets"] == reference["total_packets"],
                   f"packet total equals the reference ({status['packets']})")
        else:
            print("[WARN] parity against the on-disk reference file was skipped")

        # Exports must be buildable from the loaded state.
        csv_rows = browser.evaluate(
            "document.getElementById('btn-csv') && window.RPM.state.records.length"
            " ? window.RPM.buildCsv(window.RPM.state.records).trim().split('\\n').length : 0"
        )
        record(csv_rows == 201, f"CSV export builds {csv_rows} lines (header + 200 packets)")
        md_len = browser.evaluate(
            "document.getElementById('btn-md') && window.RPM.state.stats"
            " ? window.RPM.buildMarkdown(window.RPM.state.stats, window.RPM.state.meta).length : 0"
        )
        record(md_len > 500, f"Markdown report builds ({md_len} characters)")

        # The simulated stream must run through the same aggregation path.
        browser.evaluate("document.getElementById('btn-sim').click()")
        try:
            browser.wait_for("/synthetic/.test(window.RPM.status().source || '')"
                             " && window.RPM.status().status !== 'pending'", timeout=30)
            sim = browser.evaluate("JSON.parse(JSON.stringify(window.RPM.status()))")
            record(sim["proto_counts"] and sim["records"] == sim["packets"] > 0,
                   f"simulated stream analysed ({sim['packets']} packets, {sim['protocols']} protocols)")
        except TimeoutError:
            record(False, "simulated stream analysed")

        # Back to the bundled capture, to leave the page in its default state.
        browser.evaluate("document.getElementById('btn-sample').click()")
        browser.wait_for("window.RPM.status().checks_total > 0", timeout=30)

        filter_rows = browser.evaluate(
            "(function(){var f=document.getElementById('filter');f.value='DNS';"
            "f.dispatchEvent(new Event('input',{bubbles:true}));"
            "var n=document.querySelectorAll('#packet-body tr').length;"
            "f.value='';f.dispatchEvent(new Event('input',{bubbles:true}));return n;})()"
        )
        dns_records = browser.evaluate(
            "window.RPM.state.records.filter(function(r){return r.protocol==='DNS';}).length"
        )
        record(filter_rows == dns_records > 0,
               f"table filter works (DNS rows: {filter_rows} of {dns_records} DNS records)")

        # A visitor can drop in their own capture; it is parsed locally in the page.
        if local_pcap.exists():
            try:
                browser.call("DOM.enable")
                doc = browser.call("DOM.getDocument", {"depth": -1})
                node_id = browser.call(
                    "DOM.querySelector",
                    {"nodeId": doc["result"]["root"]["nodeId"], "selector": "#file-input"},
                )["result"]["nodeId"]
                browser.call("DOM.setFileInputFiles",
                             {"files": [str(local_pcap)], "nodeId": node_id})
                browser.wait_for("/local file/.test(window.RPM.status().source || '')"
                                 " && window.RPM.status().status !== 'pending'", timeout=30)
                uploaded = browser.evaluate("JSON.parse(JSON.stringify(window.RPM.status()))")
                record(uploaded["records"] == uploaded["packets"] == 200,
                       f"uploaded capture analysed locally ({uploaded['packets']} packets, "
                       f"source='{uploaded['source']}')")
                record(uploaded["checks_total"] == 0,
                       "parity panel reports no reference for user uploads "
                       f"(checks_total={uploaded['checks_total']})")
            except (TimeoutError, RuntimeError) as exc:
                record(False, f"uploaded capture analysed locally ({exc})")
            browser.evaluate("document.getElementById('btn-sample').click()")
            browser.wait_for("window.RPM.status().checks_total > 0", timeout=30)
        else:
            print(f"[WARN] upload check skipped, {local_pcap} not found")

        charts = browser.evaluate(
            "(function(){var a=document.querySelector('#chart-protocol svg')||document.querySelector('#chart-protocol *');"
            "var b=document.querySelector('#chart-endpoints svg')||document.querySelector('#chart-endpoints *');"
            "return (a?a.childElementCount:0)+(b?b.childElementCount:0);})()"
        )
        record(charts > 0, f"protocol and endpoint charts rendered ({charts} elements)")

        status_after = browser.evaluate("window.RPM.status()")
        record(status_after["checks_passed"] == status_after["checks_total"] == 17,
               "bundled capture still verified after the interactive checks "
               f"({status_after['checks_passed']}/{status_after['checks_total']})")

        sw_count = browser.evaluate(
            "navigator.serviceWorker ? navigator.serviceWorker.getRegistrations().then(function(r){return r.length;}) : 0"
        )
        cache_keys = browser.evaluate("window.caches ? window.caches.keys().then(function(k){return k.length;}) : 0")
        record(sw_count >= 1 and cache_keys >= 1,
               f"service worker registered ({sw_count}) with {cache_keys} cache(s)")

    return report_and_exit()


def report_and_exit() -> int:
    failed = [label for ok, label in RESULTS if not ok]
    print("\n" + "-" * 72)
    print(f"check_demo: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if failed:
        for label in failed:
            print(f"  failed: {label}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
