#!/usr/bin/env python3
"""Query UptimeRobot for monitor status and uptime ratios.

Lists all monitors with current status, uptime percentage, and average
response time.  Exits non-zero when any monitor is down — suitable for
cron alerting or dashboard integration.

Examples:
    export UPTIMEROBOT_API_KEY=your_read_only_api_key
    python query_uptimerobot.py
    python query_uptimerobot.py --days 30 --csv uptime_report.csv
    python query_uptimerobot.py -v
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

log = logging.getLogger("query_uptimerobot")

API_URL = "https://api.uptimerobot.com/v2/getMonitors"
DEFAULT_DAYS = 7
PAGE_LIMIT = 50

STATUS_LABELS = {
    0: "PAUSE",
    1: "PEND",
    2: "UP",
    8: "DEGR",
    9: "DOWN",
}


@dataclass
class Monitor:
    friendly_name: str
    url: str
    status: int
    uptime_ratio: float
    avg_response_ms: int

    @property
    def ok(self) -> bool:
        return self.status == 2

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, "UNK")


def uptimerobot_post(api_key: str, extra_params: dict | None = None) -> dict:
    """Send a POST request to the UptimeRobot API and return parsed JSON."""
    form = {"api_key": api_key, "format": "json"}
    if extra_params:
        form.update(extra_params)
    body = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(
        API_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    log.debug("POST %s params=%s", API_URL, {k: v for k, v in form.items() if k != "api_key"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    if data.get("stat") != "ok":
        err = data.get("error", {})
        raise RuntimeError(f"API error: {err.get('message', data)}")
    return data


def fetch_monitors(api_key: str, uptime_days: int) -> list[Monitor]:
    """Retrieve all monitors with pagination."""
    monitors: list[Monitor] = []
    offset = 0
    while True:
        data = uptimerobot_post(api_key, {
            "response_times": "1",
            "response_times_average": "1",
            "custom_uptime_ratios": str(uptime_days),
            "offset": str(offset),
            "limit": str(PAGE_LIMIT),
        })
        for m in data.get("monitors", []):
            ratios = m.get("custom_uptime_ratio", "0")
            avg_resp = 0
            if m.get("average_response_time"):
                try:
                    avg_resp = int(float(m["average_response_time"]))
                except (ValueError, TypeError):
                    pass
            monitors.append(Monitor(
                friendly_name=m.get("friendly_name", ""),
                url=m.get("url", ""),
                status=m.get("status", 0),
                uptime_ratio=float(ratios.split("-")[0]) if ratios else 0.0,
                avg_response_ms=avg_resp,
            ))
        pagination = data.get("pagination", {})
        total = pagination.get("total", 0)
        offset += PAGE_LIMIT
        if offset >= total:
            break
        log.debug("Fetching next page (offset=%d, total=%d)", offset, total)
    return monitors


def write_csv(results: list[Monitor], dest: str | None) -> None:
    """Write results as CSV to a file or stdout."""
    fields = ["status", "friendly_name", "url", "uptime_ratio", "avg_response_ms"]
    buf: io.IOBase
    if dest:
        buf = open(dest, "w", newline="", encoding="utf-8")
    else:
        buf = sys.stdout
    try:
        writer = csv.DictWriter(buf, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "status": r.status_label,
                "friendly_name": r.friendly_name,
                "url": r.url,
                "uptime_ratio": r.uptime_ratio,
                "avg_response_ms": r.avg_response_ms,
            })
    finally:
        if dest:
            buf.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Query UptimeRobot for monitor status and uptime ratios.",
    )
    p.add_argument(
        "--api-key",
        metavar="KEY",
        help="UptimeRobot API key (default: env UPTIMEROBOT_API_KEY)",
    )
    p.add_argument(
        "--days",
        type=int,
        default=DEFAULT_DAYS,
        metavar="N",
        help=f"uptime ratio period in days (default: {DEFAULT_DAYS})",
    )
    p.add_argument(
        "--csv",
        metavar="FILE",
        dest="csv_file",
        help="write CSV report to FILE",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="show debug output",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        format="%(levelname)-7s %(message)s",
        level=logging.DEBUG if args.verbose else logging.WARNING,
        stream=sys.stderr,
    )

    api_key = args.api_key or os.environ.get("UPTIMEROBOT_API_KEY", "")
    if not api_key:
        log.error(
            "No API key provided. Use --api-key or set UPTIMEROBOT_API_KEY."
        )
        return 2

    try:
        monitors = fetch_monitors(api_key, args.days)
    except (RuntimeError, urllib.error.URLError) as exc:
        log.error("Failed to query UptimeRobot: %s", exc)
        return 1

    if not monitors:
        print("  No monitors found.")
        return 0

    # Sort: DOWN first, then DEGRADED, UP, PAUSED
    sort_order = {9: 0, 8: 1, 2: 2, 1: 3, 0: 4}
    monitors.sort(key=lambda m: sort_order.get(m.status, 5))

    for m in monitors:
        label = m.status_label
        if m.status in (0, 1):
            ratio_str = "  --"
            resp_str = "  --"
        else:
            ratio_str = f"{m.uptime_ratio:5.1f}%"
            resp_str = f"{m.avg_response_ms:>4d}ms"
        print(f"  {label:<5} {m.friendly_name:<35} {ratio_str}  {resp_str}  {m.url}")

    up = sum(1 for m in monitors if m.status == 2)
    down = sum(1 for m in monitors if m.status in (8, 9))
    paused = sum(1 for m in monitors if m.status in (0, 1))
    print(f"\n  {up} up, {down} down, {paused} paused — {len(monitors)} monitors ({args.days}-day uptime)")

    if args.csv_file:
        write_csv(monitors, args.csv_file)
        print(f"\nCSV written to {args.csv_file}", file=sys.stderr)

    return 0 if all(m.ok or m.status in (0, 1) for m in monitors) else 1


if __name__ == "__main__":
    sys.exit(main())
