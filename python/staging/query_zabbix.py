#!/usr/bin/env python3
"""Query Zabbix monitoring via JSON-RPC API.

Retrieves active problems, host status, or a system health overview from
a Zabbix server.  Designed for cron integration — exits non-zero when
active problems exist or hosts are unavailable.

Examples:
    export ZABBIX_URL=https://zabbix.example.com/api_jsonrpc.php
    export ZABBIX_USER=api_reader ZABBIX_PASS=secret
    python query_zabbix.py problems
    python query_zabbix.py hosts --csv host_status.csv
    python query_zabbix.py health -v
    python query_zabbix.py problems --api-token your_api_token
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger("query_zabbix")

SEVERITY_LABELS = {
    0: "N/C",
    1: "INFO",
    2: "WARN",
    3: "AVG",
    4: "HIGH",
    5: "CRIT",
}


@dataclass
class Problem:
    eventid: str
    host: str
    name: str
    severity: int
    duration: str
    acknowledged: bool

    @property
    def ok(self) -> bool:
        return False

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, "UNK")


@dataclass
class HostStatus:
    host: str
    name: str
    available: str
    active_problems: int
    error: str

    @property
    def ok(self) -> bool:
        return self.available == "available" and self.active_problems == 0


@dataclass
class HealthSummary:
    total_hosts: int = 0
    monitored_hosts: int = 0
    unavailable_hosts: int = 0
    active_problems: int = 0
    problems_by_severity: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.active_problems == 0 and self.unavailable_hosts == 0


def format_duration(seconds: int) -> str:
    """Convert seconds to human-readable duration like '3d 2h' or '45m'."""
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    remaining_min = minutes % 60
    if hours < 24:
        return f"{hours}h {remaining_min}m" if remaining_min else f"{hours}h"
    days = hours // 24
    remaining_hrs = hours % 24
    return f"{days}d {remaining_hrs}h" if remaining_hrs else f"{days}d"


def zabbix_rpc(url: str, method: str, params: dict,
               auth: str | None = None) -> object:
    """Execute a Zabbix JSON-RPC call and return the result."""
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    }
    if auth is not None:
        payload["auth"] = auth

    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json-rpc",
        },
        method="POST",
    )
    log.debug("RPC %s %s", method, json.dumps(params)[:200])

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} from Zabbix: {exc.reason}") from exc

    if "error" in data:
        err = data["error"]
        msg = err.get("data", err.get("message", str(err)))
        raise RuntimeError(f"Zabbix API error: {msg}")

    return data["result"]


def zabbix_login(url: str, user: str, password: str) -> str:
    """Authenticate to Zabbix and return an auth token.

    Tries the modern parameter name (Zabbix 6.4+) first, then falls back
    to the legacy 'user' parameter for older versions.
    """
    try:
        return str(zabbix_rpc(url, "user.login", {"username": user, "password": password}))
    except RuntimeError:
        log.debug("Login with 'username' failed, retrying with legacy 'user' parameter")
        return str(zabbix_rpc(url, "user.login", {"user": user, "password": password}))


def fetch_problems(url: str, auth: str, min_severity: int) -> list[Problem]:
    """Retrieve active (unresolved) problems."""
    now = int(time.time())
    result = zabbix_rpc(url, "problem.get", {
        "output": ["eventid", "name", "severity", "clock", "acknowledged"],
        "selectHosts": ["host"],
        "recent": True,
        "sortfield": ["severity", "eventid"],
        "sortorder": "DESC",
        "severities": list(range(min_severity, 6)) if min_severity > 0 else None,
        "suppressed": False,
    }, auth=auth)

    problems: list[Problem] = []
    for item in result:
        hosts = item.get("hosts", [])
        host = hosts[0]["host"] if hosts else "(unknown)"
        clock = int(item.get("clock", 0))
        dur = format_duration(now - clock) if clock else "?"
        problems.append(Problem(
            eventid=item["eventid"],
            host=host,
            name=item["name"],
            severity=int(item["severity"]),
            duration=dur,
            acknowledged=item.get("acknowledged", "0") == "1",
        ))
    return problems


def fetch_hosts(url: str, auth: str) -> list[HostStatus]:
    """Retrieve monitored hosts with availability and problem counts."""
    hosts_raw = zabbix_rpc(url, "host.get", {
        "output": ["hostid", "host", "name", "status"],
        "filter": {"status": 0},
        "selectInterfaces": ["available", "error"],
    }, auth=auth)

    problem_counts: dict[str, int] = {}
    problems_raw = zabbix_rpc(url, "problem.get", {
        "output": ["eventid"],
        "selectHosts": ["hostid"],
        "recent": True,
        "suppressed": False,
    }, auth=auth)
    for p in problems_raw:
        for h in p.get("hosts", []):
            hid = h["hostid"]
            problem_counts[hid] = problem_counts.get(hid, 0) + 1

    hosts: list[HostStatus] = []
    for h in hosts_raw:
        ifaces = h.get("interfaces", [])
        avail = "unknown"
        error = ""
        for iface in ifaces:
            a = int(iface.get("available", 0))
            if a == 2:
                avail = "unavailable"
                error = iface.get("error", "")
                break
            if a == 1:
                avail = "available"
        hosts.append(HostStatus(
            host=h["host"],
            name=h.get("name", ""),
            available=avail,
            active_problems=problem_counts.get(h["hostid"], 0),
            error=error,
        ))
    return hosts


def fetch_health(url: str, auth: str) -> HealthSummary:
    """Retrieve a system health overview."""
    all_hosts = zabbix_rpc(url, "host.get", {
        "output": ["hostid", "status"],
        "selectInterfaces": ["available"],
    }, auth=auth)

    monitored = [h for h in all_hosts if str(h.get("status")) == "0"]
    unavailable = 0
    for h in monitored:
        for iface in h.get("interfaces", []):
            if int(iface.get("available", 0)) == 2:
                unavailable += 1
                break

    problems = zabbix_rpc(url, "problem.get", {
        "output": ["severity"],
        "recent": True,
        "suppressed": False,
    }, auth=auth)

    by_severity: dict[str, int] = {}
    for p in problems:
        label = SEVERITY_LABELS.get(int(p["severity"]), "UNK")
        by_severity[label] = by_severity.get(label, 0) + 1

    return HealthSummary(
        total_hosts=len(all_hosts),
        monitored_hosts=len(monitored),
        unavailable_hosts=unavailable,
        active_problems=len(problems),
        problems_by_severity=by_severity,
    )


def write_csv(items: list[Problem] | list[HostStatus], dest: str | None,
              mode: str) -> None:
    """Write results as CSV to a file or stdout."""
    if mode == "problems":
        fields = ["severity", "host", "name", "duration", "acknowledged"]
        rows = [
            {"severity": p.severity_label, "host": p.host, "name": p.name,
             "duration": p.duration, "acknowledged": p.acknowledged}
            for p in items  # type: ignore[union-attr]
        ]
    else:
        fields = ["host", "name", "available", "active_problems", "error"]
        rows = [
            {"host": h.host, "name": h.name, "available": h.available,
             "active_problems": h.active_problems, "error": h.error}
            for h in items  # type: ignore[union-attr]
        ]

    buf: io.IOBase
    if dest:
        buf = open(dest, "w", newline="", encoding="utf-8")
    else:
        buf = sys.stdout
    try:
        writer = csv.DictWriter(buf, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if dest:
            buf.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Query Zabbix monitoring via JSON-RPC API.",
    )
    p.add_argument(
        "mode",
        choices=["problems", "hosts", "health"],
        help="query mode",
    )
    p.add_argument(
        "--url",
        metavar="URL",
        help="Zabbix API URL (default: env ZABBIX_URL)",
    )
    p.add_argument(
        "--user",
        metavar="USER",
        help="Zabbix username (default: env ZABBIX_USER)",
    )
    p.add_argument(
        "--password",
        metavar="PASS",
        help="Zabbix password (default: env ZABBIX_PASS)",
    )
    p.add_argument(
        "--api-token",
        metavar="TOKEN",
        help="Zabbix API token — bypasses user/pass login (Zabbix 5.4+)",
    )
    p.add_argument(
        "--min-severity",
        type=int,
        default=0,
        choices=range(6),
        metavar="N",
        help="minimum severity to show, 0-5 (default: 0, problems mode only)",
    )
    p.add_argument(
        "--csv",
        metavar="FILE",
        dest="csv_file",
        help="write CSV report to FILE (problems/hosts modes)",
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

    url = args.url or os.environ.get("ZABBIX_URL", "")
    if not url:
        log.error("No Zabbix URL. Use --url or set ZABBIX_URL.")
        return 2

    # Resolve auth: API token takes precedence over user/pass
    api_token = args.api_token or os.environ.get("ZABBIX_API_TOKEN", "")
    auth: str

    if api_token:
        auth = api_token
        log.debug("Using API token authentication")
    else:
        user = args.user or os.environ.get("ZABBIX_USER", "")
        password = args.password or os.environ.get("ZABBIX_PASS", "")
        if not user or not password:
            log.error(
                "Credentials required. Use --api-token (or ZABBIX_API_TOKEN), "
                "or --user/--password (or ZABBIX_USER/ZABBIX_PASS)."
            )
            return 2
        try:
            auth = zabbix_login(url, user, password)
        except (RuntimeError, urllib.error.URLError) as exc:
            log.error("Zabbix login failed: %s", exc)
            return 1

    try:
        if args.mode == "problems":
            problems = fetch_problems(url, auth, args.min_severity)
            if not problems:
                print("  No active problems.")
                return 0
            for p in problems:
                ack = "[ack]" if p.acknowledged else ""
                print(f"  {p.severity_label:<5} {p.host:<25} {p.name:<40} {p.duration:>8}  {ack}")
            print(f"\n  {len(problems)} active problem(s)")
            if args.csv_file:
                write_csv(problems, args.csv_file, "problems")
                print(f"\nCSV written to {args.csv_file}", file=sys.stderr)
            return 1

        elif args.mode == "hosts":
            hosts = fetch_hosts(url, auth)
            if not hosts:
                print("  No monitored hosts found.")
                return 0
            hosts.sort(key=lambda h: (h.available != "unavailable", -h.active_problems, h.host))
            for h in hosts:
                label = "DOWN" if h.available == "unavailable" else "OK"
                prob_str = f"{h.active_problems} problems" if h.active_problems else "0 problems"
                err_str = f"  {h.error}" if h.error else ""
                print(f"  {label:<5} {h.host:<25} {h.name:<25} {prob_str}{err_str}")
            down = sum(1 for h in hosts if h.available == "unavailable")
            with_problems = sum(1 for h in hosts if h.active_problems > 0)
            print(f"\n  {len(hosts)} hosts — {down} unavailable, {with_problems} with active problems")
            if args.csv_file:
                write_csv(hosts, args.csv_file, "hosts")
                print(f"\nCSV written to {args.csv_file}", file=sys.stderr)
            return 1 if down > 0 or with_problems > 0 else 0

        else:  # health
            health = fetch_health(url, auth)
            print(f"  Monitored hosts:  {health.monitored_hosts} / {health.total_hosts} total")
            label = "unavailable" if health.unavailable_hosts else "unavailable"
            print(f"  Unavailable:      {health.unavailable_hosts}")
            print(f"  Active problems:  {health.active_problems}")
            if health.problems_by_severity:
                for sev in ["CRIT", "HIGH", "AVG", "WARN", "INFO", "N/C"]:
                    count = health.problems_by_severity.get(sev, 0)
                    if count:
                        print(f"    {sev:<5} {count}")
            if args.csv_file:
                log.warning("CSV export is not supported for health mode")
            return 0 if health.ok else 1

    except (RuntimeError, urllib.error.URLError) as exc:
        log.error("Zabbix query failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
