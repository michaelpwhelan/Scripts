#!/usr/bin/env python3
"""Check SSL/TLS certificate expiry for one or more hosts.

Connects to each host:port, retrieves the certificate, and reports
how many days remain before expiry.  Exits non-zero when any cert is
expired or within the warning threshold — suitable for cron / monitoring.

Examples:
    python test_cert_expiry.py github.com cloudflare.com
    python test_cert_expiry.py -f hosts.txt --warn 14 --csv report.csv
    python test_cert_expiry.py mail.example.com:993 vpn.example.com:8443
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger("test_cert_expiry")

DEFAULT_PORT = 443
DEFAULT_WARN_DAYS = 30
DEFAULT_TIMEOUT = 5
MAX_WORKERS = 20


@dataclass
class CertResult:
    host: str
    port: int
    status: str = ""
    subject: str = ""
    issuer: str = ""
    expiry: str = ""
    days_left: int | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "OK"


def check_cert(host: str, port: int, timeout: int, warn_days: int) -> CertResult:
    """Connect with TLS validation and inspect the peer certificate."""
    result = CertResult(host=host, port=port)
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        result.status = "INVALID"
        result.error = str(exc)
        return result
    except (OSError, socket.timeout) as exc:
        result.status = "ERROR"
        result.error = str(exc)
        return result

    if not cert:
        result.status = "ERROR"
        result.error = "No certificate returned"
        return result

    not_after = cert.get("notAfter", "")
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        result.status = "ERROR"
        result.error = f"Unparseable notAfter: {not_after!r}"
        return result

    subject_parts = dict(x[0] for x in cert.get("subject", ()))
    issuer_parts = dict(x[0] for x in cert.get("issuer", ()))

    result.subject = subject_parts.get("commonName", "")
    result.issuer = issuer_parts.get("organizationName", "")
    result.expiry = expiry.strftime("%Y-%m-%d")
    result.days_left = (expiry - datetime.now(timezone.utc)).days

    if result.days_left < 0:
        result.status = "EXPIRED"
    elif result.days_left <= warn_days:
        result.status = "WARNING"
    else:
        result.status = "OK"

    return result


def parse_target(value: str) -> tuple[str, int]:
    """Parse 'host' or 'host:port' into (host, port)."""
    if value.startswith("["):
        # IPv6 bracket notation: [::1]:443
        bracket_end = value.find("]")
        if bracket_end == -1:
            return value, DEFAULT_PORT
        host = value[1:bracket_end]
        rest = value[bracket_end + 1 :]
        port = int(rest[1:]) if rest.startswith(":") else DEFAULT_PORT
        return host, port
    if value.count(":") == 1:
        host, port_str = value.rsplit(":", 1)
        return host, int(port_str)
    return value, DEFAULT_PORT


def load_targets(args: argparse.Namespace) -> list[tuple[str, int]]:
    """Build target list from CLI args and/or a host file."""
    targets = [parse_target(t) for t in args.targets]
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(parse_target(line))
    return targets


def write_csv(results: list[CertResult], dest: str | None) -> None:
    """Write results as CSV to a file or stdout."""
    fields = ["host", "port", "status", "subject", "issuer", "expiry", "days_left", "error"]
    buf: io.IOBase
    if dest:
        buf = open(dest, "w", newline="", encoding="utf-8")
    else:
        buf = sys.stdout

    try:
        writer = csv.DictWriter(buf, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({f: getattr(r, f) for f in fields})
    finally:
        if dest:
            buf.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check SSL/TLS certificate expiry for one or more hosts.",
    )
    p.add_argument(
        "targets",
        nargs="*",
        metavar="HOST[:PORT]",
        help="hosts to check (default port 443)",
    )
    p.add_argument(
        "-f", "--file",
        metavar="PATH",
        help="file with one host[:port] per line",
    )
    p.add_argument(
        "-w", "--warn",
        type=int,
        default=DEFAULT_WARN_DAYS,
        metavar="DAYS",
        help=f"warning threshold in days (default: {DEFAULT_WARN_DAYS})",
    )
    p.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        metavar="SEC",
        help=f"connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    p.add_argument(
        "--csv",
        metavar="FILE",
        dest="csv_file",
        help="write CSV report to FILE (omit for stdout summary only)",
    )
    p.add_argument(
        "-j", "--workers",
        type=int,
        default=MAX_WORKERS,
        metavar="N",
        help=f"max parallel connections (default: {MAX_WORKERS})",
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

    targets = load_targets(args)
    if not targets:
        log.error("No targets specified. Pass hosts as arguments or use -f FILE.")
        return 2

    results: list[CertResult] = []
    with ThreadPoolExecutor(max_workers=min(args.workers, len(targets))) as pool:
        futures = {
            pool.submit(check_cert, host, port, args.timeout, args.warn): (host, port)
            for host, port in targets
        }
        for future in as_completed(futures):
            results.append(future.result())

    # Sort to match input order
    order = {(h, p): i for i, (h, p) in enumerate(targets)}
    results.sort(key=lambda r: order.get((r.host, r.port), 0))

    # Print summary
    for r in results:
        label = f"{r.host}:{r.port}"
        if r.status == "OK":
            print(f"  OK      {label:<40} expires {r.expiry} ({r.days_left}d)")
        elif r.status == "WARNING":
            print(f"  WARN    {label:<40} expires {r.expiry} ({r.days_left}d)")
        elif r.status == "EXPIRED":
            print(f"  EXPIRED {label:<40} expired {abs(r.days_left)}d ago")
        elif r.status == "INVALID":
            print(f"  INVALID {label:<40} {r.error}")
        else:
            print(f"  ERROR   {label:<40} {r.error}")

    if args.csv_file:
        write_csv(results, args.csv_file)
        print(f"\nCSV written to {args.csv_file}", file=sys.stderr)

    # Exit code: 1 if any cert is not OK, 0 if all healthy
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
