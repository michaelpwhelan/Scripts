#!/usr/bin/env python3
"""Bulk forward and reverse DNS lookups.

Resolves hostnames to IPs (forward) and IPs to PTR records (reverse),
printing a summary table and optionally exporting CSV.

Examples:
    python resolve_dns_bulk.py github.com 8.8.8.8 cloudflare.com
    python resolve_dns_bulk.py -f hosts.txt --csv results.csv
    echo -e "1.1.1.1\\ngoogle.com" | python resolve_dns_bulk.py -
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import logging
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

log = logging.getLogger("resolve_dns_bulk")

MAX_WORKERS = 20


@dataclass
class DnsResult:
    query: str
    query_type: str = ""
    forward_ips: list[str] = field(default_factory=list)
    forward_error: str = ""
    reverse_ptr: str = ""
    reverse_error: str = ""

    @property
    def ok(self) -> bool:
        return not self.forward_error


def is_ip(value: str) -> bool:
    """Check whether a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def forward_lookup(host: str) -> tuple[list[str], str]:
    """Resolve a hostname to its IP addresses (A/AAAA)."""
    try:
        results = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = sorted({r[4][0] for r in results})
        return ips, ""
    except socket.gaierror as exc:
        return [], str(exc)


def reverse_lookup(ip: str) -> tuple[str, str]:
    """Resolve an IP address to its PTR hostname."""
    try:
        return socket.gethostbyaddr(ip)[0], ""
    except (socket.herror, socket.gaierror) as exc:
        return "", str(exc)


def resolve(target: str) -> DnsResult:
    """Run forward and reverse lookups for a single target."""
    target = target.strip()
    result = DnsResult(query=target)

    if is_ip(target):
        result.query_type = "IP"
        result.forward_ips = [target]
        result.reverse_ptr, result.reverse_error = reverse_lookup(target)
    else:
        result.query_type = "Hostname"
        result.forward_ips, result.forward_error = forward_lookup(target)
        if result.forward_ips:
            result.reverse_ptr, result.reverse_error = reverse_lookup(
                result.forward_ips[0]
            )
        else:
            result.reverse_error = "No IP to reverse"

    return result


def load_targets(args: argparse.Namespace) -> list[str]:
    """Build target list from positional args, -f file, or stdin."""
    targets: list[str] = []

    for t in args.targets:
        if t == "-":
            targets.extend(
                line.strip()
                for line in sys.stdin
                if line.strip() and not line.startswith("#")
            )
        else:
            targets.append(t)

    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            targets.extend(
                line.strip()
                for line in fh
                if line.strip() and not line.startswith("#")
            )

    return targets


def write_csv(results: list[DnsResult], dest: str | None) -> None:
    """Write results as CSV to a file or stdout."""
    fields = ["query", "type", "forward_ips", "forward_error", "reverse_ptr", "reverse_error"]
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
                "query": r.query,
                "type": r.query_type,
                "forward_ips": "; ".join(r.forward_ips),
                "forward_error": r.forward_error,
                "reverse_ptr": r.reverse_ptr,
                "reverse_error": r.reverse_error,
            })
    finally:
        if dest:
            buf.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Bulk forward and reverse DNS lookups.",
    )
    p.add_argument(
        "targets",
        nargs="*",
        metavar="HOST_OR_IP",
        help="hostnames or IPs to resolve (use '-' to read stdin)",
    )
    p.add_argument(
        "-f", "--file",
        metavar="PATH",
        help="file with one host/IP per line",
    )
    p.add_argument(
        "--csv",
        metavar="FILE",
        dest="csv_file",
        help="write CSV report to FILE",
    )
    p.add_argument(
        "-j", "--workers",
        type=int,
        default=MAX_WORKERS,
        metavar="N",
        help=f"max parallel lookups (default: {MAX_WORKERS})",
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

    results: list[DnsResult] = []
    with ThreadPoolExecutor(max_workers=min(args.workers, len(targets))) as pool:
        futures = {
            pool.submit(resolve, t): t for t in targets
        }
        for future in as_completed(futures):
            results.append(future.result())

    # Sort to match input order
    order = {t: i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order.get(r.query, 0))

    # Print summary table
    for r in results:
        ips = "; ".join(r.forward_ips)
        if r.forward_error:
            print(f"  FAIL  {r.query:<40} {r.forward_error}")
        elif r.reverse_ptr:
            print(f"  OK    {r.query:<40} -> {ips:<30} PTR {r.reverse_ptr}")
        else:
            err = r.reverse_error or "no PTR"
            print(f"  OK    {r.query:<40} -> {ips:<30} ({err})")

    if args.csv_file:
        write_csv(results, args.csv_file)
        print(f"\nCSV written to {args.csv_file}", file=sys.stderr)

    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
