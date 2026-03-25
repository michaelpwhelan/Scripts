#!/usr/bin/env python3
"""Verify Backblaze B2 backup freshness and immutability.

Lists B2 buckets and checks that each contains recent backups within a
configurable age window.  Reports PASS/FAIL/WARN per bucket, validating
the offsite component of a 3-2-1 backup strategy.  Exits non-zero when
any bucket is stale or missing immutability — suitable for cron / FFIEC
compliance verification.

Examples:
    export B2_KEY_ID=your_key_id B2_APP_KEY=your_app_key
    python check_b2_backups.py
    python check_b2_backups.py --max-age 48 --csv backup_report.csv
    python check_b2_backups.py --bucket my-veeam-bucket -v
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger("check_b2_backups")

B2_AUTH_URL = "https://api.backblazeb2.com/b2api/v3/b2_authorize_account"
DEFAULT_MAX_AGE_HOURS = 24
DEFAULT_SCAN_DEPTH = 1000


@dataclass
class B2Auth:
    account_id: str
    auth_token: str
    api_url: str


@dataclass
class BucketCheck:
    bucket_name: str
    bucket_id: str
    file_lock_enabled: bool = False
    newest_file: str = ""
    newest_age_hours: float = -1
    file_count: int = 0
    status: str = ""
    issues: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "PASS"


def b2_authorize(key_id: str, app_key: str) -> B2Auth:
    """Authenticate to B2 and return auth context."""
    creds = base64.b64encode(f"{key_id}:{app_key}".encode()).decode()
    req = urllib.request.Request(
        B2_AUTH_URL,
        headers={"Authorization": f"Basic {creds}"},
        method="GET",
    )
    log.debug("Authorizing with B2 API")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise RuntimeError("B2 authorization failed — check B2_KEY_ID and B2_APP_KEY") from exc
        raise RuntimeError(f"B2 auth HTTP {exc.code}: {exc.reason}") from exc

    storage = data.get("apiInfo", {}).get("storageApi", {})
    return B2Auth(
        account_id=data["accountId"],
        auth_token=data["authorizationToken"],
        api_url=storage.get("apiUrl", data.get("apiUrl", "")),
    )


def b2_api_call(auth: B2Auth, endpoint: str, params: dict) -> dict:
    """POST to a B2 API endpoint and return parsed JSON."""
    url = f"{auth.api_url}{endpoint}"
    body = json.dumps(params).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": auth.auth_token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    log.debug("POST %s", endpoint)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode()
        except Exception:
            pass
        raise RuntimeError(f"B2 API {endpoint} HTTP {exc.code}: {err_body or exc.reason}") from exc


def list_buckets(auth: B2Auth, bucket_name: str | None = None) -> list[dict]:
    """List B2 buckets, optionally filtered by name."""
    params: dict = {"accountId": auth.account_id}
    if bucket_name:
        params["bucketName"] = bucket_name
    data = b2_api_call(auth, "/b2api/v3/b2_list_buckets", params)
    return data.get("buckets", [])


def find_newest_file(auth: B2Auth, bucket_id: str, scan_depth: int) -> tuple[str, int, int]:
    """Scan up to scan_depth files to find the newest upload timestamp.

    Returns (filename, upload_timestamp_ms, files_scanned).
    """
    newest_name = ""
    newest_ts = 0
    scanned = 0
    start_file = None

    while scanned < scan_depth:
        params: dict = {
            "bucketId": bucket_id,
            "maxFileCount": min(1000, scan_depth - scanned),
        }
        if start_file:
            params["startFileName"] = start_file
        data = b2_api_call(auth, "/b2api/v3/b2_list_file_names", params)
        files = data.get("files", [])
        if not files:
            break
        for f in files:
            ts = f.get("uploadTimestamp", 0)
            if ts > newest_ts:
                newest_ts = ts
                newest_name = f.get("fileName", "")
        scanned += len(files)
        next_file = data.get("nextFileName")
        if not next_file:
            break
        start_file = next_file
        log.debug("Scanned %d files in bucket %s so far", scanned, bucket_id)

    return newest_name, newest_ts, scanned


def check_bucket(auth: B2Auth, bucket: dict, max_age_hours: int, scan_depth: int) -> BucketCheck:
    """Run freshness and immutability checks on a single bucket."""
    result = BucketCheck(
        bucket_name=bucket.get("bucketName", ""),
        bucket_id=bucket.get("bucketId", ""),
    )

    lock_cfg = bucket.get("fileLockConfiguration", {})
    result.file_lock_enabled = lock_cfg.get("isFileLockEnabled", False)

    log.debug("Checking bucket %s (lock=%s)", result.bucket_name, result.file_lock_enabled)
    newest_name, newest_ts, scanned = find_newest_file(auth, result.bucket_id, scan_depth)
    result.file_count = scanned
    result.newest_file = newest_name

    issues: list[str] = []

    if newest_ts > 0:
        newest_dt = datetime.fromtimestamp(newest_ts / 1000, tz=timezone.utc)
        age = (datetime.now(timezone.utc) - newest_dt).total_seconds() / 3600
        result.newest_age_hours = round(age, 1)

        if age > max_age_hours:
            issues.append(f"Backup older than {max_age_hours}h threshold ({result.newest_age_hours:.0f}h)")
    elif scanned == 0:
        result.newest_age_hours = -1
        issues.append("Bucket is empty — no backup files found")
    else:
        issues.append("No files with upload timestamps found")

    if not result.file_lock_enabled:
        issues.append("Object Lock not enabled (immutability required)")

    result.issues = issues
    if any("older than" in i or "empty" in i or "No files" in i for i in issues):
        result.status = "FAIL"
    elif issues:
        result.status = "WARN"
    else:
        result.status = "PASS"

    return result


def write_csv(results: list[BucketCheck], dest: str | None) -> None:
    """Write results as CSV to a file or stdout."""
    fields = ["status", "bucket_name", "file_lock_enabled", "newest_file",
              "newest_age_hours", "file_count", "issues"]
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
                "status": r.status,
                "bucket_name": r.bucket_name,
                "file_lock_enabled": r.file_lock_enabled,
                "newest_file": r.newest_file,
                "newest_age_hours": r.newest_age_hours,
                "file_count": r.file_count,
                "issues": "; ".join(r.issues),
            })
    finally:
        if dest:
            buf.close()


def format_age(hours: float) -> str:
    """Format hours into a human-readable age string."""
    if hours < 0:
        return "N/A"
    if hours < 1:
        return f"{int(hours * 60)}m ago"
    if hours < 48:
        return f"{hours:.0f}h ago"
    return f"{hours / 24:.0f}d ago"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Verify Backblaze B2 backup freshness and immutability.",
    )
    p.add_argument(
        "--key-id",
        metavar="ID",
        help="B2 application key ID (default: env B2_KEY_ID)",
    )
    p.add_argument(
        "--app-key",
        metavar="KEY",
        help="B2 application key (default: env B2_APP_KEY)",
    )
    p.add_argument(
        "--bucket",
        metavar="NAME",
        help="check only this bucket (default: all buckets)",
    )
    p.add_argument(
        "--max-age",
        type=int,
        default=DEFAULT_MAX_AGE_HOURS,
        metavar="HOURS",
        help=f"max hours since last backup before FAIL (default: {DEFAULT_MAX_AGE_HOURS})",
    )
    p.add_argument(
        "--scan-depth",
        type=int,
        default=DEFAULT_SCAN_DEPTH,
        metavar="N",
        help=f"max files to scan per bucket for newest (default: {DEFAULT_SCAN_DEPTH})",
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

    key_id = args.key_id or os.environ.get("B2_KEY_ID", "")
    app_key = args.app_key or os.environ.get("B2_APP_KEY", "")
    if not key_id or not app_key:
        log.error(
            "B2 credentials required. Use --key-id/--app-key or set B2_KEY_ID and B2_APP_KEY."
        )
        return 2

    try:
        auth = b2_authorize(key_id, app_key)
    except (RuntimeError, urllib.error.URLError) as exc:
        log.error("B2 authorization failed: %s", exc)
        return 1

    try:
        buckets = list_buckets(auth, args.bucket)
    except (RuntimeError, urllib.error.URLError) as exc:
        log.error("Failed to list buckets: %s", exc)
        return 1

    if not buckets:
        msg = f"No bucket named '{args.bucket}' found." if args.bucket else "No buckets found."
        log.error(msg)
        return 2

    results: list[BucketCheck] = []
    for bucket in buckets:
        try:
            result = check_bucket(auth, bucket, args.max_age, args.scan_depth)
        except (RuntimeError, urllib.error.URLError) as exc:
            result = BucketCheck(
                bucket_name=bucket.get("bucketName", ""),
                bucket_id=bucket.get("bucketId", ""),
                status="FAIL",
                issues=[f"Check failed: {exc}"],
            )
        results.append(result)

    for r in results:
        lock_str = "Lock: ON " if r.file_lock_enabled else "Lock: OFF"
        age_str = f"Latest: {format_age(r.newest_age_hours)}"
        file_str = r.newest_file.rsplit("/", 1)[-1] if r.newest_file else "(none)"
        if len(file_str) > 40:
            file_str = file_str[:37] + "..."
        print(f"  {r.status:<4}  {r.bucket_name:<30} {lock_str}  {age_str:<18} {file_str}")
        for issue in r.issues:
            print(f"        -> {issue}")

    pass_count = sum(1 for r in results if r.status == "PASS")
    fail_count = sum(1 for r in results if r.status == "FAIL")
    warn_count = sum(1 for r in results if r.status == "WARN")
    print(f"\n  {pass_count} pass, {fail_count} fail, {warn_count} warn — {len(results)} buckets (max age: {args.max_age}h)")

    if args.csv_file:
        write_csv(results, args.csv_file)
        print(f"\nCSV written to {args.csv_file}", file=sys.stderr)

    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
