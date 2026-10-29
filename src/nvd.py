"""
nvd.py — Collect NVD metadata for CVEs in the 2024 CISA KEV cohort.

Input:
    kev_2024_filtered.xlsx
    Sheet: KEV_2024
    Required column: cveID

Output:
    nvd_metadata.csv
    nvd_fetch_log.csv

Install:
    pip install pandas openpyxl requests

Run:
    python nvd.py

Optional:
    python nvd.py --input kev_2024_filtered.xlsx --output nvd_metadata.csv
    Set NVD_API_KEY as an environment variable to use your NVD API key.

Notes:
- Uses the official NVD CVE API 2.0.
- Saves progress after each CVE so interrupted runs can resume.
- Without an API key, uses a conservative delay between requests.
- Missing NVD scores/fields are left blank; the script does not infer them.
"""

from __future__ import annotations

import argparse
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_INPUT = "kev_2024_filtered.xlsx"
DEFAULT_OUTPUT = "nvd_metadata.csv"
DEFAULT_LOG = "nvd_fetch_log.csv"
REQUEST_TIMEOUT = 45
MAX_RETRIES = 5


def clean_text(value: Any) -> str:
    """Convert an optional value to a clean string."""
    if value is None:
        return ""
    return str(value).strip()


def first_description(cve_record: dict) -> str:
    for item in cve_record.get("descriptions", []) or []:
        if item.get("lang") == "en":
            return clean_text(item.get("value"))
    return ""


def get_cwe_ids(cve_record: dict) -> str:
    values = []
    for weakness in cve_record.get("weaknesses", []) or []:
        for description in weakness.get("description", []) or []:
            if description.get("lang") == "en":
                value = clean_text(description.get("value"))
                if value and value not in values:
                    values.append(value)
    return "; ".join(values)


def extract_cvss(cve_record: dict) -> dict:
    """
    Return a consistent selected CVSS score plus version-specific fields.
    Selection priority for the matching score: v3.1, v3.0, v2, then v4.0.
    The separate fields preserve whichever versions NVD supplies.
    """
    metrics = cve_record.get("metrics", {}) or {}
    result = {
        "cvss_score": "",
        "cvss_severity": "",
        "cvss_version": "",
        "cvss_v31_score": "",
        "cvss_v31_severity": "",
        "cvss_v30_score": "",
        "cvss_v30_severity": "",
        "cvss_v2_score": "",
        "cvss_v2_severity": "",
        "cvss_v40_score": "",
        "cvss_v40_severity": "",
    }

    metric_map = [
        ("cvssMetricV31", "cvss_v31_score", "cvss_v31_severity", "3.1"),
        ("cvssMetricV30", "cvss_v30_score", "cvss_v30_severity", "3.0"),
        ("cvssMetricV2", "cvss_v2_score", "cvss_v2_severity", "2.0"),
        ("cvssMetricV40", "cvss_v40_score", "cvss_v40_severity", "4.0"),
    ]

    selected = None
    for metric_key, score_col, severity_col, version in metric_map:
        entries = metrics.get(metric_key, []) or []
        if not entries:
            continue

        # Prefer NVD's primary assessment if present; otherwise use the first entry.
        chosen = next(
            (entry for entry in entries if entry.get("type") == "Primary"),
            entries[0],
        )
        cvss_data = chosen.get("cvssData", {}) or {}
        score = cvss_data.get("baseScore", "")
        severity = cvss_data.get("baseSeverity", "") or chosen.get("baseSeverity", "")

        result[score_col] = score
        result[severity_col] = severity

        if selected is None and score != "":
            selected = (score, severity, version)

    if selected:
        result["cvss_score"], result["cvss_severity"], result["cvss_version"] = selected
    return result


def extract_vendor_products(cve_record: dict) -> tuple[str, str]:
    """Extract distinct vendor/product names from NVD CPE criteria strings."""
    vendors, products = [], []

    def add_cpe(criteria: str) -> None:
        parts = criteria.split(":")
        # CPE 2.3 format: cpe:2.3:<part>:<vendor>:<product>:...
        if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
            vendor, product = parts[3], parts[4]
            if vendor and vendor != "*" and vendor != "-" and vendor not in vendors:
                vendors.append(vendor)
            if product and product != "*" and product != "-" and product not in products:
                products.append(product)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            criteria = node.get("criteria")
            if isinstance(criteria, str):
                add_cpe(criteria)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(cve_record.get("configurations", []))
    return "; ".join(vendors), "; ".join(products)


def extract_record(cve_id: str, cve_record: dict) -> dict:
    cvss = extract_cvss(cve_record)
    vendor, product = extract_vendor_products(cve_record)
    published = clean_text(cve_record.get("published"))
    last_modified = clean_text(cve_record.get("lastModified"))

    return {
        "cve_id": cve_id,
        "nvd_found": True,
        "published_date": published[:10] if published else "",
        "last_modified_date": last_modified[:10] if last_modified else "",
        "cvss_score": cvss["cvss_score"],
        "cvss_severity": cvss["cvss_severity"],
        "cvss_version": cvss["cvss_version"],
        "cvss_band": cvss["cvss_severity"].upper() if cvss["cvss_severity"] else "",
        "cvss_v31_score": cvss["cvss_v31_score"],
        "cvss_v31_severity": cvss["cvss_v31_severity"],
        "cvss_v30_score": cvss["cvss_v30_score"],
        "cvss_v30_severity": cvss["cvss_v30_severity"],
        "cvss_v2_score": cvss["cvss_v2_score"],
        "cvss_v2_severity": cvss["cvss_v2_severity"],
        "cvss_v40_score": cvss["cvss_v40_score"],
        "cvss_v40_severity": cvss["cvss_v40_severity"],
        "cwe_ids": get_cwe_ids(cve_record),
        "vendor": vendor,
        "product": product,
        "description": first_description(cve_record),
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "fetch_status": "success",
        "fetch_error": "",
        "fetched_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def load_cve_ids(input_path: Path) -> list[str]:
    if not input_path.exists():
        raise FileNotFoundError(
            f"Could not find input file: {input_path}\n"
            "Place kev_2024_filtered.xlsx in this folder or pass --input."
        )

    workbook = pd.ExcelFile(input_path)
    sheet_name = "KEV_2024" if "KEV_2024" in workbook.sheet_names else workbook.sheet_names[0]
    frame = pd.read_excel(input_path, sheet_name=sheet_name)

    # Match the expected CISA column case-insensitively; tolerate whitespace.
    column_lookup = {str(column).strip().lower(): column for column in frame.columns}
    cve_column = column_lookup.get("cveid") or column_lookup.get("cve_id") or column_lookup.get("cve")
    if cve_column is None:
        raise ValueError(
            f"No CVE ID column found in sheet '{sheet_name}'. "
            f"Columns found: {list(frame.columns)}"
        )

    ids = (
        frame[cve_column]
        .dropna()
        .astype(str)
        .str.strip()
        .str.upper()
        .drop_duplicates()
        .tolist()
    )
    ids = [value for value in ids if value.startswith("CVE-")]
    if not ids:
        raise ValueError(f"No valid CVE IDs found in column '{cve_column}'.")
    print(f"Loaded {len(ids)} unique CVE IDs from sheet '{sheet_name}' ({cve_column}).")
    return ids


def fetch_cve(
    session: requests.Session,
    cve_id: str,
    api_key: str | None,
) -> tuple[dict | None, str]:
    headers = {"apiKey": api_key} if api_key else {}
    params = {"cveId": cve_id}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                payload = response.json()
                vulnerabilities = payload.get("vulnerabilities", []) or []
                if not vulnerabilities:
                    return None, "CVE not returned by NVD API"
                return vulnerabilities[0].get("cve", {}), ""

            if response.status_code in (403, 429, 500, 502, 503, 504):
                wait = min(30, (2 ** (attempt - 1)) * 2) + random.uniform(0, 1)
                if attempt < MAX_RETRIES:
                    print(
                        f"  HTTP {response.status_code} for {cve_id}; "
                        f"retrying in {wait:.1f}s ({attempt}/{MAX_RETRIES})"
                    )
                    time.sleep(wait)
                    continue

            return None, f"HTTP {response.status_code}: {response.text[:250]}"

        except requests.RequestException as exc:
            if attempt < MAX_RETRIES:
                wait = min(30, (2 ** (attempt - 1)) * 2) + random.uniform(0, 1)
                print(f"  Network error for {cve_id}; retrying in {wait:.1f}s: {exc}")
                time.sleep(wait)
            else:
                return None, f"Network error after {MAX_RETRIES} attempts: {exc}"

    return None, "Unknown fetch error"


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch NVD metadata for the 2024 KEV cohort.")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input Excel workbook")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output metadata CSV")
    parser.add_argument("--log", default=DEFAULT_LOG, help="Fetch log CSV")
    parser.add_argument(
        "--delay",
        type=float,
        default=None,
        help="Seconds between requests (default: 6 without API key, 0.7 with API key)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    log_path = Path(args.log)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    api_key = os.getenv("NVD_API_KEY", "").strip() or None
    delay = args.delay if args.delay is not None else (0.7 if api_key else 6.0)

    cve_ids = load_cve_ids(input_path)

    # Resume support: keep successfully fetched rows and only retry missing/failed IDs.
    if output_path.exists():
        existing = pd.read_csv(output_path, dtype={"cve_id": str}).fillna("")
        if "cve_id" in existing.columns:
            successful = existing[
                existing.get("fetch_status", pd.Series(index=existing.index, dtype=str)).eq("success")
            ]
            records_by_id = {
                row["cve_id"]: row.to_dict()
                for _, row in successful.iterrows()
                if row.get("cve_id")
            }
        else:
            records_by_id = {}
    else:
        records_by_id = {}

    # Keep one latest log entry per CVE. The previous implementation appended
    # the entire accumulated log list after every request, creating duplicates.
    log_by_id = {}
    if log_path.exists():
        try:
            old_log = pd.read_csv(log_path, dtype={"cve_id": str}).fillna("")
            if {"cve_id", "fetch_status", "fetch_error", "fetched_at_utc"}.issubset(old_log.columns):
                old_log = old_log.drop_duplicates(subset=["cve_id"], keep="last")
                log_by_id = {
                    row["cve_id"]: row
                    for row in old_log.to_dict(orient="records")
                    if row.get("cve_id")
                }
        except (pd.errors.ParserError, OSError):
            print("Warning: existing fetch log could not be read; a fresh log will be created.")

    # Ensure already-fetched metadata rows also have a success entry in the log.
    for cve_id, metadata_row in records_by_id.items():
        log_by_id.setdefault(cve_id, {
            "cve_id": cve_id,
            "fetch_status": "success",
            "fetch_error": "",
            "fetched_at_utc": metadata_row.get("fetched_at_utc", ""),
        })

    total = len(cve_ids)

    with requests.Session() as session:
        session.headers.update({"User-Agent": "ADA-EPSS-KEV-study/1.0 (academic research)"})

        for index, cve_id in enumerate(cve_ids, start=1):
            if cve_id in records_by_id:
                print(f"[{index}/{total}] Already saved: {cve_id}")
                continue

            print(f"[{index}/{total}] Fetching {cve_id} ...")
            cve_record, error = fetch_cve(session, cve_id, api_key)

            if cve_record is not None:
                row = extract_record(cve_id, cve_record)
                records_by_id[cve_id] = row
                log_by_id[cve_id] = {
                    "cve_id": cve_id,
                    "fetch_status": "success",
                    "fetch_error": "",
                    "fetched_at_utc": row["fetched_at_utc"],
                }
            else:
                now = datetime.now(timezone.utc).isoformat(timespec="seconds")
                log_by_id[cve_id] = {
                    "cve_id": cve_id,
                    "fetch_status": "not_found" if error == "CVE not returned by NVD API" else "error",
                    "fetch_error": error,
                    "fetched_at_utc": now,
                }
                print(f"  Warning: {error}")

            # Save after every CVE, so stopping the script does not lose completed work.
            if records_by_id:
                saved = pd.DataFrame(records_by_id.values())
                saved = saved.sort_values("cve_id")
                saved.to_csv(output_path, index=False)

            # Rewrite a deduplicated log snapshot (one row per CVE).
            pd.DataFrame(log_by_id.values()).sort_values("cve_id").to_csv(log_path, index=False)
            time.sleep(max(0.0, delay))

    # Ensure output contains a row for every input CVE, including fetch failures.
    final_rows = []
    existing_ids = set(records_by_id)
    failed_latest = {
        cve_id: row for cve_id, row in log_by_id.items()
        if row.get("fetch_status") != "success"
    }
    for cve_id in cve_ids:
        if cve_id in records_by_id:
            final_rows.append(records_by_id[cve_id])
        elif cve_id in failed_latest:
            failure = failed_latest[cve_id]
            final_rows.append({
                "cve_id": cve_id,
                "nvd_found": False,
                "published_date": "",
                "last_modified_date": "",
                "cvss_score": "",
                "cvss_severity": "",
                "cvss_version": "",
                "cvss_band": "",
                "cvss_v31_score": "",
                "cvss_v31_severity": "",
                "cvss_v30_score": "",
                "cvss_v30_severity": "",
                "cvss_v2_score": "",
                "cvss_v2_severity": "",
                "cvss_v40_score": "",
                "cvss_v40_severity": "",
                "cwe_ids": "",
                "vendor": "",
                "product": "",
                "description": "",
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "fetch_status": failure["fetch_status"],
                "fetch_error": failure["fetch_error"],
                "fetched_at_utc": failure["fetched_at_utc"],
            })

    if final_rows:
        pd.DataFrame(final_rows).to_csv(output_path, index=False)

    success_count = sum(1 for row in final_rows if row.get("fetch_status") == "success")
    print("\nFinished.")
    print(f"Input CVEs: {len(cve_ids)}")
    print(f"Successfully fetched: {success_count}")
    print(f"Missing/failed: {len(cve_ids) - success_count}")
    print(f"Metadata CSV: {output_path.resolve()}")
    print(f"Fetch log: {log_path.resolve()}")
    if len(cve_ids) > success_count:
        print("Rerun the same command to retry CVEs that did not succeed.")


if __name__ == "__main__":
    main()
