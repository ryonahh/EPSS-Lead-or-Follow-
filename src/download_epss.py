
from datetime import date, timedelta
from pathlib import Path
import csv
import gzip
import time

import requests


# Study date range: inclusive of both start and end dates
START_DATE = date(2023, 11, 2)
END_DATE = date(2025, 3, 1)

OUTPUT_DIR = Path("data/raw/epss_daily")
LOG_FILE = Path("data/processed/epss_download_log.csv")

EXPECTED_MODEL = "v2023.03.01"
BASE_URL = (
    "https://epss.empiricalsecurity.com/"
    "epss_scores-{date}.csv.gz"
)


def validate_file(path: Path, expected_date: date) -> tuple[bool, str]:
    """Validate gzip integrity, EPSS model metadata, and CSV header."""
    try:
        with gzip.open(path, "rt", encoding="utf-8") as file:
            metadata = file.readline().strip()
            header = file.readline().strip()

        expected_metadata = (
            f"#model_version:{EXPECTED_MODEL},"
            f"score_date:{expected_date.isoformat()}T00:00:00+0000"
        )

        if metadata != expected_metadata:
            return False, f"Unexpected metadata: {metadata}"

        if header != "cve,epss,percentile":
            return False, f"Unexpected CSV header: {header}"

        return True, "validated"

    except (OSError, EOFError, UnicodeDecodeError) as exc:
        return False, f"Invalid gzip/CSV file: {exc}"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    records = []

    total = (END_DATE - START_DATE).days + 1
    current = START_DATE

    print(f"Planned dates: {total}")
    print(f"Date range: {START_DATE} through {END_DATE}")
    print(f"Output directory: {OUTPUT_DIR}")
    print("Existing valid files will be reused.")
    print("Each new download will be validated before saving.\n")

    while current <= END_DATE:
        date_text = current.isoformat()
        path = OUTPUT_DIR / f"epss_scores-{date_text}.csv.gz"

        # Reuse an existing file only if its metadata and header are valid.
        if path.exists():
            valid, message = validate_file(path, current)

            if valid:
                records.append({
                    "date": date_text,
                    "status": "existing_valid",
                    "message": message,
                })
                print(f"{date_text}: existing_valid")
                current += timedelta(days=1)
                continue

            print(f"{date_text}: existing file is invalid; downloading again.")

        url = BASE_URL.format(date=date_text)
        status = "failed"
        message = "No successful attempt"

        # Retry each download up to three times.
        for attempt in range(1, 4):
            temporary = path.with_suffix(".csv.gz.tmp")

            try:
                print(
                    f"{date_text}: download attempt "
                    f"{attempt}/3"
                )

                response = session.get(url, timeout=60)
                response.raise_for_status()

                temporary.write_bytes(response.content)

                valid, validation_message = validate_file(
                    temporary, current
                )

                if not valid:
                    raise ValueError(validation_message)

                # Replace the final file only after validation succeeds.
                temporary.replace(path)

                status = "downloaded"
                message = "validated"
                break

            except (
                requests.RequestException,
                OSError,
                ValueError,
            ) as exc:
                message = str(exc)
                print(f"  Attempt {attempt} failed: {message}")

                if attempt < 3:
                    time.sleep(attempt * 2)

            finally:
                # Remove any incomplete temporary file.
                temporary.unlink(missing_ok=True)

        records.append({
            "date": date_text,
            "status": status,
            "message": message,
        })

        print(f"{date_text}: {status} — {message}")

        # Brief pause between dates to avoid sending requests too quickly.
        time.sleep(0.5)
        current += timedelta(days=1)

    # Write the complete run log, including failures.
    with LOG_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["date", "status", "message"],
        )
        writer.writeheader()
        writer.writerows(records)

    # Summarize results.
    counts = {}

    for record in records:
        status = record["status"]
        counts[status] = counts.get(status, 0) + 1

    print("\n========== DOWNLOAD SUMMARY ==========")

    for status, count in sorted(counts.items()):
        print(f"{status}: {count}")

    failed_dates = [
        record["date"]
        for record in records
        if record["status"] == "failed"
    ]

    print(f"\nExpected dates: {total}")
    print(f"Logged dates: {len(records)}")
    print(f"Failed dates: {len(failed_dates)}")
    print(f"Log saved to: {LOG_FILE}")

    if len(records) != total or failed_dates:
        print(
            "\nWARNING: Download incomplete. "
            "Check the log and retry failed dates."
        )

        if failed_dates:
            print("Failed dates:")
            for failed_date in failed_dates:
                print(f"  {failed_date}")
    else:
        print(
            "\nSUCCESS: Every expected date has a "
            "validated file."
        )


if __name__ == "__main__":
    main()
