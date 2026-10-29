
from datetime import date
from pathlib import Path
import gzip
import requests

TEST_DATES = [
    date(2023, 11, 2),
    date(2025, 2, 28),
]

OUTPUT_DIR = Path("data/raw/epss_test")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

for test_date in TEST_DATES:
    date_text = test_date.isoformat()
    url = f"https://epss.empiricalsecurity.com/epss_scores-{date_text}.csv.gz"

    print(f"\nTesting: {date_text}")

    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()

        output_path = OUTPUT_DIR / f"epss_scores-{date_text}.csv.gz"
        output_path.write_bytes(response.content)

        with gzip.open(output_path, "rt", encoding="utf-8") as file:
            metadata = file.readline().strip()
            header = file.readline().strip()

        print(f"HTTP status: {response.status_code}")
        print(f"File size: {output_path.stat().st_size:,} bytes")
        print(f"Metadata: {metadata}")
        print(f"Header: {header}")

        expected_metadata = (
            f"#model_version:v2023.03.01,"
            f"score_date:{date_text}T00:00:00+0000"
        )

        if metadata != expected_metadata or header != "cve,epss,percentile":
            output_path.unlink(missing_ok=True)
            print("FAILED: unexpected metadata or CSV header")
        else:
            print("PASSED: file downloaded and validated")

    except (requests.RequestException, OSError, EOFError, UnicodeDecodeError) as exc:
        print(f"FAILED: {exc}")
