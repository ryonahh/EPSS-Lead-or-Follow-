
import gzip
from pathlib import Path

import pandas as pd

FILE_PATH = Path("data/raw/epss_scores-2023-11-02.csv.gz")
EXPECTED_COLUMNS = {"cve", "epss", "percentile"}


def main():
    if not FILE_PATH.exists():
        raise FileNotFoundError(f"Missing file: {FILE_PATH}")

    with gzip.open(FILE_PATH, "rt", encoding="utf-8") as file:
        metadata = file.readline().strip()
        data = pd.read_csv(file)

    print("Metadata:", metadata)
    print("Columns:", list(data.columns))
    print("Rows:", len(data))

    if not EXPECTED_COLUMNS.issubset(data.columns):
        raise ValueError("Unexpected EPSS CSV columns.")

    if not data["cve"].is_unique:
        raise ValueError("Duplicate CVE IDs found.")

    if data["epss"].isna().any():
        raise ValueError("Missing EPSS scores found.")

    if not data["epss"].between(0, 1).all():
        raise ValueError("EPSS scores outside the [0, 1] range.")

    print("Validation passed.")


if __name__ == "__main__":
    main()
