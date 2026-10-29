
from pathlib import Path

import pandas as pd

INPUT_FILE = Path("data/raw/known_exploited_vulnerabilities.csv")
OUTPUT_FILE = Path("data/processed/kev_2024.csv")

def main():
    kev = pd.read_csv(INPUT_FILE, parse_dates=["dateAdded"])

    required_columns = {"cveID", "dateAdded"}
    missing = required_columns - set(kev.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    kev_2024 = kev.loc[
        kev["dateAdded"].between("2024-01-01", "2024-12-31")
    ].copy()

    if kev_2024["cveID"].duplicated().any():
        raise ValueError("Duplicate CVE IDs found in 2024 KEV subset.")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    kev_2024.to_csv(OUTPUT_FILE, index=False)

    print(f"Total catalog entries: {len(kev)}")
    print(f"2024 KEV entries: {len(kev_2024)}")
    print(f"Unique 2024 CVEs: {kev_2024['cveID'].nunique()}")
    print(f"Date range: {kev_2024['dateAdded'].min()} to "
          f"{kev_2024['dateAdded'].max()}")
    print(f"Saved: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
