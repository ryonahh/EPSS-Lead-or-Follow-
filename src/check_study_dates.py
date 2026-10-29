
from datetime import date, timedelta
import pandas as pd

KEV_FILE = "data/processed/kev_2024.csv"

def main():
    kev = pd.read_csv(KEV_FILE, parse_dates=["dateAdded"])

    first_kev = kev["dateAdded"].min().date()
    last_kev = kev["dateAdded"].max().date()

    study_start = first_kev - timedelta(days=60)
    study_end = last_kev + timedelta(days=60)

    rulebook_start = date(2023, 11, 2)
    rulebook_end = date(2025, 3, 1)

    print("2024 KEV CVEs:", len(kev))
    print("Earliest KEV listing:", first_kev)
    print("Latest KEV listing:", last_kev)
    print("Required date range from actual KEV dates:")
    print("Start:", study_start)
    print("End:", study_end)
    print("Rulebook's overall date range:")
    print("Start:", rulebook_start)
    print("End:", rulebook_end)
    print("Rulebook covers calculated range:",
          rulebook_start <= study_start and rulebook_end >= study_end)

if __name__ == "__main__":
    main()
