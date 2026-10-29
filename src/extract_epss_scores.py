
from datetime import date, timedelta
from pathlib import Path
import csv
import gzip

import pandas as pd


START_DATE = date(2023, 11, 2)
END_DATE = date(2025, 3, 1)

KEV_FILE = Path("data/processed/kev_2024.csv")
EPSS_DIR = Path("data/raw/epss_daily")
OUTPUT_FILE = Path("data/processed/epss_scores_long.csv")
MISSING_FILE = Path("data/processed/epss_missing_dates.csv")

EXPECTED_MODEL = "v2023.03.01"


def read_kev_cves():
    if not KEV_FILE.exists():
        raise FileNotFoundError(
            f"Missing {KEV_FILE}. Run the KEV filtering script first."
        )

    kev = pd.read_csv(KEV_FILE)

    if "cveID" not in kev.columns:
        raise ValueError(
            f"Expected 'cveID' column in {KEV_FILE}; "
            f"found: {list(kev.columns)}"
        )

    cves = set(
        kev["cveID"]
        .dropna()
        .astype(str)
        .str.strip()
        .str.upper()
    )

    if not cves:
        raise ValueError("No CVEs found in the 2024 KEV file.")

    return cves


def read_daily_file(path, expected_date, target_cves):
    with gzip.open(path, "rt", encoding="utf-8") as file:
        metadata = file.readline().strip()

        expected_metadata = (
            f"#model_version:{EXPECTED_MODEL},"
            f"score_date:{expected_date.isoformat()}T00:00:00+0000"
        )

        if metadata != expected_metadata:
            raise ValueError(
                f"{path.name}: unexpected metadata: {metadata}"
            )

        # The next line is the CSV header, so rewind to let pandas
        # read it as the header rather than treating it as data.
        file.seek(0)
        daily = pd.read_csv(file, skiprows=1)

    required_columns = {"cve", "epss", "percentile"}
    if not required_columns.issubset(daily.columns):
        raise ValueError(
            f"{path.name}: missing required columns: "
            f"{required_columns - set(daily.columns)}"
        )

    daily["cve"] = daily["cve"].astype(str).str.strip().str.upper()
    daily["epss"] = pd.to_numeric(daily["epss"], errors="raise")
    daily["percentile"] = pd.to_numeric(
        daily["percentile"], errors="raise"
    )

    if daily["cve"].duplicated().any():
        raise ValueError(f"{path.name}: duplicate CVE rows found.")

    if daily["epss"].isna().any():
        raise ValueError(f"{path.name}: null EPSS scores found.")

    if not daily["epss"].between(0, 1).all():
        raise ValueError(f"{path.name}: EPSS scores outside [0, 1].")

    matched = daily[daily["cve"].isin(target_cves)].copy()
    matched["date"] = expected_date.isoformat()

    return matched[["date", "cve", "epss", "percentile"]]


def main():
    target_cves = read_kev_cves()
    print(f"2024 KEV cohort CVEs: {len(target_cves)}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    extracted = []
    missing_dates = []
    current = START_DATE
    expected_total = (END_DATE - START_DATE).days + 1

    while current <= END_DATE:
        date_text = current.isoformat()
        path = EPSS_DIR / f"epss_scores-{date_text}.csv.gz"

        if not path.exists():
            missing_dates.append({
                "date": date_text,
                "reason": "daily_file_unavailable",
            })
            current += timedelta(days=1)
            continue

        daily = read_daily_file(path, current, target_cves)
        extracted.append(daily)

        print(
            f"{date_text}: matched {len(daily)} "
            f"of {len(target_cves)} study CVEs"
        )

        current += timedelta(days=1)

    if extracted:
        result = pd.concat(extracted, ignore_index=True)
    else:
        result = pd.DataFrame(
            columns=["date", "cve", "epss", "percentile"]
        )

    result.to_csv(OUTPUT_FILE, index=False)

    with MISSING_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=["date", "reason"]
        )
        writer.writeheader()
        writer.writerows(missing_dates)

    print("\n========== EXTRACTION SUMMARY ==========")
    print(f"Study CVEs: {len(target_cves)}")
    print(f"Expected daily snapshots: {expected_total}")
    print(f"Missing snapshots: {len(missing_dates)}")
    print(f"Extracted score rows: {len(result)}")
    print(f"Unique CVEs in extracted data: {result['cve'].nunique()}")
    print(f"Scores saved to: {OUTPUT_FILE}")
    print(f"Missing-date log saved to: {MISSING_FILE}")

    if missing_dates:
        print("Missing dates:")
        for item in missing_dates:
            print(f"  {item['date']}: {item['reason']}")


if __name__ == "__main__":
    main()
