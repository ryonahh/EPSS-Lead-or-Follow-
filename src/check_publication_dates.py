
from pathlib import Path
import time

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parents[1]

INPUT_FILE = (
    ROOT / "data" / "processed" / "day_minus_60_investigation.csv"
)
OUTPUT_FILE = (
    ROOT / "data" / "processed" / "publication_date_check.csv"
)

# This input file already contains the 109 CVEs missing a day -60 score.
df = pd.read_csv(INPUT_FILE)

df["cveID"] = df["cveID"].astype(str).str.strip().str.upper()
df["dateAdded"] = pd.to_datetime(df["dateAdded"], errors="coerce")
df["day_minus_60"] = pd.to_datetime(
    df["day_minus_60"], errors="coerce"
)
df["first_epss_date"] = pd.to_datetime(
    df["first_epss_date"], errors="coerce"
)

print("CVEs to investigate:", len(df))

session = requests.Session()
session.headers.update({
    "User-Agent": "EPSS-Lead-or-Follow-Research/1.0"
})

results = []

for i, row in enumerate(df.to_dict("records"), start=1):
    cve = row["cveID"]
    url = f"https://cveawg.mitre.org/api/cve/{cve}"

    published = None
    status = "unknown"

    try:
        response = session.get(url, timeout=20)

        if response.status_code == 200:
            record = response.json()
            metadata = record.get("cveMetadata", {})
            status = metadata.get("state", "unknown")

            published = metadata.get("datePublished")

            if not published:
                published = (
                    record.get("containers", {})
                    .get("cna", {})
                    .get("datePublished")
                )

        else:
            status = f"http_{response.status_code}"

    except requests.RequestException as exc:
        status = f"request_error: {type(exc).__name__}"

    results.append({
        "cveID": cve,
        "kev_date": row["dateAdded"],
        "day_minus_60": row["day_minus_60"],
        "first_epss_date": row["first_epss_date"],
        "cve_publication_date": published,
        "cve_record_status": status,
    })

    if i % 10 == 0 or i == len(df):
        print(f"Checked {i}/{len(df)} CVEs")

    time.sleep(0.15)

result_df = pd.DataFrame(results)

# Normalize dates for consistent day-difference calculations.
for column in [
    "kev_date",
    "day_minus_60",
    "first_epss_date",
]:
    result_df[column] = pd.to_datetime(
        result_df[column], errors="coerce", utc=True
    )

result_df["cve_publication_date"] = pd.to_datetime(
    result_df["cve_publication_date"],
    errors="coerce",
    utc=True,
)

# Calculate how long after publication each event occurred.
result_df["days_publication_to_kev"] = (
    result_df["kev_date"] - result_df["cve_publication_date"]
).dt.days

result_df["days_publication_to_day_minus_60"] = (
    result_df["day_minus_60"]
    - result_df["cve_publication_date"]
).dt.days

result_df.to_csv(OUTPUT_FILE, index=False)

print("\n--- Investigation summary ---")
print("CVEs investigated:", len(result_df))
print(
    "Publication dates found:",
    int(result_df["cve_publication_date"].notna().sum()),
)
print(
    "Publication dates missing:",
    int(result_df["cve_publication_date"].isna().sum()),
)

print("\nDays from CVE publication to KEV listing:")
print(result_df["days_publication_to_kev"].describe())

print("\nPublication timing relative to day -60:")
print(
    "Published after day -60:",
    int((result_df["days_publication_to_day_minus_60"] < 0).sum()),
)
print(
    "Published on day -60:",
    int((result_df["days_publication_to_day_minus_60"] == 0).sum()),
)
print(
    "Published before day -60:",
    int((result_df["days_publication_to_day_minus_60"] > 0).sum()),
)

print("\nSaved report to:")
print(OUTPUT_FILE)
