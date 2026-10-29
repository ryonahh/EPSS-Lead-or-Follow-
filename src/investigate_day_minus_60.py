
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

kev_file = ROOT / "data" / "processed" / "kev_2024.csv"
scores_file = ROOT / "data" / "processed" / "epss_scores_long.csv"

kev = pd.read_csv(kev_file)
scores = pd.read_csv(scores_file)

# Standardize CVE identifiers and dates.
kev["cveID"] = kev["cveID"].astype(str).str.strip().str.upper()
kev["dateAdded"] = pd.to_datetime(kev["dateAdded"], errors="coerce")

scores["cve"] = scores["cve"].astype(str).str.strip().str.upper()
scores["date"] = pd.to_datetime(scores["date"], errors="coerce")

# Calculate the exact day -60 for every KEV-listed CVE.
kev["day_minus_60"] = kev["dateAdded"] - pd.Timedelta(days=60)

# Find the first date each CVE appears in our extracted EPSS history.
first_scores = (
    scores.dropna(subset=["date"])
    .groupby("cve", as_index=False)["date"]
    .min()
    .rename(columns={"cve": "cveID", "date": "first_epss_date"})
)

report = kev.merge(first_scores, on="cveID", how="left")

# Check whether a score exists on the exact day -60.
day_minus_60_scores = scores.merge(
    kev[["cveID", "day_minus_60"]],
    left_on="cve",
    right_on="cveID",
    how="inner"
)

day_minus_60_scores = day_minus_60_scores[
    day_minus_60_scores["date"] == day_minus_60_scores["day_minus_60"]
]

eligible_cves = set(day_minus_60_scores["cveID"])
report["has_score_day_minus_60"] = report["cveID"].isin(eligible_cves)

# Measure when the first observed score appeared relative to day -60.
report["days_after_day_minus_60"] = (
    report["first_epss_date"] - report["day_minus_60"]
).dt.days

# Keep the 109 CVEs missing their day -60 score.
missing = report[~report["has_score_day_minus_60"]].copy()

columns = [
    "cveID",
    "dateAdded",
    "day_minus_60",
    "first_epss_date",
    "days_after_day_minus_60",
]

missing[columns].sort_values(
    ["first_epss_date", "cveID"],
    na_position="last"
).to_csv(
    ROOT / "data" / "processed" / "day_minus_60_investigation.csv",
    index=False
)

print("Total KEV CVEs:", len(report))
print("Have score on day -60:", int(report["has_score_day_minus_60"].sum()))
print("Missing score on day -60:", len(missing))
print("\nFirst score timing among the missing CVEs:")
print(
    missing["days_after_day_minus_60"]
    .value_counts(dropna=False)
    .sort_index()
    .to_string()
)
print("\nSaved detailed report to:")
print(ROOT / "data" / "processed" / "day_minus_60_investigation.csv")
