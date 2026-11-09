
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

SCORES_FILE = ROOT / "data" / "processed" / "epss_scores_long.csv"
ELIGIBILITY_FILE = ROOT / "data" / "processed" / "day_minus_60_eligibility.csv"

OUTPUT_DIR = ROOT / "data" / "processed"
DETAILS_FILE = OUTPUT_DIR / "threshold_crossings_detail.csv"
SUMMARY_FILE = OUTPUT_DIR / "threshold_crossings_summary.csv"

# EPSS values are probabilities between 0 and 1.
THRESHOLDS = {
    "1_percent": 0.01,
    "10_percent": 0.10,
    "50_percent": 0.50,
}


def main():
    scores = pd.read_csv(SCORES_FILE)
    eligibility = pd.read_csv(ELIGIBILITY_FILE)

    scores["date"] = pd.to_datetime(scores["date"], errors="coerce")
    scores["cve"] = scores["cve"].astype(str).str.strip().str.upper()
    scores["epss"] = pd.to_numeric(scores["epss"], errors="coerce")

    eligibility["cveID"] = (
        eligibility["cveID"].astype(str).str.strip().str.upper()
    )
    eligibility["dateAdded"] = pd.to_datetime(
        eligibility["dateAdded"], errors="coerce"
    )
    eligibility["day_minus_60"] = pd.to_datetime(
        eligibility["day_minus_60"], errors="coerce"
    )

    # Keep only CVEs with a score on day -60.
    eligible = eligibility[
        eligibility["has_day_minus_60_score"].astype(str).str.lower()
        .isin(["true", "1"])
    ].copy()

    if eligible.empty:
        raise ValueError("No eligible CVEs found in the eligibility file.")

    eligible_ids = set(eligible["cveID"])

    # Restrict score data to the eligible CVEs and their event windows.
    scores = scores[scores["cve"].isin(eligible_ids)].copy()

    scores = scores.merge(
        eligible[["cveID", "dateAdded", "day_minus_60"]],
        left_on="cve",
        right_on="cveID",
        how="inner",
    )

    # Day 0 is the KEV listing date. Pre-event means strictly before day 0.
    scores = scores[
        (scores["date"] >= scores["day_minus_60"])
        & (scores["date"] < scores["dateAdded"])
    ].copy()

    scores = scores.sort_values(["cve", "date"])

    details = []

    for cve_id, group in scores.groupby("cve"):
        group = group.sort_values("date").copy()
        event_date = group["dateAdded"].iloc[0]
        baseline_date = group["day_minus_60"].iloc[0]

        for threshold_name, threshold_value in THRESHOLDS.items():
            group["at_or_above"] = group["epss"] >= threshold_value

            # First observed date reaching or exceeding the threshold.
            reached = group[group["at_or_above"]]
            first_reached_date = (
                reached["date"].iloc[0] if not reached.empty else pd.NaT
            )

            # An upward crossing requires the previous observed score
            # to be below the threshold and the current score to reach it.
            previous_score = group["epss"].shift(1)
            upward_crossing = group[
                (previous_score < threshold_value)
                & (group["epss"] >= threshold_value)
            ]

            first_upward_date = (
                upward_crossing["date"].iloc[0]
                if not upward_crossing.empty
                else pd.NaT
            )

            baseline_rows = group[group["date"] == baseline_date]
            baseline_score = (
                baseline_rows["epss"].iloc[0]
                if not baseline_rows.empty
                else float("nan")
            )
            already_above_at_baseline = (
                pd.notna(baseline_score)
                and baseline_score >= threshold_value
            )

            details.append({
                "cveID": cve_id,
                "kev_date": event_date.date(),
                "day_minus_60": baseline_date.date(),
                "threshold": threshold_name,
                "threshold_value": threshold_value,
                "baseline_epss": baseline_score,
                "already_at_or_above_at_day_minus_60":
                    already_above_at_baseline,
                "first_reached_date_before_day0": first_reached_date,
                "days_before_kev_when_first_reached": (
                    (event_date - first_reached_date).days
                    if pd.notna(first_reached_date)
                    else None
                ),
                "first_upward_crossing_date_before_day0": first_upward_date,
                "days_before_kev_when_crossed_upward": (
                    (event_date - first_upward_date).days
                    if pd.notna(first_upward_date)
                    else None
                ),
                "reached_before_day0": pd.notna(first_reached_date),
                "crossed_upward_before_day0": pd.notna(first_upward_date),
            })

    detail_df = pd.DataFrame(details)
    detail_df.to_csv(DETAILS_FILE, index=False)

    summary = (
        detail_df.groupby("threshold", sort=False)
        .agg(
            eligible_cves=("cveID", "nunique"),
            reached_before_day0=("reached_before_day0", "sum"),
            crossed_upward_before_day0=("crossed_upward_before_day0", "sum"),
            already_above_at_baseline=(
                "already_at_or_above_at_day_minus_60", "sum"
            ),
        )
        .reset_index()
    )

    summary["reached_percent"] = (
        summary["reached_before_day0"] / summary["eligible_cves"] * 100
    ).round(2)

    summary["crossed_upward_percent"] = (
        summary["crossed_upward_before_day0"]
        / summary["eligible_cves"] * 100
    ).round(2)

    summary.to_csv(SUMMARY_FILE, index=False)

    print("\n--- Threshold-crossing summary ---")
    print(summary.to_string(index=False))
    print("\nDetailed results saved to:", DETAILS_FILE)
    print("Summary saved to:", SUMMARY_FILE)
    print("\nNote: counts use observed scores before day 0.")
    print("The missing 2024-12-01 snapshot is not imputed in this analysis.")


if __name__ == "__main__":
    main()
