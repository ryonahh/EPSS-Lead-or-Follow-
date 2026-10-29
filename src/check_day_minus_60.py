
from pathlib import Path
import pandas as pd


KEV_FILE = Path("data/processed/kev_2024.csv")
SCORES_FILE = Path("data/processed/epss_scores_long.csv")


def main():
    kev = pd.read_csv(KEV_FILE)
    scores = pd.read_csv(SCORES_FILE)

    kev["dateAdded"] = pd.to_datetime(kev["dateAdded"]).dt.normalize()
    scores["date"] = pd.to_datetime(scores["date"]).dt.normalize()

    scores = scores[["cve", "date", "epss"]].copy()
    scores["cve"] = scores["cve"].astype(str).str.upper().str.strip()
    kev["cveID"] = kev["cveID"].astype(str).str.upper().str.strip()

    kev["day_minus_60"] = kev["dateAdded"] - pd.Timedelta(days=60)

    check = kev[["cveID", "dateAdded", "day_minus_60"]].copy()

    check = check.merge(
        scores.rename(columns={"date": "day_minus_60", "cve": "cveID"}),
        on=["cveID", "day_minus_60"],
        how="left",
        validate="one_to_one",
    )

    check["has_day_minus_60_score"] = check["epss"].notna()

    eligible_count = int(check["has_day_minus_60_score"].sum())
    excluded_count = int((~check["has_day_minus_60_score"]).sum())

    print("========== DAY -60 ELIGIBILITY ==========")
    print(f"Total 2024 KEV CVEs: {len(check)}")
    print(f"Have day -60 EPSS score: {eligible_count}")
    print(f"Missing day -60 EPSS score: {excluded_count}")

    if excluded_count:
        print("\nCVEs missing a day -60 score:")
        print(
            check.loc[
                ~check["has_day_minus_60_score"],
                ["cveID", "dateAdded", "day_minus_60"],
            ].to_string(index=False)
        )

    output = Path("data/processed/day_minus_60_eligibility.csv")
    check.to_csv(output, index=False)
    print(f"\nEligibility report saved to: {output}")


if __name__ == "__main__":
    main()
