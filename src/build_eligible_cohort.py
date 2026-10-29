
from pathlib import Path
import pandas as pd


KEV_FILE = Path("data/processed/kev_2024.csv")
ELIGIBILITY_FILE = Path("data/processed/day_minus_60_eligibility.csv")

ELIGIBLE_FILE = Path("data/processed/eligible_kev_2024.csv")
EXCLUDED_FILE = Path("data/processed/excluded_kev_2024.csv")


def main():
    kev = pd.read_csv(KEV_FILE)
    eligibility = pd.read_csv(ELIGIBILITY_FILE)

    if "cveID" not in kev.columns:
        raise ValueError("KEV file is missing the cveID column.")

    required = {"cveID", "has_day_minus_60_score"}
    if not required.issubset(eligibility.columns):
        raise ValueError(
            f"Eligibility file must contain: {sorted(required)}"
        )

    kev["cveID"] = kev["cveID"].astype(str).str.strip().str.upper()
    eligibility["cveID"] = (
        eligibility["cveID"].astype(str).str.strip().str.upper()
    )

    if kev["cveID"].duplicated().any():
        raise ValueError("Duplicate CVEs found in the KEV cohort.")

    if eligibility["cveID"].duplicated().any():
        raise ValueError("Duplicate CVEs found in the eligibility report.")

    merged = kev.merge(
        eligibility[["cveID", "has_day_minus_60_score"]],
        on="cveID",
        how="left",
        validate="one_to_one",
        indicator=True,
    )

    if (merged["_merge"] != "both").any():
        raise ValueError(
            "Some KEV CVEs do not have an eligibility result."
        )

    merged["has_day_minus_60_score"] = (
        merged["has_day_minus_60_score"].astype(bool)
    )

    eligible = merged[merged["has_day_minus_60_score"]].drop(
        columns=["has_day_minus_60_score", "_merge"]
    )

    excluded = merged[~merged["has_day_minus_60_score"]].drop(
        columns=["_merge"]
    )

    eligible.to_csv(ELIGIBLE_FILE, index=False)
    excluded.to_csv(EXCLUDED_FILE, index=False)

    print("========== ELIGIBLE COHORT ==========")
    print(f"Original cohort: {len(merged)}")
    print(f"Eligible CVEs: {len(eligible)}")
    print(f"Excluded CVEs: {len(excluded)}")
    print(f"Eligible cohort saved to: {ELIGIBLE_FILE}")
    print(f"Exclusion report saved to: {EXCLUDED_FILE}")


if __name__ == "__main__":
    main()
