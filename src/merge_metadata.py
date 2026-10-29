
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
PROCESSED = DATA / "processed"
PROCESSED.mkdir(parents=True, exist_ok=True)


def main():
    kev = pd.read_csv(PROCESSED / "kev_2024.csv")
    nvd = pd.read_csv(DATA / "nvd_metadata.csv")
    flags = pd.read_csv(DATA / "kev_exploit_day0_flags.csv")
    eligibility = pd.read_csv(
        PROCESSED / "day_minus_60_eligibility.csv"
    )

    # Standardize the identifier column for merging.
    kev = kev.rename(columns={"cveID": "cve"})
    eligibility = eligibility.rename(columns={"cveID": "cve"})

    # Retain the columns needed for this study.
    nvd = nvd[
        [
            "cve_id",
            "published_date",
            "cvss_score",
            "cvss_severity",
            "cvss_band",
            "fetch_status",
        ]
    ].rename(columns={"cve_id": "cve"})

    flags = flags[
        [
            "cve",
            "exploit_first_date",
            "exploit_db_id",
            "exploit_url",
        ]
    ]

    # Confirm each source has one row per CVE before merging.
    for name, df in [
        ("KEV", kev),
        ("NVD", nvd),
        ("Exploit flags", flags),
        ("Eligibility", eligibility),
    ]:
        if df["cve"].duplicated().any():
            raise ValueError(f"Duplicate CVE IDs in {name} data")

    # Left joins preserve the full KEV cohort.
    merged = kev.merge(
        nvd, on="cve", how="left", validate="one_to_one"
    )
    merged = merged.merge(
        flags, on="cve", how="left", validate="one_to_one"
    )
    merged = merged.merge(
        eligibility[
            ["cve", "day_minus_60", "epss", "has_day_minus_60_score"]
        ],
        on="cve",
        how="left",
        validate="one_to_one",
    )

    merged["kev_date_added"] = pd.to_datetime(
        merged["dateAdded"], errors="coerce"
    )
    merged["exploit_first_date"] = pd.to_datetime(
        merged["exploit_first_date"], errors="coerce"
    )

    merged["days_exploit_from_kev"] = (
        merged["exploit_first_date"] - merged["kev_date_added"]
    ).dt.days

    days = merged["days_exploit_from_kev"]

    merged["exploit_timing_category"] = "No recorded Exploit-DB date"
    merged.loc[days < 0, "exploit_timing_category"] = "Before day 0"
    merged.loc[days == 0, "exploit_timing_category"] = "On day 0"
    merged.loc[
        days.between(1, 7),
        "exploit_timing_category",
    ] = "1-7 days after day 0 (buffer)"
    merged.loc[
        days > 7,
        "exploit_timing_category",
    ] = "More than 7 days after day 0"

    # Validate cohort size and baseline eligibility.
    if len(merged) != 186:
        raise ValueError(f"Expected 186 KEV CVEs, got {len(merged)}")

    if merged["cve"].nunique() != 186:
        raise ValueError("Merged data contains duplicate or missing CVE IDs")

    eligible = (
        merged["has_day_minus_60_score"]
        .astype(str)
        .str.lower()
        .eq("true")
    )
    if eligible.sum() != 77:
        raise ValueError(
            f"Expected 77 baseline-eligible CVEs, got {eligible.sum()}"
        )

    output = PROCESSED / "kev_nvd_exploit_merged.csv"
    merged.to_csv(output, index=False)

    print("Merged metadata created:", output)
    print("Rows:", len(merged))
    print("Unique CVEs:", merged["cve"].nunique())
    print("Baseline-eligible CVEs:", eligible.sum())
    print("\nExploit timing categories:")
    print(merged["exploit_timing_category"].value_counts().to_string())
    print("\nMissing publication dates:", merged["published_date"].isna().sum())
    print("Missing CVSS bands:", merged["cvss_band"].isna().sum())


if __name__ == "__main__":
    main()
