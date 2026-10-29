
from pathlib import Path
import gzip

import pandas as pd


KEV_FILE = Path("data/processed/kev_2024.csv")
EPSS_DIR = Path("data/raw/epss_daily")


def main():
    kev = pd.read_csv(KEV_FILE)
    kev["dateAdded"] = pd.to_datetime(kev["dateAdded"]).dt.normalize()
    kev["cveID"] = kev["cveID"].astype(str).str.strip().str.upper()

    results = []

    for _, row in kev.iterrows():
        cve = row["cveID"]
        day_minus_60 = (
            row["dateAdded"] - pd.Timedelta(days=60)
        ).date()

        date_text = day_minus_60.isoformat()
        path = EPSS_DIR / f"epss_scores-{date_text}.csv.gz"

        file_present = path.exists()
        score_present = False

        if file_present:
            with gzip.open(path, "rt", encoding="utf-8") as file:
                metadata = file.readline().strip()

                expected_metadata = (
                    "#model_version:v2023.03.01,"
                    f"score_date:{date_text}T00:00:00+0000"
                )

                if metadata != expected_metadata:
                    raise ValueError(
                        f"Unexpected metadata in {path.name}: {metadata}"
                    )

                daily = pd.read_csv(file, usecols=["cve"])

            daily["cve"] = daily["cve"].astype(str).str.strip().str.upper()
            score_present = daily["cve"].eq(cve).any()

        results.append({
            "cve": cve,
            "day_minus_60": date_text,
            "file_present": file_present,
            "score_present": score_present,
        })

    output = pd.DataFrame(results)
    output_path = Path("data/processed/day_minus_60_source_check.csv")
    output.to_csv(output_path, index=False)

    print("========== SOURCE CHECK ==========")
    print(f"Total CVEs: {len(output)}")
    print(f"Snapshot files missing: {(~output['file_present']).sum()}")
    print(f"Scores present: {output['score_present'].sum()}")
    print(
        "Scores absent from existing snapshots: "
        f"{((~output['score_present']) & output['file_present']).sum()}"
    )
    print(f"Report saved to: {output_path}")

    print("\nFirst 15 CVEs with absent scores or files:")
    missing = output[
        (~output["score_present"]) | (~output["file_present"])
    ]
    print(missing.head(15).to_string(index=False))


if __name__ == "__main__":
    main()
