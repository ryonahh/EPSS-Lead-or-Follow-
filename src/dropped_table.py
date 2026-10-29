import pandas as pd

kept = pd.read_parquet("data/clean/listed.parquet")
full = pd.read_csv("data/raw/known_exploited_vulnerabilities.csv", parse_dates=["dateAdded"])
y = full[(full.dateAdded >= "2024-01-01") & (full.dateAdded <= "2024-12-31")][["cveID"]].copy()
y["cve_year"] = y.cveID.str.extract(r"CVE-(\d{4})-")[0].astype(int)
y["kept"] = y.cveID.isin(kept.cve)
t = y.groupby(["cve_year", "kept"]).size().unstack(fill_value=0)
t = t.rename(columns={False: "dropped", True: "kept"})
print(t)
print(t.sum())
t.to_csv("results/dropped_by_year.csv")