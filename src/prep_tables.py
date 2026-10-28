import pandas as pd

full = pd.read_csv("data/raw/known_exploited_vulnerabilities.csv")
full["dateAdded"] = pd.to_datetime(full["dateAdded"])
listed = full[(full.dateAdded >= "2024-01-01") & (full.dateAdded <= "2024-12-31")]
listed = listed.rename(columns={"cveID": "cve", "dateAdded": "day0"})[["cve", "day0"]]

nvd = pd.read_parquet("data/clean/nvd_slim.parquet")
nvd["published"] = pd.to_datetime(nvd["published"]).dt.tz_localize(None)

def band(s):
    if pd.isna(s):
        return None
    return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low"

nvd["band"] = nvd["cvss"].map(band)

L = listed.merge(nvd[["cve", "published", "band"]], on="cve", how="left")
print("listed CVEs:", len(L))
print("no NVD date or score:", int(L.published.isna().sum() + L.band.isna().sum()))
enough = L.published <= L.day0 - pd.Timedelta(days=60)
print("published too recently (<60 days before day 0):", int((~enough & L.published.notna()).sum()))
L = L[enough & L.band.notna()]
print("usable listed CVEs:", len(L))
L.to_parquet("data/clean/listed.parquet")

pool = nvd[nvd.band.notna() & ~nvd.cve.isin(full.cveID)][["cve", "published", "band"]]
print("twin pool size:", len(pool))
pool.to_parquet("data/clean/pool.parquet")