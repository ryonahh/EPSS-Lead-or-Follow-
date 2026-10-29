import pandas as pd

# KEV catalog: the 2024 listings are your "listed" CVEs, with day 0 = dateAdded
full = pd.read_csv("data/raw/known_exploited_vulnerabilities.csv")
full["dateAdded"] = pd.to_datetime(full["dateAdded"])
k = full[(full.dateAdded >= "2024-01-01") & (full.dateAdded <= "2024-12-31")]
k = k.rename(columns={"cveID": "cve", "dateAdded": "day0"})[["cve", "day0"]]


def band(s):
    if pd.isna(s):
        return None
    return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low"


# B's NVD file: publish date and CVSS score for the 186 listed CVEs
meta = pd.read_csv("data/nvd_metadata.csv")
meta = meta.rename(columns={"cve_id": "cve", "published_date": "published", "cvss_score": "cvss"})
meta["published"] = pd.to_datetime(meta["published"]).dt.tz_localize(None)

L = k.merge(meta[["cve", "published", "cvss"]], on="cve", how="left")
L["band"] = L.cvss.map(band)
print("listed CVEs:", len(L))
print("no NVD date or score:", int(L.published.isna().sum() + L.band.isna().sum()))
enough = L.published <= L.day0 - pd.Timedelta(days=60)
print("published too recently (<60 days before day 0):", int((~enough & L.published.notna()).sum()))
L = L[enough & L.band.notna()]
print("usable listed CVEs:", len(L))
L.to_parquet("data/clean/listed.parquet")

# Twin pool: everything fetched by get_pool.py that was never KEV-listed
pool = pd.read_parquet("data/clean/nvd_pool.parquet")
pool["band"] = pool.cvss.map(band)
pool = pool[pool.band.notna() & ~pool.cve.isin(full.cveID)][["cve", "published", "band"]]
print("twin pool size:", len(pool))
pool.to_parquet("data/clean/pool.parquet")