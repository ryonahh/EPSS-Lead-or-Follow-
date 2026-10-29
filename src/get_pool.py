import os, time, pathlib, requests, pandas as pd

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
key = os.environ.get("NVD_API_KEY")
headers = {"apiKey": key} if key else {}
pause = 0.7 if key else 6.5
PAGE = 1000

OUT = pathlib.Path("data/raw/pool_chunks")
OUT.mkdir(parents=True, exist_ok=True)

meta = pd.read_csv("data/nvd_metadata.csv")
meta["published"] = pd.to_datetime(meta["published_date"]).dt.tz_localize(None)
kev = pd.read_csv("data/raw/known_exploited_vulnerabilities.csv", parse_dates=["dateAdded"])
kev = kev.rename(columns={"cveID": "cve_id", "dateAdded": "day0"})[["cve_id", "day0"]]

L = meta.merge(kev, on="cve_id")
L = L[L.published <= L.day0 - pd.Timedelta(days=60)]
print("listed CVEs needing a pool:", len(L))

# +-30 day window around each publish date, merged, cut into chunks under 120 days
iv = sorted((p - pd.Timedelta(days=30), p + pd.Timedelta(days=30)) for p in L.published)
merged = []
for s, e in iv:
    if merged and s <= merged[-1][1]:
        merged[-1][1] = max(merged[-1][1], e)
    else:
        merged.append([s, e])
chunks = []
for s, e in merged:
    while s < e:
        c = min(s + pd.Timedelta(days=100), e)
        chunks.append((s, c))
        s = c
print("date chunks to fetch:", len(chunks))


def fetch(params):
    for attempt in range(8):
        try:
            r = requests.get(URL, params=params, headers=headers, timeout=120)
            if r.status_code == 200:
                return r.json()
            print("status", r.status_code, "- retrying", flush=True)
        except (requests.exceptions.RequestException, ValueError) as e:
            print("network error:", type(e).__name__, "- retrying", flush=True)
        time.sleep(5 * (attempt + 1))
    raise SystemExit("gave up on " + params["pubStartDate"] + " index " + str(params["startIndex"]))


for i, (s, e) in enumerate(chunks):
    f = OUT / f"chunk_{i:03d}.parquet"
    if f.exists():
        continue
    rows, start = [], 0
    while True:
        params = {
            "pubStartDate": s.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": e.strftime("%Y-%m-%dT23:59:59.999"),
            "startIndex": start,
            "resultsPerPage": PAGE,
        }
        j = fetch(params)
        for v in j["vulnerabilities"]:
            c = v["cve"]
            m = c.get("metrics", {})
            score = None
            for k in ("cvssMetricV31", "cvssMetricV30"):
                if k in m:
                    score = m[k][0]["cvssData"]["baseScore"]
                    break
            rows.append((c["id"], c["published"], score))
        start += PAGE
        total = j["totalResults"]
        print(f"chunk {i + 1}/{len(chunks)}  {s.date()}  {min(start, total)} / {total}", flush=True)
        time.sleep(pause)
        if start >= total:
            break
    part = pd.DataFrame(rows, columns=["cve", "published", "cvss"])
    part["cvss"] = pd.to_numeric(part["cvss"], errors="coerce")
    part.to_parquet(f)

df = pd.concat([pd.read_parquet(p) for p in sorted(OUT.glob("chunk_*.parquet"))])
df = df.drop_duplicates("cve")
df["published"] = pd.to_datetime(df["published"]).dt.tz_localize(None)
df.to_parquet("data/clean/nvd_pool.parquet")
print("saved", len(df), "CVEs to data/clean/nvd_pool.parquet")