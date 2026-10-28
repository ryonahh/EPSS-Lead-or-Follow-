import time, pathlib, datetime as dt, requests

OUT = pathlib.Path("data/raw/epss")
OUT.mkdir(parents=True, exist_ok=True)
d, end = dt.date(2023, 11, 2), dt.date(2025, 3, 1)

while d <= end:
    f = OUT / f"epss_scores-{d}.csv.gz"
    if not f.exists():
        url = f"https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
        for attempt in range(3):
            r = requests.get(url, timeout=60)
            if r.status_code == 200:
                f.write_bytes(r.content)
                break
            time.sleep(2)
        else:
            print("FAILED", d)
    d += dt.timedelta(days=1)
print("done")