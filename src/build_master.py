import glob
import sys

import pandas as pd

pairs = pd.read_csv(sys.argv[1], parse_dates=["day0"])
out = sys.argv[2]

listed = pairs[["listed_cve", "day0"]].drop_duplicates()
listed = listed.assign(cve=listed.listed_cve, group="listed")
twins = pairs.rename(columns={"twin_cve": "cve"}).assign(group="twin")
members = pd.concat([listed, twins[["listed_cve", "day0", "cve", "group"]]])
need = set(members.cve)

frames = []
for f in sorted(glob.glob("data/raw/epss/epss_scores-*.csv.gz")):
    d = pd.Timestamp(f.split("epss_scores-")[1][:10])
    df = pd.read_csv(f, comment="#", usecols=["cve", "epss"])
    df = df[df.cve.isin(need)]
    df["date"] = d
    frames.append(df)
epss = pd.concat(frames)

m = members.merge(epss, on="cve")
m["rel_day"] = (m.date - m.day0).dt.days
m = m[(m.rel_day >= -60) & (m.rel_day <= 60)]

cov = m.groupby("cve").rel_day.nunique() / 121
print("CVEs with EPSS data:", m.cve.nunique(), "of", len(need))
print("mean day-coverage:", round(cov.mean(), 3), "| CVEs under 90%:", int((cov < 0.9).sum()))
print("listed CVEs with data:", m[m.group == "listed"].cve.nunique())
m[["listed_cve", "cve", "group", "rel_day", "epss"]].to_parquet(out)