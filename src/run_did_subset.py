import sys

import pandas as pd

from did import gap_curve, lead_time

m = pd.read_parquet(sys.argv[1])
pairs = pd.read_csv("data/clean/pairs.csv", parse_dates=["day0"])
ex = pd.read_csv("data/exploit_first_date.csv", parse_dates=["exploit_first_date"])
ex = ex.rename(columns={"exploit_first_date": "exploit_date"})

d0 = pairs[["listed_cve", "day0"]].drop_duplicates()
d0 = d0.merge(ex[["cve", "exploit_date"]], left_on="listed_cve", right_on="cve", how="left")
clean = d0[d0.exploit_date.isna() | (d0.exploit_date > d0.day0)].listed_cve
had = d0[d0.exploit_date <= d0.day0].listed_cve
print("no exploit code by day 0:", len(clean), "| had exploit code:", len(had))

for name, keep in (("no exploit code by day 0", clean), ("had exploit code", had)):
    sub = m[m.listed_cve.isin(keep)]
    curve, se, base = gap_curve(sub)
    print(name, "-> lead time:", lead_time(curve, base))