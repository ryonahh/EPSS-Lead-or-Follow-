import sys

import pandas as pd

m = pd.read_parquet(sys.argv[1])
pairs = pd.read_csv("data/clean/pairs.csv", parse_dates=["day0"])
ex = pd.read_csv("data/exploit_first_date.csv", parse_dates=["exploit_first_date"])
ex = ex.rename(columns={"exploit_first_date": "exploit_date"})
d0 = pairs[["listed_cve", "day0"]].drop_duplicates()
d0 = d0.merge(ex[["cve", "exploit_date"]], left_on="listed_cve", right_on="cve", how="left")

L = m[m.group == "listed"].set_index(["listed_cve", "rel_day"]).epss
T = m[m.group == "twin"].groupby(["listed_cve", "rel_day"]).epss.mean()
gap = (L - T).dropna().unstack("rel_day")
did = gap.sub(gap.loc[:, -60:-31].mean(axis=1), axis=0)
pre = did.loc[:, -19:-1].mean(axis=1)


def fmt(x):
    if len(x) < 2:
        return "n<2"
    return f"{x.mean():.4f} [{x.mean() - 1.96 * x.sem():.4f}, {x.mean() + 1.96 * x.sem():.4f}]"


print("buffer_days | group | n | avg gap days -19..-1 [95% CI]")
for b in (3, 7, 14):
    cutoff = d0.day0 - pd.Timedelta(days=b)
    clean = d0[d0.exploit_date.isna() | (d0.exploit_date > cutoff)].listed_cve
    had = d0[d0.exploit_date <= cutoff].listed_cve
    for name, keep in (("no exploit seen", clean), ("exploit seen", had)):
        x = pre[pre.index.isin(keep)]
        print(b, name, len(x), fmt(x))