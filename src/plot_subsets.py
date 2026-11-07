import sys

import matplotlib.pyplot as plt
import pandas as pd

from did import gap_curve

m = pd.read_parquet(sys.argv[1])
pairs = pd.read_csv("data/clean/pairs.csv", parse_dates=["day0"])
ex = pd.read_csv("data/exploit_first_date.csv", parse_dates=["exploit_first_date"])
ex = ex.rename(columns={"exploit_first_date": "exploit_date"})
d0 = pairs[["listed_cve", "day0"]].drop_duplicates()
d0 = d0.merge(ex[["cve", "exploit_date"]], left_on="listed_cve", right_on="cve", how="left")
had = d0[d0.exploit_date <= d0.day0].listed_cve
clean = d0[d0.exploit_date.isna() | (d0.exploit_date > d0.day0)].listed_cve

fig, ax = plt.subplots(figsize=(9, 5))
for name, keep in (
    (f"no exploit code by day 0 (n={len(clean)})", clean),
    (f"had exploit code (n={len(had)})", had),
):
    curve, se, base = gap_curve(m[m.listed_cve.isin(keep)])
    ax.plot(curve.index, curve.values, label=name)
    ax.fill_between(curve.index, curve - 1.96 * se, curve + 1.96 * se, alpha=0.2)
ax.axvline(0, linestyle="--", color="gray")
ax.axhline(0, color="gray", linewidth=0.5)
ax.set_xlabel("days from KEV listing")
ax.set_ylabel("EPSS gap vs. baseline")
ax.legend()
fig.savefig("results/gap_subsets.png", dpi=150)
print("saved results/gap_subsets.png")