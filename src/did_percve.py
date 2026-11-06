import sys

import matplotlib.pyplot as plt
import pandas as pd

m = pd.read_parquet(sys.argv[1])
L = m[m.group == "listed"].set_index(["listed_cve", "rel_day"]).epss
T = m[m.group == "twin"].groupby(["listed_cve", "rel_day"]).epss.mean()
gap = (L - T).dropna().unstack("rel_day")
base = gap.loc[:, -60:-31].mean(axis=1)
did = gap.sub(base, axis=0)
mean, se = did.mean(), did.sem()


def ci(x):
    return x.mean() - 1.96 * x.sem(), x.mean() + 1.96 * x.sem()


pre = did.loc[:, -19:-1].mean(axis=1)
post = did.loc[:, 1:7].mean(axis=1)
print("listed CVEs:", len(did))
print(f"2 x baseline noise (the old threshold): {2 * mean.loc[-60:-31].std():.4f}")
print(f"avg gap days -19..-1: {pre.mean():.4f}  95% CI {ci(pre)[0]:.4f} to {ci(pre)[1]:.4f}")
print(f"median gap days -19..-1: {pre.median():.4f} | share of CVEs with a positive gap: {(pre > 0).mean():.2f}")
print(f"avg gap days +1..+7:  {post.mean():.4f}  95% CI {ci(post)[0]:.4f} to {ci(post)[1]:.4f}")

plt.plot(mean.index, mean.values)
plt.fill_between(mean.index, mean - 1.96 * se, mean + 1.96 * se, alpha=0.2)
plt.axvline(0, linestyle="--", color="gray")
plt.axhline(0, color="gray", linewidth=0.5)
plt.xlabel("days from KEV listing")
plt.ylabel("EPSS gap vs. own baseline")
plt.savefig("results/gap_percve.png", dpi=150)
print("saved results/gap_percve.png")