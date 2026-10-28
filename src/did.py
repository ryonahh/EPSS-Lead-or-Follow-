import numpy as np
import pandas as pd


def gap_curve(master):
    """master columns: listed_cve, cve, group ('listed'/'twin'), rel_day, epss"""
    L = master[master.group == "listed"].set_index(["listed_cve", "rel_day"]).epss
    T = master[master.group == "twin"].groupby(["listed_cve", "rel_day"]).epss.mean()
    gap = (L - T).dropna()                      # listed minus its twins' average
    curve = gap.groupby("rel_day").mean()       # average over all listed CVEs
    se = gap.groupby("rel_day").sem()
    base = curve.loc[-60:-31]                   # baseline window
    return curve - base.mean(), se, base        # DiD: gap change vs. baseline


def lead_time(curve, base, k=2, run=3):
    """Days before day 0 when the gap first stays above k*baseline-noise for `run` days."""
    thr = k * base.std()
    above = (curve.loc[-30:-1] > thr).astype(int)
    streak = above.rolling(run).sum() == run
    hits = streak[streak].index
    if len(hits) == 0:
        return None
    return -(int(hits[0]) - (run - 1))


def fake_master(n_listed=30, n_twins=5, seed=1):
    rng = np.random.default_rng(seed)
    days = np.arange(-60, 61)
    rows = []
    for i in range(n_listed):
        lc = f"L{i}"
        bump = np.where(days > -10, 0.01 * (days + 10), 0)   # planted rise from day -9
        for d, b in zip(days, bump):
            rows.append((lc, lc, "listed", d, max(0, 0.02 + b + rng.normal(0, 0.003))))
        for j in range(n_twins):
            for d in days:
                rows.append((lc, f"T{i}_{j}", "twin", d, max(0, 0.02 + rng.normal(0, 0.003))))
    return pd.DataFrame(rows, columns=["listed_cve", "cve", "group", "rel_day", "epss"])


if __name__ == "__main__":
    import matplotlib.pyplot as plt
    m = fake_master()
    curve, se, base = gap_curve(m)
    print("lead time (days before day 0):", lead_time(curve, base))
    plt.plot(curve.index, curve.values)
    plt.fill_between(curve.index, curve - 1.96 * se, curve + 1.96 * se, alpha=0.2)
    plt.axvline(0, linestyle="--")
    plt.xlabel("days from KEV listing")
    plt.ylabel("EPSS gap vs. baseline")
    plt.savefig("results/gap_dummy.png", dpi=150)
    print("saved results/gap_dummy.png")