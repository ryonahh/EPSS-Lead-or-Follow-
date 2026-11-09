"""Placebo tests for the KEV event study. Plan: report/placebo_plan.md (fixed before running).

A) fake treated twin: one random twin per group plays the listed CVE, real day 0.
B) fake dates: each group borrows the day 0 of a different listed CVE that is
   more than 60 days from its true day 0, with the fake window inside the EPSS files.

usage: python src/placebo.py [data/clean/master.parquet] [shared/pairs.csv]
"""
import glob
import pathlib
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from did import gap_curve, lead_time

N_DRAWS, SEED = 1000, 42
FIRST, LAST = pd.Timestamp("2023-11-02"), pd.Timestamp("2025-03-01")
EPSS_CACHE = pathlib.Path("data/clean/epss_members.parquet")
RES = pathlib.Path("results")


def metrics(m):
    curve, se, base = gap_curve(m)
    return curve, curve.loc[1:7].mean(), curve.loc[-19:-1].mean(), lead_time(curve, base)


def per_cve_ci(m, lo, hi):
    """Mean and 95% CI across listed CVEs of each CVE's own baseline-adjusted gap."""
    L = m[m.group == "listed"].set_index(["listed_cve", "rel_day"]).epss
    T = m[m.group == "twin"].groupby(["listed_cve", "rel_day"]).epss.mean()
    g = (L - T).dropna().unstack()
    adj = g.loc[:, lo:hi].mean(axis=1) - g.loc[:, -60:-31].mean(axis=1)
    adj = adj.dropna()
    h = 1.96 * adj.sem()
    return adj.mean(), adj.mean() - h, adj.mean() + h


def load_epss(cves):
    if EPSS_CACHE.exists():
        e = pd.read_parquet(EPSS_CACHE)
        if set(cves) <= set(e.cve):
            return e
    frames = []
    for f in sorted(glob.glob("data/raw/epss/epss_scores-*.csv.gz")):
        df = pd.read_csv(f, comment="#", usecols=["cve", "epss"])
        df = df[df.cve.isin(cves)]
        df["date"] = pd.Timestamp(f.split("epss_scores-")[1][:10])
        frames.append(df)
    e = pd.concat(frames, ignore_index=True)
    e.to_parquet(EPSS_CACHE)
    return e


def placebo_a(master, rng):
    twins = master[master.group == "twin"]
    groups = twins.groupby("listed_cve").cve.unique()
    out, curves = [], []
    for i in range(N_DRAWS):
        fake = {g: rng.choice(c) for g, c in groups.items()}
        m = twins.copy()
        m["group"] = np.where(m.cve.values == m.listed_cve.map(fake).values, "listed", "twin")
        curve, post, pre, lt = metrics(m)
        out.append(dict(draw=i, post_1_7=post, pre_m19_m1=pre, lead_time=lt, groups=len(groups)))
        curves.append(curve)
    return pd.DataFrame(out), pd.concat(curves, axis=1)


def placebo_b(pairs, epss, rng):
    day0 = pairs.drop_duplicates("listed_cve").set_index("listed_cve").day0
    listed = pd.DataFrame({"listed_cve": day0.index, "cve": day0.index, "group": "listed"})
    twins = pairs.rename(columns={"twin_cve": "cve"})[["listed_cve", "cve"]].assign(group="twin")
    mem = pd.concat([listed, twins]).merge(epss, on="cve")
    have = np.sort(epss.date.unique())

    ok_window = (day0 - pd.Timedelta(days=60) >= FIRST) & (day0 + pd.Timedelta(days=60) <= LAST)
    donors = {}
    for g, d in day0.items():
        far = (day0 - d).abs() > pd.Timedelta(days=60)
        donors[g] = day0[far & ok_window & (day0.index != g)].values
    no_donor = [g for g, v in donors.items() if len(v) == 0]

    out, curves, out_bal, curves_bal = [], [], [], []
    for i in range(N_DRAWS):
        fake = pd.Series({g: rng.choice(v) for g, v in donors.items() if len(v)})
        m = mem[mem.listed_cve.isin(fake.index)].copy()
        m["rel_day"] = (m.date - m.listed_cve.map(fake)).dt.days
        m = m[(m.rel_day >= -60) & (m.rel_day <= 60)]
        curve, post, pre, lt = metrics(m)
        out.append(dict(draw=i, post_1_7=post, pre_m19_m1=pre, lead_time=lt,
                        groups=m[m.group == "listed"].listed_cve.nunique()))
        curves.append(curve)

        # B-balanced: listed CVE scored on every fake day that has an EPSS file
        lo, hi = fake - pd.Timedelta(days=60), fake + pd.Timedelta(days=60)
        files = pd.Series({g: ((have >= lo[g]) & (have <= hi[g])).sum() for g in fake.index})
        got = m[m.group == "listed"].groupby("listed_cve").rel_day.nunique()
        full = got[got >= files.reindex(got.index)].index
        mb = m[m.listed_cve.isin(full)]
        curve, post, pre, lt = metrics(mb)
        out_bal.append(dict(draw=i, post_1_7=post, pre_m19_m1=pre, lead_time=lt, groups=len(full)))
        curves_bal.append(curve)
    return (pd.DataFrame(out), pd.concat(curves, axis=1),
            pd.DataFrame(out_bal), pd.concat(curves_bal, axis=1), no_donor)


def summarise(name, d, real_post, real_pre):
    lt = d.lead_time.dropna()
    return dict(
        test=name, n_draws=len(d), mean_groups=d.groups.mean(),
        post_1_7_mean=d.post_1_7.mean(),
        post_1_7_p2_5=d.post_1_7.quantile(0.025), post_1_7_p97_5=d.post_1_7.quantile(0.975),
        share_post_ge_real=(d.post_1_7 >= real_post).mean(),
        pre_m19_m1_mean=d.pre_m19_m1.mean(),
        pre_m19_m1_p2_5=d.pre_m19_m1.quantile(0.025), pre_m19_m1_p97_5=d.pre_m19_m1.quantile(0.975),
        share_pre_ge_real=(d.pre_m19_m1 >= real_pre).mean(),
        lead_time_found_share=len(lt) / len(d),
        lead_time_median=lt.median() if len(lt) else np.nan,
    )


def plot(curves, real, title, path):
    lo, hi = curves.quantile(0.025, axis=1), curves.quantile(0.975, axis=1)
    fig, ax = plt.subplots(figsize=(8, 4.6), dpi=200)
    ax.fill_between(curves.index, lo, hi, color="#c3c2b7", alpha=0.6, lw=0,
                    label="placebo, middle 95% of 1000 draws")
    ax.plot(curves.index, curves.median(axis=1), color="#52514e", lw=1.5, ls="--",
            label="placebo median")
    ax.plot(real.index, real.values, color="#2a78d6", lw=2.2, label="real KEV listing")
    ax.axhline(0, color="#52514e", lw=0.6)
    ax.axvline(0, color="#52514e", lw=0.8, ls=":")
    ax.axvspan(-60, -31, color="#cde2fb", alpha=0.35, lw=0)
    ax.text(-45.5, 0.235, "baseline", ha="center", fontsize=10, color="#52514e")
    ax.set_ylim(-0.08, 0.26)
    ax.set_xlim(-60, 60)
    ax.set_xlabel("days from day 0", fontsize=12)
    ax.set_ylabel("EPSS gap vs. baseline", fontsize=12)
    ax.set_title(title, fontsize=13, loc="left")
    ax.tick_params(labelsize=11)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.legend(loc="center right", frameon=False, fontsize=10)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


if __name__ == "__main__":
    master = pd.read_parquet(sys.argv[1] if len(sys.argv) > 1 else "data/clean/master.parquet")
    pairs = pd.read_csv(sys.argv[2] if len(sys.argv) > 2 else "shared/pairs.csv", parse_dates=["day0"])

    real, real_post, real_pre, real_lt = metrics(master)
    post_ci, pre_ci = per_cve_ci(master, 1, 7), per_cve_ci(master, -19, -1)
    print(f"real: +1..+7 = {real_post:.4f}  CI {post_ci[1]:.3f}..{post_ci[2]:.3f}")
    print(f"real: -19..-1 = {real_pre:.4f}  CI {pre_ci[1]:.3f}..{pre_ci[2]:.3f}  lead time = {real_lt}")

    a, ca = placebo_a(master, np.random.default_rng(SEED))
    epss = load_epss(set(pairs.listed_cve) | set(pairs.twin_cve))
    b, cb, bb, cbb, no_donor = placebo_b(pairs, epss, np.random.default_rng(SEED))
    print("groups with no acceptable fake date:", no_donor)

    rows = [dict(test="real", n_draws=1, mean_groups=master.listed_cve.nunique(),
                 post_1_7_mean=real_post, post_1_7_p2_5=post_ci[1], post_1_7_p97_5=post_ci[2],
                 pre_m19_m1_mean=real_pre, pre_m19_m1_p2_5=pre_ci[1], pre_m19_m1_p97_5=pre_ci[2],
                 lead_time_found_share=float(real_lt is not None),
                 lead_time_median=real_lt if real_lt is not None else np.nan)]
    rows += [summarise("A_fake_treated_twin", a, real_post, real_pre),
             summarise("B_fake_dates", b, real_post, real_pre),
             summarise("B_balanced_diagnostic", bb, real_post, real_pre)]
    summary = pd.DataFrame(rows)
    summary.to_csv(RES / "placebo_summary.csv", index=False, float_format="%.4f")
    pd.concat([a.assign(test="A"), b.assign(test="B"), bb.assign(test="B_balanced")]).to_csv(
        RES / "placebo_draws.csv", index=False, float_format="%.5f")
    with pd.option_context("display.width", 200, "display.max_columns", 20):
        print(summary.T)

    plot(ca, real, "Placebo A: a random twin plays the listed CVE (real day 0)", RES / "placebo_A.png")
    plot(cb, real, "Placebo B: fake day 0 borrowed from another listed CVE", RES / "placebo_B.png")
    print("saved results/placebo_A.png, results/placebo_B.png, results/placebo_summary.csv")
