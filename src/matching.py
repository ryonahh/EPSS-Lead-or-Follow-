import numpy as np
import pandas as pd


def match_twins(listed, pool, n_twins=5, min_twins=2, window_days=30, seed=42):
    """
    listed: columns cve, day0, published, band
    pool:   columns cve, published, band (only never-KEV-listed CVEs)
    Returns (pairs table, list of dropped listed CVEs).
    """
    rng = np.random.default_rng(seed)
    used, pairs, dropped = set(), [], []
    for r in listed.itertuples():
        ok = pool[
            (pool.band == r.band)
            & ((pool.published - r.published).abs() <= pd.Timedelta(days=window_days))
            & (~pool.cve.isin(used))
        ]
        if len(ok) < min_twins:
            dropped.append(r.cve)
            continue
        pick = ok.sample(n=min(n_twins, len(ok)),
                         random_state=int(rng.integers(10**9)))
        used.update(pick.cve)
        for t in pick.cve:
            pairs.append((r.cve, t, r.day0))
    return pd.DataFrame(pairs, columns=["listed_cve", "twin_cve", "day0"]), dropped


if __name__ == "__main__":
    rng = np.random.default_rng(0)
    bands = ["Low", "Medium", "High", "Critical"]
    base = pd.Timestamp("2023-06-01")
    pool = pd.DataFrame({
        "cve": [f"CVE-P-{i}" for i in range(200)],
        "published": base + pd.to_timedelta(rng.integers(0, 120, 200), unit="D"),
        "band": rng.choice(bands, 200),
    })
    listed = pd.DataFrame({
        "cve": ["CVE-L-1", "CVE-L-2", "CVE-L-3"],
        "day0": pd.to_datetime(["2024-02-01", "2024-03-15", "2024-05-10"]),
        "published": pd.to_datetime(["2023-07-01", "2023-08-10", "2023-09-20"]),
        "band": ["High", "Critical", "Medium"],
    })
    pairs, dropped = match_twins(listed, pool)
    print(pairs)
    print("dropped:", dropped)
    print("twins per listed CVE:\n", pairs.groupby("listed_cve").size())
    assert pairs.twin_cve.is_unique, "a twin was used twice"