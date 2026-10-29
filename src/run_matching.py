import sys
import pandas as pd
from matching import match_twins

listed = pd.read_parquet("data/clean/listed.parquet")
pool = pd.read_parquet("data/clean/pool.parquet")
pilot = "--pilot" in sys.argv
if pilot:
    listed = listed.sample(n=min(50, len(listed)), random_state=42)

pairs, dropped = match_twins(listed, pool)
print("listed:", len(listed), "| matched:", pairs.listed_cve.nunique(),
      "| dropped (<2 twins):", len(dropped))
print(pairs.groupby("listed_cve").size().describe())

name = "pairs_pilot" if pilot else "pairs"
pairs.to_csv(f"data/clean/{name}.csv", index=False)
pd.Series(dropped, name="cve").to_csv(f"data/clean/{name}_dropped.csv", index=False)