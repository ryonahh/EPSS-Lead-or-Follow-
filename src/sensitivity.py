import sys

import pandas as pd

from did import gap_curve, lead_time

m = pd.read_parquet(sys.argv[1])
curve, se, base = gap_curve(m)
print("threshold_k  run_days  lead_time")
for k in (1.5, 2, 3):
    for run in (2, 3, 5):
        print(k, run, lead_time(curve, base, k=k, run=run))