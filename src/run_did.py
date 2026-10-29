import sys

import matplotlib.pyplot as plt
import pandas as pd

from did import gap_curve, lead_time

m = pd.read_parquet(sys.argv[1])
curve, se, base = gap_curve(m)
print("lead time (days before day 0):", lead_time(curve, base))
plt.plot(curve.index, curve.values)
plt.fill_between(curve.index, curve - 1.96 * se, curve + 1.96 * se, alpha=0.2)
plt.axvline(0, linestyle="--")
plt.xlabel("days from KEV listing")
plt.ylabel("EPSS gap vs. baseline")
plt.savefig(sys.argv[2], dpi=150)
print("saved", sys.argv[2])