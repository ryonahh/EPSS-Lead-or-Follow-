import collections
import glob
import gzip
import re

c = collections.Counter()
for f in sorted(glob.glob("data/raw/epss/*.csv.gz")):
    with gzip.open(f, "rt") as h:
        first = h.readline()
    m = re.search(r"model_version:([^,]+)", first)
    c[m.group(1) if m else first.strip()] += 1

print(c)