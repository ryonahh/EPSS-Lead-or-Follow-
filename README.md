# Does EPSS Lead or Follow?

A small event study asking whether EPSS scores for CVEs that CISA later adds to the Known Exploited Vulnerabilities (KEV) catalog pull away from similar, never-listed CVEs *before* the listing date (day 0), or only after it.

- **Sample:** KEV listings from 1 Jan to 31 Dec 2024. 186 CVEs, of which 77 have EPSS history at day -60 (109 dropped).
- **Controls:** 383 matched "twins" that were never KEV-listed: same CVSS band, published within ±30 days, published at least 60 days before day 0, seed 42.
- **Model:** EPSS v3 daily scores from 2 Nov 2023 to 1 Mar 2025 (485 of 486 files; 1 Dec 2024 is unavailable).
- **Window:** days -60 to +60, baseline -60 to -31, lead-time rule 2 SD for 3 days.

The rules are in `EPSS_Study_Rulebook.pdf` and `report/placebo_plan.md`. They were not changed after results were seen.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export NVD_API_KEY=...   # optional, makes get_pool.py about 10x faster
```

## Run order

Run every command from the repo root.

```bash
mkdir -p data/raw data/clean

# 1. KEV catalog
curl -L -o data/raw/known_exploited_vulnerabilities.csv \
  https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv

# 2. Daily EPSS files -> data/raw/epss/  (about 486 files, about 700 MB; resumable)
python src/download_epss.py

# 3. NVD twin pool -> data/clean/nvd_pool.parquet  (rate-limited; about 30-60 min without a key)
python src/get_pool.py

# 4. Listed CVEs + twin pool -> data/clean/listed.parquet, data/clean/pool.parquet
python src/prep_tables.py

# 5. Twin matching -> data/clean/pairs.csv  (should match shared/pairs.csv: 77 listed, 383 twins)
python src/run_matching.py

# 6. Master table: listed + twins, EPSS by day from -60 to +60
python src/build_master.py shared/pairs.csv data/clean/master.parquet

# 7. Main DiD gap curve and lead time
python src/run_did.py data/clean/master.parquet results/gap_main.png

# 8. Lead-time sensitivity, dropped-CVE table
python src/sensitivity.py data/clean/master.parquet
python src/dropped_table.py

# 9. Placebo tests (1000 draws each, about 1 min)
python src/placebo.py data/clean/master.parquet shared/pairs.csv
```

`data/nvd_metadata.csv` (NVD details for the 186 listed CVEs) comes from `src/nvd.py`, run on `data/kev_2024_filtered.xlsx`. It is committed, so you do not need to rerun it.

`data/raw/` and `data/clean/` are git-ignored. Do not commit them.

## Outputs

| File | What it is |
|---|---|
| `shared/pairs.csv` | Frozen twin matches: `listed_cve, twin_cve, day0` |
| `results/gap_main.png` | Main DiD gap curve (listed minus twins, minus baseline) with 95% band |
| `results/placebo_A.png` | Placebo A (random twin plays the listed CVE) vs. the real curve |
| `results/placebo_B.png` | Placebo B (fake day 0 from another listed CVE) vs. the real curve |
| `results/placebo_summary.csv` | Placebo metrics. The `real` row's `p2_5`/`p97_5` columns hold the 95% CI across CVEs. Placebo rows hold the 2.5th and 97.5th percentiles across draws. |
| `results/placebo_draws.csv` | Every placebo draw: +1..+7 gap, -19..-1 gap, lead time |
| `results/dropped_by_year.csv` | Kept vs. dropped 2024 KEV CVEs by CVE year |
| `results/EPSS_4slides.pptx` | 4-slide summary deck |
| `report/` | Report sections: data (Part A), method and results, placebo plan, limitations |

## Code

| Script | Role |
|---|---|
| `src/download_epss.py` | Download daily EPSS files |
| `src/nvd.py` | NVD metadata for the 2024 KEV CVEs |
| `src/get_pool.py` | NVD pool of candidate twins around each listed CVE's publish date |
| `src/prep_tables.py` | Filter listed CVEs (60-day history), band CVSS, build the twin pool |
| `src/matching.py`, `src/run_matching.py` | Twin matching (seed 42) |
| `src/build_master.py` | Merge EPSS scores onto listed CVEs and twins by relative day |
| `src/did.py` | `gap_curve` (DiD) and `lead_time`, used by every analysis script |
| `src/run_did.py`, `src/sensitivity.py` | Main figure and lead-time sensitivity |
| `src/placebo.py` | Placebo tests A and B |
| `src/dropped_table.py` | Dropped-CVE breakdown |

## Headline results

- Jump after listing (+1..+7 days): **0.208** EPSS (95% CI 0.136 to 0.278). This is expected, because KEV is an EPSS input.
- Before listing (-19..-1 days): **0.013** (95% CI -0.002 to 0.026). This is not distinguishable from zero.
- Lead time: **none claimed.** The fixed rule returns 19 days, but it disappears at 3 SD and fires in 16-59% of placebo draws.
- Placebo: no placebo draw reproduces the jump at listing.
