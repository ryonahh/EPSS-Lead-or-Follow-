# Placebo test plan (fixed before running)

Written 31 Oct 2026, before `src/placebo.py` was run on real data. Nothing below may be changed after seeing placebo output. If a placebo shows a jump, we report it as possible leakage. We do not change twin rules, the window, the baseline or the lead-time rule.

## What stays exactly the same as the main analysis

- Sample: `shared/pairs.csv` (77 listed CVEs, 383 twins), KEV listings 1 Jan to 31 Dec 2024, EPSS v3 daily files 2 Nov 2023 to 1 Mar 2025.
- Window: days -60 to +60 around day 0.
- Code: `gap_curve` and `lead_time` are imported from `src/did.py` and used unchanged.
- Baseline: days -60 to -31 (inside `gap_curve`).
- Lead-time rule: the gap must rise above 2 SD of the baseline curve for 3 consecutive days within days -30 to -1 (`lead_time(curve, base, k=2, run=3)`).
- Randomness: one `numpy.random.default_rng(42)` per placebo. N = 1000 draws each.

## Placebo A: fake treated twin (real day 0)

For each listed CVE group, pick one of its twins at random to play the "listed" CVE. Its remaining twins (3 or 4) are the controls. The real listed CVE is left out, and the group keeps its real day 0. No twin was ever KEV-listed, so the true effect is zero. A jump at day 0 would mean the date alone (model updates or calendar effects shared by the group) creates a gap.

## Placebo B: fake dates (real labels)

Each listed CVE and its twins get the day 0 of a different listed CVE, drawn at random. A fake date is accepted only if:
- it is more than 60 days from the group's true day 0, so the real listing falls outside the fake -60..+60 window, and
- the fake window (fake day 0 ± 60 days) lies inside 2 Nov 2023 to 1 Mar 2025.

Days with no EPSS score (for example, before a CVE was published) are dropped exactly as `gap_curve` already drops them. No extra filter is added. Groups with no acceptable donor date are dropped from that draw, and we report how often this happens.

Pre-declared diagnostic (reported alongside B, never in its place): **B-balanced** reruns the same draws, keeping only groups in which the listed CVE has a score on every fake day that has an EPSS file. The 1 Dec 2024 file is missing for all CVEs, so that day does not count against a group. This shows whether any B result comes from groups entering the panel partway through the window.

## Metrics recorded for every draw

1. Mean gap over days +1 to +7 (the post-listing jump).
2. Mean gap over days -19 to -1 (pre-listing separation).
3. Lead time from `lead_time` (`None` means no lead time found).

For each placebo we report the mean, the 2.5th and 97.5th percentiles of metrics 1 and 2 across draws, and the share of draws in which a lead time is found. We compare these with the real values (from the same code on the real master table) and give the share of placebo draws at or above each real value.

## How we will read the results (fixed now)

- **Method passes** if the placebo +1..+7 gaps are centred near zero, their 95% range includes 0, and the real +1..+7 gap lies above the 97.5th percentile of the placebo draws.
- **Possible leakage** if the placebo 95% range for the +1..+7 or -19..-1 gap excludes zero, or if the lead-time rule fires in more than 5% of draws. We report this as a finding and change no rules.
- The real -19..-1 gap is judged against the placebo distribution. If it sits inside the middle 95%, it cannot be told apart from what the method produces when nothing is happening.
- Passing a placebo validates the method. It does **not** show that EPSS gives early warning.
