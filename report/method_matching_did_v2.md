## Matching and difference-in-differences

**Twins.** Each KEV-listed CVE is compared with up to five "twins": CVEs that were never added to the KEV catalog (as of the 28 Oct 2026 pull), sit in the same CVSS severity band (Critical 9.0-10, High 7.0-8.9, Medium 4.0-6.9, Low below 4.0, from NVD v3.x scores), and were published within 30 days of the listed CVE. Twins are drawn at random with a fixed seed (42), and no twin is used twice. A twin has no listing date of its own, so it borrows the day 0 of the CVE it is matched to. Twins are "no confirmed event" CVEs, not CVEs known to be safe. We matched 77 listed CVEs to 383 twins (75 with five twins, 2 with four). Two twins (CVE-2024-29160 and CVE-2024-35099) have no EPSS scores in our files, so their groups are compared with four twins in practice.

**Extra matching filter not in the rulebook.** `src/matching.py` adds one condition that the one-page rulebook does not state: a twin must have been published at least 60 days before its listed CVE's day 0. This applies the same "60 days of EPSS history" requirement to twins that the rulebook applies to listed CVEs, so every twin can have a day -60 score. It was in the code before any results were produced and was not changed afterwards. We report it here because the rulebook should have listed it.

**Gap curve.** For each day from 60 days before to 60 days after day 0, we take the listed CVE's EPSS score minus the average EPSS score of its twins, then average this gap across all listed CVEs. The twins show what a similar CVE's score does anyway, including general drift and model updates. We then subtract the gap's average over days -60 to -31, a stretch where nothing should be happening yet. What is left is the difference-in-differences: how much more the listed CVEs moved than their twins, relative to their own starting gap. Window averages are reported with 95% intervals across listed CVEs (each CVE's mean gap over the window minus its own baseline mean).

**Lead time.** Because EPSS uses KEV listing as an input, a jump at or after day 0 is partly built in, so our main question is the period before listing. The rule, fixed before we looked at any results, defines lead time as the first day before day 0 on which the gap rises above 2 standard deviations of its baseline noise and stays above it for 3 days in a row.

**Lead time: none claimed.** The fixed rule returns 19 days. We do not report this as a lead time, for three reasons, all stated openly here. First, the baseline noise is tiny (SD 0.0051), so the threshold is only about 0.010 EPSS. Second, the result is not robust (see the sensitivity table). Third, the placebo test shows the rule fires far too often when there is nothing to find. We keep the rule as written and report what it returned. We do not replace it with a different rule.

**Sensitivity.** Lead time (days before day 0) under other thresholds (k × baseline SD) and run lengths, from `src/sensitivity.py`:

| k (SD) | run 2 days | run 3 days | run 5 days |
|---:|---:|---:|---:|
| 1.5 | 19 | 19 | 19 |
| 2 (main) | 19 | **19** | 19 |
| 3 | 2 | none | none |

Every looser setting gives 19 days, because the gap steps up once around day -19 (the curve reaches 0.011 on day -19 and 0.018 on day -17) and stays there. At 3 SD (0.015) the signal disappears, apart from a 2-day blip just before listing. A rise of about 0.01 EPSS is too small to act on in practice.

**Dropped CVEs.** Of the 186 CVEs added to KEV in 2024, 109 were excluded because they were published less than 60 days before listing and so had no EPSS score at day -60. The remaining 77 are the main sample. Of the 109 dropped, 100 are CVE-2024 IDs and 8 are CVE-2023 IDs (`results/dropped_by_year.csv`). These are mostly vulnerabilities that were exploited soon after disclosure, so our conclusions apply to older CVEs, not to every KEV listing.

**Result.** EPSS rises sharply at KEV listing: the average gap over days +1 to +7 is 0.208 (95% interval 0.136 to 0.278), and it stays at about that level for the following 60 days. Before listing the gap is small: the average over days -19 to -1 is 0.013 (95% interval -0.002 to 0.026), the median is 0.000, and only 34 of 77 listed CVEs (44%) rise above their own baseline gap (13 do not move at all). The pre-listing movement appears as a few step changes, which is what a small number of individual CVEs jumping looks like. The interval rules out an average early gap larger than about 0.026, roughly an eighth of the post-listing jump. Because EPSS takes KEV listing as an input, the jump at listing is expected and is not evidence of foresight.

**Exploit-code split and ingestion buffer.** Using Exploit-DB publication dates, we split the 77 listed CVEs by whether an exploit was recorded before the cutoff (day 0 minus the buffer). The mean adjusted gap before listing (from Part A):

| Buffer | Group | n | Mean adjusted gap | 95% interval |
|---:|---|---:|---:|---|
| 3, 7 or 14 days | No exploit date recorded before cutoff | 59 | 0.009 | -0.007 to 0.024 |
| 3, 7 or 14 days | Exploit date recorded before cutoff | 18 | 0.022 | -0.012 to 0.056 |

The three buffers give identical results because no recorded exploit date falls within 14 days before listing, so no CVE changes group. Both intervals include zero. The group with an earlier exploit has the larger point estimate, which fits EPSS reacting to public exploit code, but 18 CVEs are too few to tell the groups apart. Of the 59 "no exploit date" CVEs, 55 have no Exploit-DB entry at all and 4 have one only after listing. A missing entry does not mean no exploit existed.

**Placebo test.** The plan was fixed in `report/placebo_plan.md` before the placebo code was run. We used the same `gap_curve` and `lead_time` code, seed 42 and 1000 draws (`src/placebo.py`, `results/placebo_summary.csv`).

| | Gap +1..+7 (mean; 95% of draws) | Gap -19..-1 (mean; 95% of draws) | Lead-time rule fires |
|---|---|---|---:|
| Real KEV listing | 0.208 | 0.013 | yes (19 days) |
| A: random twin as "listed", real day 0 | 0.000 (-0.002 to 0.002) | 0.000 (-0.002 to 0.002) | 59% of draws |
| B: fake day 0 from another listed CVE | -0.014 (-0.041 to 0.008) | -0.007 (-0.025 to 0.010) | 16% of draws |
| B-balanced (diagnostic) | -0.003 (-0.027 to 0.017) | 0.000 (-0.015 to 0.017) | 36% of draws |

- *The jump passes.* No placebo draw comes close to the real +1..+7 gap of 0.208 (0 of 1000 in every placebo). Both 95% ranges include zero. Neither the date alone (A) nor the CVEs alone (B) produces a jump, so the post-listing jump is tied to the actual listing. Placebo B drifts slightly downward after the fake day 0. This is likely because many listed CVEs receive fake dates after their real listing, when their scores are slowly falling back. The drift goes in the opposite direction to a fake signal.
- *The lead-time rule fails, which we report as possible leakage.* Under our pre-declared criterion, a rule that fires in more than 5% of null draws is unreliable. The 2 SD / 3-day rule fires in 59% of A draws and 16% of B draws, typically at about 22-23 days. With such a small baseline SD, ordinary drift crosses the threshold. This is why the 19-day figure is not a lead time. We did not change the rule.
- *The pre-listing gap is borderline.* The real -19..-1 gap (0.013) is above every placebo A draw. However, A's twins have low, stable scores, so A gives a narrow null. It is above 98.7% of placebo B draws and 94.6% of B-balanced draws. Under the fake-dates null, the small pre-listing rise is somewhat unusual, but its own 95% interval still includes zero and it is about one-sixteenth of the post-listing jump. It may reflect public inputs EPSS already reads (such as exploit code) rather than foresight. We do not treat it as evidence of early warning.

The placebo validates the method for the jump at listing. It does not show that EPSS gives early warning.
