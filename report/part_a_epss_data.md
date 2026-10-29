# Part A: EPSS Historical Data and Threshold Analysis

## 1. Data Collection

The study uses daily historical EPSS v3 scores for 186 CVEs in the 2024 CISA Known Exploited Vulnerabilities (KEV) cohort. The study window runs from 2 November 2023 to 1 March 2025.

There were 486 expected daily snapshots. A total of 485 were downloaded and validated. The snapshot for 1 December 2024 was unavailable and was recorded in the download log.

## 2. EPSS Score Extraction

Daily EPSS scores were extracted into `data/processed/epss_scores_long.csv`.

- Extracted records: 59,733
- Unique CVEs: 186
- Duplicate CVE-date pairs: 0
- Observed score range: 0 to 1

The missing daily snapshot was not silently imputed in the extracted score data.

## 3. Day -60 Eligibility

The primary analysis requires an observed EPSS score exactly 60 days before each CVE's KEV listing date.

- Total KEV CVEs: 186
- Eligible CVEs: 77
- CVEs without an observed score on day -60: 109

The primary analysis retains the 77 eligible CVEs. The remaining 109 are excluded from the primary analysis under the predefined eligibility rule.

## 4. Threshold Analysis

Thresholds of 1%, 10%, and 50% were examined before the KEV listing date (day 0).

| EPSS threshold | Reached before day 0 | Already above threshold at baseline | Observed upward crossings |
|---|---:|---:|---:|
| 1% | 40/77 (51.95%) | 38 | 2/77 (2.60%) |
| 10% | 29/77 (37.66%) | 25 | 5/77 (6.49%) |
| 50% | 20/77 (25.97%) | 18 | 2/77 (2.60%) |

"Reached before day 0" includes scores already above the threshold at day -60. An upward crossing requires an observed score below the threshold followed by a score at or above it. These counts can overlap.

## 5. Metadata Integration

NVD publication dates and CVSS severity bands were merged with KEV and exploit-date metadata using `src/merge_metadata.py`.

Validation confirmed 186 unique CVEs, 77 baseline-eligible CVEs, no missing publication dates or CVSS bands, and exact agreement with the original eligibility IDs.

The merged CSV is generated under `data/processed/` and is excluded from Git by the repository's existing data ignore rule.

## 6. Exploit-Date Limitations

Of the 186 KEV CVEs, 18 had a recorded Exploit-DB date before KEV listing, 15 had a recorded date more than seven days after listing, and 153 had no recorded Exploit-DB date.

The absence of a recorded Exploit-DB date does not establish that no public exploit existed. Exploit-DB dates are proxies for public information and may not reflect the true first public release.

## 7. Interpretation and Limitations

Threshold crossings describe EPSS score timing relative to KEV listing; they do not by themselves establish independent early-warning capability. EPSS may incorporate public threat information. Interpretation requires the team's matched-control and event-study analysis, including the predefined seven-day ingestion buffer and sensitivity checks.

The missing 1 December 2024 snapshot should be considered when interpreting daily changes near that date.

## 8. Missing-Snapshot Gap Check

The daily EPSS snapshot for 1 December 2024 was unavailable. A diagnostic check of the 77 baseline-eligible CVEs found observed scores for all 77 CVEs on both 30 November and 2 December 2024. No upward threshold crossings at 1%, 10%, or 50% were detected across observed score gaps longer than one day.

This check does not recover the missing day's scores or rule out an unobserved temporary crossing on that date. The missing snapshot remains a data limitation.

## 9. Ingestion-Buffer Sensitivity Analysis

The analysis was repeated using 3-day, 7-day, and 14-day ingestion buffers, as required by the study protocol.

| Buffer (days) | Group | n | Mean adjusted EPSS gap | 95% confidence interval |
|---:|---|---:|---:|---|
| 3 | No exploit date recorded before cutoff | 59 | 0.0086 | [-0.0069, 0.0242] |
| 3 | Exploit date recorded before cutoff | 18 | 0.0220 | [-0.0116, 0.0556] |
| 7 | No exploit date recorded before cutoff | 59 | 0.0086 | [-0.0069, 0.0242] |
| 7 | Exploit date recorded before cutoff | 18 | 0.0220 | [-0.0116, 0.0556] |
| 14 | No exploit date recorded before cutoff | 59 | 0.0086 | [-0.0069, 0.0242] |
| 14 | Exploit date recorded before cutoff | 18 | 0.0220 | [-0.0116, 0.0556] |

The group sizes and estimated means were identical across all three buffer specifications. The diagnostic found 55 missing exploit dates among 77 listed CVEs and 22 recorded dates. No recorded date changed group membership when the buffer changed from 3 to 7 or 14 days.

Both confidence intervals include zero, so these estimates do not establish a statistically distinguishable positive mean adjusted gap at the conventional 5% significance level.

The results indicate that the estimates are unchanged across these three buffer choices for the current dataset. However, missing Exploit-DB dates do not establish that no public exploit existed, and recorded dates may not identify the true first public release.
