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
