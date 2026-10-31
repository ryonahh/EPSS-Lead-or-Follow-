# Limitations

1. Twins are CVEs never KEV-listed as of the catalog pull date (28 Oct 2026). They are "no confirmed event", not "never attacked".

2. EPSS uses public inputs (exploit code, KEV listing), so early separation may partly reflect those inputs, not foresight.

3. Social media chatter and private exploit sharing are not observable. Our claim is "EPSS separates early after removing observable inputs", not "EPSS predicts attacks".

4. One EPSS model version: all scores come from EPSS v3, which ran from 7 Mar 2023 to 17 Mar 2025 (when v4 replaced it). Our EPSS files (2 Nov 2023 to 1 Mar 2025) and every -60..+60 window around a 2024 KEV listing lie inside that period, so no model change falls inside the study. The results describe v3 only, and v4 may behave differently. The sample is small (77 listed CVEs from one year of KEV listings), so the results are indicative, not general.

5. Exploit-DB dates are publication dates on that site, which can be later than true first release. 55 of the 77 listed CVEs have no Exploit-DB entry at all, which does not mean no exploit existed.

6. Exclusion: 109 of 186 KEV CVEs from 2024 were dropped because they were published less than 60 days before listing and had no day -60 EPSS history. These tend to be fast-exploited CVEs, so results apply to older CVEs, not KEV CVEs in general.

7. Twin matching uses CVSS v3.x scores from NVD. CVEs with no v3 score could not be banded and were excluded. Twins must also have been published at least 60 days before day 0. This filter is in `src/matching.py` but not in the rulebook.

8. The EPSS file for 1 Dec 2024 is unavailable (485 of 486 daily files). That day is simply missing for every CVE, with no imputation. Two twins have no EPSS scores at all.

9. Placebo test: the placebo supports the jump at listing (no placebo draw comes near it) but shows that our 2 SD / 3-day lead-time rule fires in 16-59% of null draws, so the rule cannot detect a lead time reliably with this sample. We therefore claim no lead time. The pre-listing gap of 0.013 sits in the top 1-5% of fake-date placebo draws, so a small early rise cannot be fully ruled out, but its own 95% interval includes zero and it may come from inputs EPSS already reads. Passing a placebo validates the method; it does not prove that EPSS gives early warning.
