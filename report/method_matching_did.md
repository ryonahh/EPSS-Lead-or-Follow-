\## Matching and difference-in-differences



\*\*Twins.\*\* Each KEV-listed CVE is compared with up to five "twins": CVEs that were never added to the KEV catalog (as of the 28 Oct 2026 pull), sit in the same CVSS severity band (Critical 9.0-10, High 7.0-8.9, Medium 4.0-6.9, Low below 4.0, from NVD v3.x scores), and were published within 30 days of the listed CVE. Every twin must also have at least 60 days of EPSS history before the reference date. Twins are drawn at random with a fixed seed, and no twin is used twice. A twin has no listing date of its own, so it borrows the day 0 of the CVE it is matched to. Twins are "no confirmed event" CVEs, not CVEs known to be safe. We matched 77 listed CVEs to 383 twins (about 5 each).



\*\*Gap curve.\*\* For each day from 60 days before to 60 days after day 0, we take the listed CVE's EPSS score minus the average EPSS score of its twins, then average this gap across all listed CVEs. The twins show what a similar CVE's score does anyway, including general drift and model updates. We then subtract the gap's average over days -60 to -31, a stretch where nothing should be happening yet. What is left is the difference-in-differences: how much more the listed CVEs moved than their twins, relative to their own starting gap. The shaded band is a 95% interval across listed CVEs.



\*\*Lead time.\*\* Because EPSS uses KEV listing as an input, a jump at or after day 0 is partly built in, so our main result is the period before listing. We define lead time as the first day before day 0 on which the gap rises above 2 standard deviations of its baseline noise and stays above it for 3 days in a row. This rule was fixed before we looked at any results. Our result: \[lead time = X days, with the 95% band covering / not covering zero]. We also report how the answer changes with a stricter or looser threshold: \[sensitivity result].



\*\*Dropped CVEs.\*\* Of the 186 CVEs added to KEV in 2024, 109 were excluded because they were published less than 60 days before listing and so had no EPSS score at day -60. The remaining 77 are the main sample. The excluded CVEs are mostly recent (CVE-2024) vulnerabilities that were exploited quickly, so our conclusions apply to older CVEs, not to every KEV listing.



\*\*Result.\*\* EPSS rises sharply at KEV listing: the average gap over days +1 to +7 is 0.207 (95% interval 0.136 to 0.278), and it stays at about that level for the following 60 days. Before listing the gap is small and not distinguishable from zero: the average over days -19 to -1 is 0.012 (95% interval -0.002 to 0.026), the median is 0.000, and only 48% of listed CVEs have a positive gap. The pre-listing movement appears as a few step changes, which is what a small number of individual CVEs jumping looks like. An earlier version of our lead-time rule (first day the gap exceeds 2 standard deviations of baseline noise for 3 days) returned 19 days, but the baseline noise was about 0.005, so the threshold was only about 0.010, and the result disappeared at 3 standard deviations. We therefore do not claim a lead time. The interval rules out an average early gap larger than about 0.026, roughly an eighth of the post-listing jump. Because EPSS takes KEV listing as an input, the jump at listing is expected and is not evidence of foresight. \[Add: exploit-code split result and 3/7/14-day buffer table from A.]

