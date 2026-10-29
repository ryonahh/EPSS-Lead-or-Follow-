\# Limitations



1\. Twins are CVEs never KEV-listed as of the catalog pull date (28 Oct 2026). They are "no confirmed event", not "never attacked".

2\. EPSS uses public inputs (exploit code, KEV listing), so early separation may partly reflect those inputs, not foresight.

3\. Social media chatter and private exploit sharing are not observable. Our claim is "EPSS separates early after removing observable inputs", not "EPSS predicts attacks".

4\. Small sample: KEV listings from 2024 only, one EPSS model version (to be confirmed), 77 listed CVEs. Results are indicative, not general.

5\. Exploit-DB dates are publication dates on that site, which can be later than true first release.

6\. Exclusion: 109 of 186 KEV CVEs from 2024 were dropped because they were published less than 60 days before listing and had no day -60 EPSS history. These tend to be fast-exploited CVEs, so results apply to older CVEs, not KEV CVEs in general.

7\. Twin matching uses CVSS v3.x scores from NVD. CVEs with no v3 score could not be banded and were excluded.

