Search GitHub for PoC code based on a CVE ID or search query. Sorts results in descending order by star count.<br>
Shows the total number of results found, then walks through the top matches one by one — for each, the repo name, star count, last-updated date, URL, and description — asking whether to clone it. Enter `q` at any prompt to quit early.<br>

If the query is a CVE ID (e.g. `CVE-2026-41651`), it's searched as-is. Otherwise `PoC` is appended to the search term. If that turns up nothing, the tool falls back to searching `<query> CVE`, pulls any CVE IDs out of the matching repos' names/descriptions, and re-searches on those CVE IDs directly — useful for vague queries (e.g. a product name) that don't literally contain the word "PoC".<br>

**Requires:** `curl`, `jq`, and `git`.<br>

**Usage:**<br>
`./get_poc.sh [-v|--version VERSION] [-l|--limit N] <CVE-ID or search query>`<br>

Pass `-v`/`--version` to only show CVEs whose affected range actually includes that version — the query is treated as a product name, looked up on [NVD](https://nvd.nist.gov/), and matched against each candidate CVE's CPE version range (`versionStartIncluding`/`versionEndExcluding`/etc.), not just a text search for the version string:<br>
`./get_poc.sh -v 1.2.8 packagekit`<br>

Pass `-l`/`--limit` to cap how many results are shown (default 30, max 100 — GitHub's per-page ceiling):<br>
`./get_poc.sh -l 5 pwnkit`<br>

GitHub's unauthenticated requests are limited to 10/minute. Set the `GITHUB_TOKEN` environment variable to raise that to 30/minute:<br>
`GITHUB_TOKEN=ghp_xxxx ./get_poc.sh pwnkit`<br>

NVD's unauthenticated requests (used with `-v`) are limited to 5/30s. Set `NVD_API_KEY` (free at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)) to raise that to 50/30s:<br>
`NVD_API_KEY=xxxx ./get_poc.sh -v 1.2.8 packagekit`<br>

**Example:**<br>
```
$ ./get_poc.sh pwnkit
Searching GitHub for: pwnkit PoC

Found 47 total results — showing top 30 by stars
(enter q at any prompt to quit)

[1/30]  arthepsy/CVE-2021-4034  (★ 312 | updated 2026-03-11)
  https://github.com/arthepsy/CVE-2021-4034
  PoC for PwnKit: Local Privilege Escalation Vulnerability in polkit's pkexec (CVE-2021-4034)
Clone? [y/n/q] y
Cloning into 'CVE-2021-4034'...
Continue browsing? [y/n] n
```

A browser-based port of this same search, no local dependencies needed, is at [pwnmi.com/tools/poc-finder](https://pwnmi.com/tools/poc-finder/).
