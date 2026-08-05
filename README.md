Search GitHub for PoC code based on a CVE ID or search query. Sorts results in descending order by star count.<br>
Shows the total number of results found, then walks through the top matches one by one — for each, the repo name, star count, last-updated date, URL, and description — asking whether to clone it. Enter `q` at any prompt to quit early.<br>

**Requires:** `curl`, `jq`, and `git`.<br>

**Usage:**<br>
`./get_poc.sh <CVE-ID or search query>`<br>

Unauthenticated requests are limited to 10/minute. Set the `GITHUB_TOKEN` environment variable to raise that to 30/minute:<br>
`GITHUB_TOKEN=ghp_xxxx ./get_poc.sh pwnkit`<br>

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
