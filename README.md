## get_poc.sh

Search GitHub for PoC code based on a CVE ID or search query. Sorts results in descending order by star count.<br>
Shows the total number of results found, then walks through the top matches one by one — for each, the repo name, star count, last-updated date, URL, and description — asking whether to clone it. Enter `q` at any prompt to quit early.<br>

If the query is a CVE ID (e.g. `CVE-2026-41651`), it's searched as-is. Otherwise `PoC` is appended to the search term. If that turns up nothing, the tool falls back to searching `<query> CVE`, pulls any CVE IDs out of the matching repos' names/descriptions, and re-searches on those CVE IDs directly — useful for vague queries (e.g. a product name) that don't literally contain the word "PoC".<br>

**Requires:** `curl`, `jq`, and `git`.<br>

**Usage:**<br>
`./get_poc.sh [-v|--version VERSION] [-s|--since WHEN] [-l|--limit N] <CVE-ID or search query>`<br>

Pass `-v`/`--version` to only show CVEs whose affected range actually includes that version — the query is treated as a product name, looked up on [NVD](https://nvd.nist.gov/), and matched against each candidate CVE's CPE version range (`versionStartIncluding`/`versionEndExcluding`/etc.), not just a text search for the version string:<br>
`./get_poc.sh -v 1.2.8 packagekit`<br>

With `-v`, pass `-s`/`--since` to only consider CVEs published within a given window — `30d`, `2y`, or `all` for no limit (**default: `30d`**):<br>
`./get_poc.sh -v 1.2.8 -s 2y packagekit`<br>

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

## scan_packages.sh

Batch version of the `-v` lookup: feed it a list of installed packages and versions, and it reports every matching CVE per package — not just ones with a PoC — flagging which ones do have a public PoC on GitHub.

**Usage:**<br>
`./scan_packages.sh [-f|--file FILE] [-o|--output CSV_FILE] [-d|--delay SECONDS] [-x|--exclude REGEX] [-X|--exclude-file FILE] [-s|--since WHEN] [-p|--poc-only]`<br>

Reads `PACKAGE VERSION` pairs, one per line, from `FILE` or stdin:<br>
```
# Debian/Ubuntu
dpkg-query -W -f='${Package} ${Version}\n' | awk '{v=$2; sub(/^[0-9]+:/,"",v); sub(/-[^-]*$/,"",v); print $1, v}' | ./scan_packages.sh

# RedHat/Fedora
rpm -qa --qf '%{NAME} %{VERSION}\n' | ./scan_packages.sh
```

- `-o`/`--output FILE` also writes a CSV report (`package,version,cve,poc_found,poc_repo,poc_stars,poc_url`). `poc_found` is `yes`, `no`, or `error` (the GitHub lookup for that CVE failed — rate-limited or network error — so it's unverified, not confirmed absent).
- `-p`/`--poc-only` only reports CVEs that have a public PoC (skips the rest).
- `-x`/`--exclude REGEX` skips packages whose name matches an extended regex — repeatable, to cut down the API load on a big install list. E.g. to skip libraries and Python packages:<br>
  `... | ./scan_packages.sh -x '^lib' -x '^python[23]?-'` (Debian-style `lib*` prefix)<br>
  `... | ./scan_packages.sh -x '^lib' -x '-libs$' -x '^python[23]?-'` (RedHat mixes `lib*` prefix and `-libs` suffix, e.g. `openssl-libs`)
- `-X`/`--exclude-file FILE` is the same thing but reads patterns from a file, one regex per line — blank lines and lines starting with `#` are ignored, and it combines with any `-x` also given:<br>
  ```
  # excludes.txt
  ^lib
  ^python[23]?-
  -doc$
  -dbg(sym)?$
  ^perl-
  ```
  `... | ./scan_packages.sh -X excludes.txt`
- `-s`/`--since WHEN` only reports CVEs published within a given window — `30d`, `2y`, or `all` for no limit (**default: `30d`**). Also cuts down noise/load, since most installed packages' CVEs (if any) are old news.
- `-d`/`--delay SECONDS` overrides the pause between NVD/GitHub API calls. Scanning a full package list means one NVD request per package plus one GitHub request per CVE found, so this respects both services' unauthenticated rate limits by default (and paces faster automatically once `GITHUB_TOKEN`/`NVD_API_KEY` are set) — expect a full system scan to take a while without both tokens.

`get_poc.sh` and `scan_packages.sh` share their NVD/GitHub lookup logic via `poc_lib.sh` — keep all three files together.

**Caveat:** version matching compares your installed (upstream) version string against NVD's stated CPE ranges for that exact product name — it doesn't know about distro security backports. Debian/Ubuntu/RHEL frequently patch CVEs into a package without bumping its upstream version (only the distro revision suffix, which `scan_packages.sh`'s example pipelines already strip), so a flagged CVE may already be fixed in your actual installed package. Cross-check anything that matters against your distro's own security tracker ([Debian](https://security-tracker.debian.org/tracker/), [Ubuntu](https://ubuntu.com/security/cve)) before acting on it.

## poc-finder

A browser-based port of this same search, no local dependencies needed, is at [pwnmi.com/tools/poc-finder](https://pwnmi.com/tools/poc-finder/).
