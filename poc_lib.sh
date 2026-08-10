# Shared NVD/GitHub helpers for get_poc.sh and scan_packages.sh.
# Meant to be sourced (`. "$(dirname "$0")/poc_lib.sh"`), not executed directly.

poc_lib_init_auth() {
    AUTH_ARGS=()
    [[ -n "${GITHUB_TOKEN:-}" ]] && AUTH_ARGS=(-H "Authorization: token $GITHUB_TOKEN")

    NVD_AUTH_ARGS=()
    [[ -n "${NVD_API_KEY:-}" ]] && NVD_AUTH_ARGS=(-H "apiKey: $NVD_API_KEY")
}

check_deps() {
    local missing=()
    for cmd in curl jq git sort; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: missing required tools: ${missing[*]}" >&2
        exit 1
    fi
}

# Search GitHub repos for a raw (space-joined) query string. Uses $LIMIT for per_page.
gh_search() {
    local encoded="${1// /+}"
    curl -sf -H "Accept: application/vnd.github.v3+json" \
        "${AUTH_ARGS[@]}" \
        "https://api.github.com/search/repositories?q=${encoded}&sort=stars&order=desc&per_page=${LIMIT}"
}

is_cve_id() {
    [[ "$1" =~ ^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,}$ ]]
}

nvd_lookup_by_cve() {
    curl -sf -H "Accept: application/json" "${NVD_AUTH_ARGS[@]}" \
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$1"
}

nvd_lookup_by_keyword() {
    local encoded="${1// /%20}"
    curl -sf -H "Accept: application/json" "${NVD_AUTH_ARGS[@]}" \
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encoded}&resultsPerPage=100"
}

# Batch-fetch EPSS scores (FIRST.org's Exploit Prediction Scoring System —
# probability of real-world exploitation in the next 30 days, 0-1) for a
# comma-separated list of CVE IDs. Prints "CVE score" lines; CVEs with no
# EPSS data yet (e.g. very new) are simply absent from the output.
epss_lookup() {
    curl -sf "https://api.first.org/data/v1/epss?cve=$1" \
        | jq -r '.data[]? | "\(.cve) \(.epss)"'
}

# Convert a "<N>d" (days), "<N>y" (years), or "all"/"0" (no limit) value into
# an ISO cutoff date (YYYY-MM-DD), or print nothing for "all"/"0". Prints
# nothing and returns 1 on an unrecognized format.
since_to_cutoff() {
    local val="$1"
    [[ "$val" == "all" || "$val" == "0" ]] && return 0
    [[ "$val" =~ ^([0-9]+)([dy])$ ]] || return 1
    local n="${BASH_REMATCH[1]}" unit="${BASH_REMATCH[2]}"
    if [[ "$unit" == "d" ]]; then
        date -d "-${n} days" +%Y-%m-%d
    else
        date -d "-${n} years" +%Y-%m-%d
    fi
}

# Dotted-version comparisons (a <= b, a < b, etc.) via sort -V.
version_le() {
    [[ "$1" == "$2" ]] && return 0
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}
version_lt() { [[ "$1" != "$2" ]] && version_le "$1" "$2"; }
version_gt() { version_lt "$2" "$1"; }
version_ge() { version_le "$2" "$1"; }

# Does TARGET fall within an NVD CPE match's version range (or equal its
# exact pinned version, when no range bounds are given)?
cpe_match_version() {
    local target="$1" start_inc="$2" start_exc="$3" end_inc="$4" end_exc="$5" exact="$6"
    [[ -n "$start_inc" ]] && { version_ge "$target" "$start_inc" || return 1; }
    [[ -n "$start_exc" ]] && { version_gt "$target" "$start_exc" || return 1; }
    [[ -n "$end_inc" ]] && { version_le "$target" "$end_inc" || return 1; }
    [[ -n "$end_exc" ]] && { version_lt "$target" "$end_exc" || return 1; }
    if [[ -z "$start_inc$start_exc$end_inc$end_exc" ]]; then
        [[ -n "$exact" && "$exact" != "*" && "$exact" == "$target" ]] || return 1
    fi
    return 0
}

# Look up CVEs for a product (or a specific CVE ID) via NVD, and print the
# IDs of those whose affected CPE range actually includes $version. If
# $since (an ISO cutoff date, YYYY-MM-DD) is given, CVEs published before it
# are skipped. Prints every remaining match found (caller decides whether to
# cap the count).
discover_version_cves() {
    local product="$1" version="$2" since="${3:-}" resp exact_cve=""
    if is_cve_id "$product"; then
        resp=$(nvd_lookup_by_cve "$product") || return 1
        # Already resolved to one specific CVE — no product name to filter on.
        exact_cve="$product"
    else
        resp=$(nvd_lookup_by_keyword "$product") || return 1
    fi

    local token="${product%% *}"
    token="${token,,}"
    token="${token//-/_}"

    while IFS=$'\x1f' read -r cve pub start_inc start_exc end_inc end_exc exact vendor prod; do
        [[ -z "$cve" ]] && continue
        [[ -n "$since" && -n "$pub" && "$pub" < "$since" ]] && continue
        if [[ -z "$exact_cve" ]]; then
            # Exact match on the CPE product field only — substring/vendor
            # matching lets unrelated products through (e.g. "wget" matching
            # a CVE whose CPE product is actually "wget2").
            local prod_norm="${prod,,}"
            prod_norm="${prod_norm//-/_}"
            [[ "$prod_norm" == "$token" ]] || continue
        fi
        cpe_match_version "$version" "$start_inc" "$start_exc" "$end_inc" "$end_exc" "$exact" \
            && printf '%s\n' "$cve"
    done < <(jq -r '
        .vulnerabilities[]? | .cve as $c |
        ($c.configurations // [])[] | .nodes[]? | .cpeMatch[]? | select(.vulnerable == true) |
        [$c.id,
         ($c.published // ""),
         (.versionStartIncluding // ""),
         (.versionStartExcluding // ""),
         (.versionEndIncluding // ""),
         (.versionEndExcluding // ""),
         (.criteria | split(":")[5] // ""),
         (.criteria | split(":")[3] // ""),
         (.criteria | split(":")[4] // "")
        ] | join("")' <<< "$resp")
    return 0
}

cache_default_dir() {
    echo "${XDG_CACHE_HOME:-$HOME/.cache}/cvescope"
}

# Build a cache filename from arbitrary key parts (package, version, and
# whatever scan settings affect the result, e.g. since/min-epss) so a
# changed setting naturally misses the cache instead of returning a stale
# answer computed under different rules.
cache_key() {
    printf '%s' "$*" | sha1sum | awk '{print $1}'
}

# Print the cached JSON blob for $key if $dir/$key.json exists and is no
# older than $ttl_seconds. Returns 1 (prints nothing) on a miss.
cache_get() {
    local dir="$1" key="$2" ttl="$3" file="$1/$2.json" ts now
    [[ -f "$file" ]] || return 1
    ts=$(jq -r '.timestamp // empty' "$file" 2>/dev/null) || return 1
    [[ -n "$ts" ]] || return 1
    now=$(date +%s)
    [[ $((now - ts)) -le "$ttl" ]] || return 1
    cat "$file"
}

# Store $cves_json (a jq array of result objects) under $key, stamped with
# the current time.
cache_set() {
    local dir="$1" key="$2" cves_json="$3"
    mkdir -p "$dir"
    jq -n --argjson ts "$(date +%s)" --argjson cves "$cves_json" \
        '{timestamp: $ts, cves: $cves}' > "$dir/$key.json"
}

# Like gh_search, but for a specific CVE ID: GitHub's search treats the
# query as a loose token match, so searching "CVE-2021-3448" also returns
# repos named e.g. "CVE-2021-34486" (same digit prefix, different CVE
# entirely). Filters results down to ones whose name/description actually
# contain the exact CVE ID (not immediately followed by another digit).
gh_search_cve() {
    local cve="$1" resp
    resp=$(gh_search "$cve") || return 1
    jq --arg cve "$cve" '
        .items = [.items[] | select(
            ((.full_name // "") | test("(?i)" + $cve + "($|[^0-9])")) or
            ((.description // "") | test("(?i)" + $cve + "($|[^0-9])"))
        )]
        | .total_count = (.items | length)
    ' <<< "$resp"
}
