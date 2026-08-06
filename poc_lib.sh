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

    while IFS=$'\x1f' read -r cve pub start_inc start_exc end_inc end_exc exact vendor prod; do
        [[ -z "$cve" ]] && continue
        [[ -n "$since" && -n "$pub" && "$pub" < "$since" ]] && continue
        if [[ -z "$exact_cve" ]]; then
            local hay="${vendor,,}${prod,,}"
            [[ "$hay" == *"$token"* ]] || continue
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
