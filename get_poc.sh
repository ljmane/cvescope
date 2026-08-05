#!/bin/bash

set -uo pipefail

usage() {
    echo "Usage: $0 [-v|--version VERSION] [-l|--limit N] <CVE-ID or search query>"
    echo "  -v, --version VERSION   Only show CVEs whose affected range includes VERSION"
    echo "                          (looked up via NVD; query is treated as a product name)"
    echo "  -l, --limit N           Show at most N results (default 30, max 100)"
    echo "  Set GITHUB_TOKEN env var for higher GitHub API rate limits (30 req/min vs 10)"
    echo "  Set NVD_API_KEY env var for higher NVD API rate limits (50 req/30s vs 5, used with -v)"
    exit 1
}

check_deps() {
    local missing=()
    for cmd in curl jq git sort; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: missing required tools: ${missing[*]}"
        exit 1
    fi
}

[[ $# -eq 0 ]] && usage
check_deps

VERSION=""
LIMIT=30
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--version)
            [[ $# -lt 2 ]] && usage
            VERSION="$2"
            shift 2
            ;;
        -l|--limit)
            [[ $# -lt 2 ]] && usage
            LIMIT="$2"
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done
QUERY="${ARGS[*]}"
[[ -z "$QUERY" ]] && usage

[[ "$LIMIT" =~ ^[0-9]+$ && "$LIMIT" -gt 0 ]] || usage
[[ "$LIMIT" -gt 100 ]] && LIMIT=100

AUTH_ARGS=()
[[ -n "${GITHUB_TOKEN:-}" ]] && AUTH_ARGS=(-H "Authorization: token $GITHUB_TOKEN")

NVD_AUTH_ARGS=()
[[ -n "${NVD_API_KEY:-}" ]] && NVD_AUTH_ARGS=(-H "apiKey: $NVD_API_KEY")

# Search GitHub repos for a raw (space-joined) query string.
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
# IDs of those whose affected CPE range actually includes $version.
discover_version_cves() {
    local product="$1" version="$2" resp exact_cve=""
    if is_cve_id "$product"; then
        resp=$(nvd_lookup_by_cve "$product") || return 1
        # Already resolved to one specific CVE — no product name to filter on.
        exact_cve="$product"
    else
        resp=$(nvd_lookup_by_keyword "$product") || return 1
    fi

    local token="${product%% *}"
    token="${token,,}"

    while IFS=$'\x1f' read -r cve start_inc start_exc end_inc end_exc exact vendor prod; do
        [[ -z "$cve" ]] && continue
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

if [[ -n "$VERSION" ]]; then
    echo "Looking up CVEs for '$QUERY' affecting version $VERSION via NVD..."
    DISCOVERY=$(discover_version_cves "$QUERY" "$VERSION") || {
        echo "Error: NVD API request failed. Check your connection or NVD_API_KEY."
        exit 1
    }

    mapfile -t CVE_IDS < <(printf '%s\n' "$DISCOVERY" | awk 'NF && !seen[$0]++' | head -n 5)

    if [[ ${#CVE_IDS[@]} -eq 0 ]]; then
        echo "No CVEs found for '$QUERY' affecting version $VERSION"
        exit 0
    fi

    echo "Matching CVE(s): ${CVE_IDS[*]}"

    RESPONSES=()
    for cve in "${CVE_IDS[@]}"; do
        RESP=$(gh_search "$cve") && RESPONSES+=("$RESP")
    done

    if [[ ${#RESPONSES[@]} -eq 0 ]]; then
        echo "No results found for: $QUERY $VERSION"
        exit 0
    fi

    RESULTS=$(printf '%s\n' "${RESPONSES[@]}" | jq -s --argjson limit "$LIMIT" '
        {items: ([.[].items[]] | unique_by(.full_name) | sort_by(-.stargazers_count) | .[0:$limit])}
        | .total_count = (.items | length)')
    COUNT=$(jq '.items | length' <<< "$RESULTS")
else
    # A bare CVE ID is already specific enough on its own — forcing the literal
    # word "PoC" into the query excludes real PoC repos whose name/description
    # never spell out that word (e.g. a repo just named "CVE-2026-41651").
    if is_cve_id "$QUERY"; then
        SEARCH_TERM="$QUERY"
    else
        SEARCH_TERM="${QUERY} PoC"
    fi

    echo "Searching GitHub for: $SEARCH_TERM"

    RESULTS=$(gh_search "$SEARCH_TERM") || {
        echo "Error: GitHub API request failed. Check your connection or GITHUB_TOKEN."
        exit 1
    }

    COUNT=$(jq '.items | length' <<< "$RESULTS")

    # For a generic query (not a CVE ID) that turned up nothing, look for CVE IDs
    # mentioned alongside it, then search each of those CVE IDs directly.
    if [[ "$COUNT" -eq 0 ]] && ! is_cve_id "$QUERY"; then
        echo "No direct PoC hits for '$QUERY' — looking for related CVE IDs..."
        DISCOVERY=$(gh_search "${QUERY} CVE") || DISCOVERY=""

        CVE_IDS=()
        if [[ -n "$DISCOVERY" ]]; then
            while IFS= read -r cve; do
                [[ -n "$cve" ]] && CVE_IDS+=("$cve")
            done < <(jq -r '.items[] | (.full_name + " " + (.description // ""))' <<< "$DISCOVERY" \
                | grep -oiE 'CVE-[0-9]{4}-[0-9]{4,}' | tr '[:lower:]' '[:upper:]' | awk '!seen[$0]++' | head -n 5)
        fi

        if [[ ${#CVE_IDS[@]} -eq 0 ]]; then
            echo "No results found for: $QUERY"
            exit 0
        fi

        echo "Found related CVE(s): ${CVE_IDS[*]}"

        RESPONSES=()
        for cve in "${CVE_IDS[@]}"; do
            RESP=$(gh_search "$cve") && RESPONSES+=("$RESP")
        done

        if [[ ${#RESPONSES[@]} -gt 0 ]]; then
            RESULTS=$(printf '%s\n' "${RESPONSES[@]}" | jq -s '
                {items: ([.[].items[]] | unique_by(.full_name) | sort_by(-.stargazers_count) | .[0:30])}
                | .total_count = (.items | length)')
        fi

        COUNT=$(jq '.items | length' <<< "$RESULTS")
    fi
fi

if [[ "$COUNT" -eq 0 ]]; then
    echo "No results found for: $QUERY"
    exit 0
fi

TOTAL=$(jq '.total_count' <<< "$RESULTS")

echo "Found $TOTAL total results — showing top $COUNT by stars"
echo "(enter q at any prompt to quit)"

NUM=0
while [[ $NUM -lt $COUNT ]]; do
    ITEM=$(jq ".items[$NUM]" <<< "$RESULTS")
    REPO=$(jq -r '.full_name' <<< "$ITEM")
    DESC=$(jq -r '.description // "(no description)"' <<< "$ITEM")
    STARS=$(jq -r '.stargazers_count' <<< "$ITEM")
    UPDATED=$(jq -r '.updated_at[:10]' <<< "$ITEM")

    echo ""
    echo "[$((NUM + 1))/$COUNT]  $REPO  (★ $STARS | updated $UPDATED)"
    echo "  https://github.com/$REPO"
    echo "  $DESC"

    read -rp "Clone? [y/n/q] " ANS
    case "${ANS,,}" in
        y|yes)
            git clone "https://github.com/$REPO.git"
            read -rp "Continue browsing? [y/n] " CONT
            [[ "${CONT,,}" =~ ^y ]] || break
            NUM=$((NUM + 1))
            ;;
        q|quit|exit)
            echo "Exiting."
            break
            ;;
        n|no|"")
            NUM=$((NUM + 1))
            ;;
        *)
            echo "Please enter y, n, or q"
            ;;
    esac
done
