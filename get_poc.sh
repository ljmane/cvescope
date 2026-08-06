#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=poc_lib.sh
source "$SCRIPT_DIR/poc_lib.sh"

usage() {
    echo "Usage: $0 [-v|--version VERSION] [-s|--since WHEN] [-l|--limit N] <CVE-ID or search query>"
    echo "  -v, --version VERSION   Only show CVEs whose affected range includes VERSION"
    echo "                          (looked up via NVD; query is treated as a product name)"
    echo "  -s, --since WHEN        With -v: only CVEs published in the last WHEN"
    echo "                          (e.g. 30d, 2y; or 'all' for no limit — default 30d)"
    echo "  -l, --limit N           Show at most N results (default 30, max 100)"
    echo "  Set GITHUB_TOKEN env var for higher GitHub API rate limits (30 req/min vs 10)"
    echo "  Set NVD_API_KEY env var for higher NVD API rate limits (50 req/30s vs 5, used with -v)"
    exit 1
}

[[ $# -eq 0 ]] && usage
check_deps

VERSION=""
SINCE_VALUE="30d"
LIMIT=30
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--version)
            [[ $# -lt 2 ]] && usage
            VERSION="$2"
            shift 2
            ;;
        -s|--since)
            [[ $# -lt 2 ]] && usage
            SINCE_VALUE="$2"
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

poc_lib_init_auth

SINCE_CUTOFF=$(since_to_cutoff "$SINCE_VALUE") || usage

if [[ -n "$VERSION" ]]; then
    if [[ -n "$SINCE_CUTOFF" ]]; then
        echo "Looking up CVEs for '$QUERY' affecting version $VERSION, published in the last $SINCE_VALUE, via NVD..."
    else
        echo "Looking up CVEs for '$QUERY' affecting version $VERSION via NVD..."
    fi
    DISCOVERY=$(discover_version_cves "$QUERY" "$VERSION" "$SINCE_CUTOFF") || {
        echo "Error: NVD API request failed. Check your connection or NVD_API_KEY."
        exit 1
    }

    mapfile -t CVE_IDS < <(printf '%s\n' "$DISCOVERY" | awk 'NF && !seen[$0]++' | head -n 5)

    if [[ ${#CVE_IDS[@]} -eq 0 ]]; then
        echo "No CVEs found for '$QUERY' affecting version $VERSION${SINCE_CUTOFF:+ published in the last $SINCE_VALUE}"
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
            RESULTS=$(printf '%s\n' "${RESPONSES[@]}" | jq -s --argjson limit "$LIMIT" '
                {items: ([.[].items[]] | unique_by(.full_name) | sort_by(-.stargazers_count) | .[0:$limit])}
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
