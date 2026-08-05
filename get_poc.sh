#!/bin/bash

set -uo pipefail

usage() {
    echo "Usage: $0 <CVE-ID or search query>"
    echo "  Set GITHUB_TOKEN env var for higher API rate limits (30 req/min vs 10)"
    exit 1
}

check_deps() {
    local missing=()
    for cmd in curl jq git; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: missing required tools: ${missing[*]}"
        exit 1
    fi
}

[[ $# -eq 0 ]] && usage
check_deps

QUERY="${*}"

AUTH_ARGS=()
[[ -n "${GITHUB_TOKEN:-}" ]] && AUTH_ARGS=(-H "Authorization: token $GITHUB_TOKEN")

# Search GitHub repos for a raw (space-joined) query string.
gh_search() {
    local encoded="${1// /+}"
    curl -sf -H "Accept: application/vnd.github.v3+json" \
        "${AUTH_ARGS[@]}" \
        "https://api.github.com/search/repositories?q=${encoded}&sort=stars&order=desc&per_page=30"
}

is_cve_id() {
    [[ "$1" =~ ^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,}$ ]]
}

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

COUNT=$(echo "$RESULTS" | jq '.items | length')

# For a generic query (not a CVE ID) that turned up nothing, look for CVE IDs
# mentioned alongside it, then search each of those CVE IDs directly.
if [[ "$COUNT" -eq 0 ]] && ! is_cve_id "$QUERY"; then
    echo "No direct PoC hits for '$QUERY' — looking for related CVE IDs..."
    DISCOVERY=$(gh_search "${QUERY} CVE") || DISCOVERY=""

    CVE_IDS=()
    if [[ -n "$DISCOVERY" ]]; then
        while IFS= read -r cve; do
            [[ -n "$cve" ]] && CVE_IDS+=("$cve")
        done < <(echo "$DISCOVERY" | jq -r '.items[] | (.full_name + " " + (.description // ""))' \
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

    COUNT=$(echo "$RESULTS" | jq '.items | length')
fi

if [[ "$COUNT" -eq 0 ]]; then
    echo "No results found for: $QUERY"
    exit 0
fi

TOTAL=$(echo "$RESULTS" | jq '.total_count')

echo "Found $TOTAL total results — showing top $COUNT by stars"
echo "(enter q at any prompt to quit)"

NUM=0
while [[ $NUM -lt $COUNT ]]; do
    ITEM=$(echo "$RESULTS" | jq ".items[$NUM]")
    REPO=$(echo "$ITEM" | jq -r '.full_name')
    DESC=$(echo "$ITEM" | jq -r '.description // "(no description)"')
    STARS=$(echo "$ITEM" | jq -r '.stargazers_count')
    UPDATED=$(echo "$ITEM" | jq -r '.updated_at[:10]')

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
