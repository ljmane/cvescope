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
ENCODED_QUERY="${QUERY// /+}+PoC"
API_URL="https://api.github.com/search/repositories?q=${ENCODED_QUERY}&sort=stars&order=desc&per_page=30"

AUTH_ARGS=()
[[ -n "${GITHUB_TOKEN:-}" ]] && AUTH_ARGS=(-H "Authorization: token $GITHUB_TOKEN")

echo "Searching GitHub for: $QUERY PoC"

RESULTS=$(curl -sf -H "Accept: application/vnd.github.v3+json" \
    "${AUTH_ARGS[@]}" "$API_URL") || {
    echo "Error: GitHub API request failed. Check your connection or GITHUB_TOKEN."
    exit 1
}

TOTAL=$(echo "$RESULTS" | jq '.total_count')
COUNT=$(echo "$RESULTS" | jq '.items | length')

if [[ "$COUNT" -eq 0 ]]; then
    echo "No results found for: $QUERY"
    exit 0
fi

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
