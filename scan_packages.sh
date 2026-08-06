#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=poc_lib.sh
source "$SCRIPT_DIR/poc_lib.sh"

usage() {
    echo "Usage: $0 [-f|--file FILE] [-o|--output CSV_FILE] [-d|--delay SECONDS] [-x|--exclude REGEX] [-s|--since WHEN] [-p|--poc-only]"
    echo ""
    echo "Reads 'PACKAGE VERSION' pairs, one per line, from FILE or stdin, e.g.:"
    echo "  dpkg-query -W -f='\${Package} \${Version}\n' | sed -E 's/^([^ ]+) [0-9]+://;s/-[^ -]*\$//' | $0"
    echo "  rpm -qa --qf '%{NAME} %{VERSION}\n' | $0"
    echo ""
    echo "For each package, looks up matching CVEs on NVD (filtered to ones whose CPE"
    echo "version range actually includes the given version) and reports every one —"
    echo "flagging which have a public PoC found on GitHub."
    echo ""
    echo "  -f, --file FILE     Read package/version pairs from FILE instead of stdin"
    echo "  -o, --output FILE   Also write a CSV report to FILE"
    echo "  -d, --delay SECONDS Override the delay between NVD/GitHub API calls"
    echo "  -x, --exclude REGEX Skip packages whose name matches REGEX (extended regex,"
    echo "                      repeatable). E.g. -x '^lib' -x '^python3?-'"
    echo "  -s, --since WHEN    Only report CVEs published in the last WHEN"
    echo "                      (e.g. 30d, 2y; or 'all' for no limit — default 30d)"
    echo "  -p, --poc-only      Only report CVEs that have a public PoC"
    echo "  Set GITHUB_TOKEN / NVD_API_KEY env vars for higher rate limits and faster default pacing"
    exit 1
}

check_deps

FILE=""
OUTPUT=""
DELAY=""
POC_ONLY=0
EXCLUDES=()
SINCE_VALUE="30d"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            [[ $# -lt 2 ]] && usage
            FILE="$2"
            shift 2
            ;;
        -o|--output)
            [[ $# -lt 2 ]] && usage
            OUTPUT="$2"
            shift 2
            ;;
        -d|--delay)
            [[ $# -lt 2 ]] && usage
            DELAY="$2"
            shift 2
            ;;
        -x|--exclude)
            [[ $# -lt 2 ]] && usage
            EXCLUDES+=("$2")
            shift 2
            ;;
        -s|--since)
            [[ $# -lt 2 ]] && usage
            SINCE_VALUE="$2"
            shift 2
            ;;
        -p|--poc-only)
            POC_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

if [[ -n "$DELAY" ]]; then
    [[ "$DELAY" =~ ^[0-9]+(\.[0-9]+)?$ ]] || usage
fi

EXCLUDE_RE=""
if [[ ${#EXCLUDES[@]} -gt 0 ]]; then
    EXCLUDE_RE=$(IFS='|'; echo "${EXCLUDES[*]}")
fi

if [[ -n "$FILE" && ! -r "$FILE" ]]; then
    echo "Error: cannot read file: $FILE" >&2
    exit 1
fi

poc_lib_init_auth

SINCE_CUTOFF=$(since_to_cutoff "$SINCE_VALUE") || usage

# Only need the single top PoC hit per CVE.
LIMIT=1

# Space out API calls to stay under each service's unauthenticated rate limit
# (NVD: 5 req/30s, GitHub: 10 req/min); go faster automatically if the
# corresponding token/key is set. -d/--delay overrides both.
NVD_DELAY=6.5
[[ -n "${NVD_API_KEY:-}" ]] && NVD_DELAY=0.7
GH_DELAY=6.5
[[ -n "${GITHUB_TOKEN:-}" ]] && GH_DELAY=2.1
if [[ -n "$DELAY" ]]; then
    NVD_DELAY="$DELAY"
    GH_DELAY="$DELAY"
fi

if [[ -n "$FILE" ]]; then
    mapfile -t LINES < "$FILE"
else
    mapfile -t LINES
fi
TOTAL=${#LINES[@]}

PRE_EXCLUDED=0
if [[ -n "$EXCLUDE_RE" ]]; then
    for line in "${LINES[@]}"; do
        read -r pkg _ <<< "$line"
        [[ -n "$pkg" && "$pkg" =~ $EXCLUDE_RE ]] && PRE_EXCLUDED=$((PRE_EXCLUDED + 1))
    done
fi

if [[ -n "$OUTPUT" ]]; then
    printf '"package","version","cve","poc_found","poc_repo","poc_stars","poc_url"\n' > "$OUTPUT"
fi

SINCE_LABEL="all time"
[[ -n "$SINCE_CUTOFF" ]] && SINCE_LABEL="last $SINCE_VALUE (published >= $SINCE_CUTOFF)"
SCAN_MSG="Scanning $TOTAL line(s)"
[[ "$PRE_EXCLUDED" -gt 0 ]] && SCAN_MSG="$SCAN_MSG ($PRE_EXCLUDED excluded by -x, $((TOTAL - PRE_EXCLUDED)) to check)"
echo "$SCAN_MSG (NVD delay: ${NVD_DELAY}s, GitHub delay: ${GH_DELAY}s, since: $SINCE_LABEL)..." >&2

PKG_COUNT=0
EXCLUDED_COUNT=0
AFFECTED_COUNT=0
CVE_COUNT=0
POC_COUNT=0

i=0
for line in "${LINES[@]}"; do
    i=$((i + 1))
    read -r pkg ver _ <<< "$line"
    [[ -z "$pkg" || -z "$ver" ]] && continue

    printf '\r\033[K[%d/%d] %s %s' "$i" "$TOTAL" "$pkg" "$ver" >&2

    if [[ -n "$EXCLUDE_RE" && "$pkg" =~ $EXCLUDE_RE ]]; then
        EXCLUDED_COUNT=$((EXCLUDED_COUNT + 1))
        continue
    fi
    PKG_COUNT=$((PKG_COUNT + 1))

    DISCOVERY=$(discover_version_cves "$pkg" "$ver" "$SINCE_CUTOFF")
    NVD_STATUS=$?
    sleep "$NVD_DELAY"

    if [[ $NVD_STATUS -ne 0 ]]; then
        echo "" >&2
        echo "  [$pkg $ver] NVD lookup failed (rate-limited or network error) — skipping" >&2
        continue
    fi

    mapfile -t CVES < <(printf '%s\n' "$DISCOVERY" | awk 'NF && !seen[$0]++')
    [[ ${#CVES[@]} -eq 0 ]] && continue

    AFFECTED_COUNT=$((AFFECTED_COUNT + 1))
    echo "" >&2
    echo "[$i/$TOTAL] $pkg $ver"

    for cve in "${CVES[@]}"; do
        CVE_COUNT=$((CVE_COUNT + 1))

        RESP=$(gh_search "$cve")
        GH_STATUS=$?
        sleep "$GH_DELAY"

        POC_FOUND="no"
        REPO=""
        STARS=""
        URL=""
        TOTAL_POCS=0
        if [[ $GH_STATUS -eq 0 ]]; then
            TOTAL_POCS=$(jq '.total_count' <<< "$RESP")
            if [[ "$TOTAL_POCS" -gt 0 ]]; then
                POC_FOUND="yes"
                POC_COUNT=$((POC_COUNT + 1))
                REPO=$(jq -r '.items[0].full_name' <<< "$RESP")
                STARS=$(jq -r '.items[0].stargazers_count' <<< "$RESP")
                URL="https://github.com/$REPO"
            fi
        fi

        if [[ "$POC_ONLY" -eq 1 && "$POC_FOUND" == "no" ]]; then
            continue
        fi

        if [[ "$POC_FOUND" == "yes" ]]; then
            echo "  $cve  PoC: YES  (${TOTAL_POCS} found, top: $REPO ★$STARS)  $URL"
        else
            echo "  $cve  PoC: no"
        fi

        if [[ -n "$OUTPUT" ]]; then
            printf '"%s","%s","%s","%s","%s","%s","%s"\n' \
                "$pkg" "$ver" "$cve" "$POC_FOUND" "$REPO" "$STARS" "$URL" >> "$OUTPUT"
        fi
    done
done

printf '\r\033[K' >&2
echo ""
echo "Summary: $PKG_COUNT package(s) scanned ($EXCLUDED_COUNT excluded), $AFFECTED_COUNT affected, $CVE_COUNT CVE(s) found, $POC_COUNT with a public PoC."
[[ -n "$OUTPUT" ]] && echo "CSV report written to $OUTPUT"

exit 0
