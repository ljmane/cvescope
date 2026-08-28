#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=poc_lib.sh
source "$SCRIPT_DIR/poc_lib.sh"

usage() {
    echo "Usage: $0 [-f|--file FILE] [-o|--output CSV_FILE] [-d|--delay SECONDS] [-x|--exclude REGEX] [-X|--exclude-file FILE] [-s|--since WHEN] [-p|--poc-only] [--min-epss N] [--no-cache] [--cache-ttl HOURS] [--stale-out FILE]"
    echo ""
    echo "Reads 'PACKAGE VERSION' pairs, one per line, from FILE or stdin, e.g.:"
    echo "  dpkg-query -W -f='\${Package} \${Version}\n' | sed -E 's/^([^ ]+) [0-9]+://;s/-[^ -]*\$//' | $0"
    echo "  rpm -qa --qf '%{NAME} %{VERSION}\n' | $0"
    echo ""
    echo "For each package, looks up matching CVEs on NVD (filtered to ones whose CPE"
    echo "version range actually includes the given version) and reports every one —"
    echo "flagging which have a public PoC found on GitHub."
    echo ""
    echo "  -f, --file FILE       Read package/version pairs from FILE instead of stdin"
    echo "  -o, --output FILE     Also write a CSV report to FILE"
    echo "  -d, --delay SECONDS   Override the delay between NVD/GitHub/EPSS API calls"
    echo "  -x, --exclude REGEX   Skip packages whose name matches REGEX (extended regex,"
    echo "                        repeatable). E.g. -x '^lib' -x '^python3?-'"
    echo "  -X, --exclude-file FILE  Same as -x, one regex per line. Blank lines and lines"
    echo "                        starting with # are ignored. Combines with any -x given."
    echo "  -s, --since WHEN      Only report CVEs published in the last WHEN"
    echo "                        (e.g. 30d, 2y; or 'all' for no limit — default 30d)"
    echo "  -p, --poc-only        Only report CVEs that have a public PoC"
    echo "  --min-epss N          Only run the GitHub PoC check for CVEs with an EPSS score"
    echo "                        (FIRST.org's predicted REMOTE exploitation probability,"
    echo "                        0-1) >= N. Lower-scored CVEs are still reported, just not"
    echo "                        GitHub-checked (shown as PoC: SKIPPED). CVEs with no EPSS"
    echo "                        data yet are always checked. Off by default. CAUTION: EPSS"
    echo "                        is trained on internet-facing exploitation telemetry, so"
    echo "                        local privesc CVEs score low even with a real, working PoC"
    echo "                        — avoid this flag if that's what you're hunting for."
    echo "  --no-cache            Don't read or write the local results cache"
    echo "  --cache-ttl HOURS     How long a cached package result stays fresh (default 24)"
    echo "  --stale-out FILE      Write 'PACKAGE VERSION' lines for packages that have a real"
    echo "                        CVE match outside your -s window to FILE — same format this"
    echo "                        script reads, so you can re-check just those with a wider"
    echo "                        window instead of re-running -s all against everything:"
    echo "                        $0 -f packages --stale-out stale.txt"
    echo "                        $0 -f stale.txt -s all"
    echo "  Set GITHUB_TOKEN / NVD_API_KEY env vars for higher rate limits and faster default pacing"
    echo "  Set CVESCOPE_CACHE_DIR to override the cache location (default ~/.cache/cvescope)"
    exit 1
}

check_deps

FILE=""
OUTPUT=""
DELAY=""
POC_ONLY=0
EXCLUDES=()
EXCLUDE_FILE=""
SINCE_VALUE="30d"
MIN_EPSS=""
NO_CACHE=0
CACHE_TTL_HOURS=24
STALE_OUT=""
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
        -X|--exclude-file)
            [[ $# -lt 2 ]] && usage
            EXCLUDE_FILE="$2"
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
        --min-epss)
            [[ $# -lt 2 ]] && usage
            MIN_EPSS="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE=1
            shift
            ;;
        --cache-ttl)
            [[ $# -lt 2 ]] && usage
            CACHE_TTL_HOURS="$2"
            shift 2
            ;;
        --stale-out)
            [[ $# -lt 2 ]] && usage
            STALE_OUT="$2"
            shift 2
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

if [[ -n "$MIN_EPSS" ]]; then
    [[ "$MIN_EPSS" =~ ^0(\.[0-9]+)?$|^1(\.0+)?$ ]] || usage
fi

[[ "$CACHE_TTL_HOURS" =~ ^[0-9]+$ ]] || usage
CACHE_TTL_SECONDS=$((CACHE_TTL_HOURS * 3600))

if [[ "$NO_CACHE" -eq 0 ]] && ! command -v sqlite3 &>/dev/null; then
    echo "Error: sqlite3 is required for the results cache. Install it, or pass --no-cache to skip caching." >&2
    exit 1
fi

if [[ -n "$EXCLUDE_FILE" ]]; then
    if [[ ! -r "$EXCLUDE_FILE" ]]; then
        echo "Error: cannot read exclude file: $EXCLUDE_FILE" >&2
        exit 1
    fi
    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
        pattern="${pattern#"${pattern%%[![:space:]]*}"}"
        pattern="${pattern%"${pattern##*[![:space:]]}"}"
        [[ -z "$pattern" || "$pattern" == \#* ]] && continue
        EXCLUDES+=("$pattern")
    done < "$EXCLUDE_FILE"
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

if [[ -n "$MIN_EPSS" ]]; then
    echo "Warning: --min-epss filters by predicted REMOTE exploitation likelihood." >&2
    echo "  Local privilege-escalation CVEs score low on EPSS almost by design (it's" >&2
    echo "  trained on internet-facing exploitation telemetry), even ones with a real," >&2
    echo "  working PoC. If you're hunting for privesc vectors specifically, --min-epss" >&2
    echo "  will likely hide the exact CVEs you're looking for. Prefer -s/--since and" >&2
    echo "  -x/-X to cut scan volume instead." >&2
fi

SINCE_CUTOFF=$(since_to_cutoff "$SINCE_VALUE") || usage

# Only need the single top PoC hit per CVE.
LIMIT=1

# Space out API calls to stay under each service's unauthenticated rate limit
# (NVD: 5 req/30s, GitHub: 10 req/min); go faster automatically if the
# corresponding token/key is set. -d/--delay overrides both. FIRST.org (EPSS)
# publishes no hard limit; a light default delay is still applied.
NVD_DELAY=6.5
[[ -n "${NVD_API_KEY:-}" ]] && NVD_DELAY=0.7
GH_DELAY=6.5
[[ -n "${GITHUB_TOKEN:-}" ]] && GH_DELAY=2.1
EPSS_DELAY=0.5
if [[ -n "$DELAY" ]]; then
    NVD_DELAY="$DELAY"
    GH_DELAY="$DELAY"
    EPSS_DELAY="$DELAY"
fi

CACHE_DIR="${CVESCOPE_CACHE_DIR:-$(cache_default_dir)}"

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
    printf '"package","version","cve","poc_found","poc_repo","poc_stars","poc_url","epss"\n' > "$OUTPUT"
fi

SINCE_LABEL="all time"
[[ -n "$SINCE_CUTOFF" ]] && SINCE_LABEL="last $SINCE_VALUE (published >= $SINCE_CUTOFF)"
SCAN_MSG="Scanning $TOTAL line(s)"
[[ "$PRE_EXCLUDED" -gt 0 ]] && SCAN_MSG="$SCAN_MSG ($PRE_EXCLUDED excluded by -x, $((TOTAL - PRE_EXCLUDED)) to check)"
EPSS_LABEL=""
[[ -n "$MIN_EPSS" ]] && EPSS_LABEL=", min EPSS: $MIN_EPSS"
CACHE_LABEL=", cache: on (${CACHE_TTL_HOURS}h)"
[[ "$NO_CACHE" -eq 1 ]] && CACHE_LABEL=", cache: off"
echo "$SCAN_MSG (NVD delay: ${NVD_DELAY}s, GitHub delay: ${GH_DELAY}s, since: $SINCE_LABEL$EPSS_LABEL$CACHE_LABEL)..." >&2

START_TIME=$(date +%s)

PKG_COUNT=0
EXCLUDED_COUNT=0
AFFECTED_COUNT=0
CVE_COUNT=0
POC_COUNT=0
GH_ERROR_COUNT=0
EPSS_SKIP_COUNT=0
CACHE_HIT_COUNT=0
STALE_PKG_COUNT=0
STALE_PKGS=()
STALE_FILE=$(mktemp)
trap 'rm -f "$STALE_FILE"' EXIT

# Print one CVE's report line + CSV row, and update the running counters.
# Args: pkg ver cve poc_found repo stars url epss
report_cve() {
    local pkg="$1" ver="$2" cve="$3" poc_found="$4" repo="$5" stars="$6" url="$7" epss="$8"

    CVE_COUNT=$((CVE_COUNT + 1))
    case "$poc_found" in
        yes) POC_COUNT=$((POC_COUNT + 1)) ;;
        error) GH_ERROR_COUNT=$((GH_ERROR_COUNT + 1)) ;;
        skipped) EPSS_SKIP_COUNT=$((EPSS_SKIP_COUNT + 1)) ;;
    esac

    if [[ "$POC_ONLY" -eq 1 && "$poc_found" == "no" ]]; then
        : # still counted above, just not printed/written
    else
        case "$poc_found" in
            yes) echo "  $cve  PoC: YES  (top: $repo ★$stars)  $url" ;;
            error) echo "  $cve  PoC: ERROR (GitHub lookup failed — rate-limited? try again or set GITHUB_TOKEN)" ;;
            skipped) echo "  $cve  PoC: SKIPPED (EPSS ${epss:-unknown} < $MIN_EPSS threshold)" ;;
            *) echo "  $cve  PoC: no" ;;
        esac

        if [[ -n "$OUTPUT" ]]; then
            printf '"%s","%s","%s","%s","%s","%s","%s","%s"\n' \
                "$pkg" "$ver" "$cve" "$poc_found" "$repo" "$stars" "$url" "$epss" >> "$OUTPUT"
        fi
    fi
}

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

    CACHE_KEY=$(cache_key "$pkg" "$ver" "$SINCE_VALUE" "${MIN_EPSS:-off}")

    CACHED=""
    if [[ "$NO_CACHE" -eq 0 ]]; then
        CACHED=$(cache_get "$CACHE_DIR" "$CACHE_KEY" "$CACHE_TTL_SECONDS")
    fi

    if [[ -n "$CACHED" ]]; then
        CACHE_HIT_COUNT=$((CACHE_HIT_COUNT + 1))
        mapfile -t ROWS < <(jq -r '.cves[] | [.cve, .poc_found, (.poc_repo//""), (.poc_stars//""), (.poc_url//""), (.epss//"")] | join(",")' <<< "$CACHED")
        if [[ ${#ROWS[@]} -gt 0 ]]; then
            AFFECTED_COUNT=$((AFFECTED_COUNT + 1))
            echo "" >&2
            echo "[$i/$TOTAL] $pkg $ver (cached)"
            for row in "${ROWS[@]}"; do
                IFS=',' read -r cve poc_found repo stars url epss <<< "$row"
                report_cve "$pkg" "$ver" "$cve" "$poc_found" "$repo" "$stars" "$url" "$epss"
            done
        fi
        continue
    fi

    : > "$STALE_FILE"
    DISCOVERY=$(discover_version_cves "$pkg" "$ver" "$SINCE_CUTOFF" "$STALE_FILE")
    NVD_STATUS=$?
    sleep "$NVD_DELAY"

    if [[ $NVD_STATUS -ne 0 ]]; then
        echo "" >&2
        echo "  [$pkg $ver] NVD lookup failed (rate-limited or network error) — skipping" >&2
        continue
    fi

    mapfile -t CVES < <(printf '%s\n' "$DISCOVERY" | awk 'NF && !seen[$0]++')

    if [[ ${#CVES[@]} -eq 0 ]]; then
        if [[ -s "$STALE_FILE" ]]; then
            STALE_PKG_COUNT=$((STALE_PKG_COUNT + 1))
            STALE_PKGS+=("$pkg $ver")
        fi
        [[ "$NO_CACHE" -eq 0 ]] && cache_set "$CACHE_DIR" "$CACHE_KEY" "[]"
        continue
    fi

    AFFECTED_COUNT=$((AFFECTED_COUNT + 1))
    echo "" >&2
    echo "[$i/$TOTAL] $pkg $ver"

    declare -A EPSS_SCORES=()
    if [[ -n "$MIN_EPSS" ]]; then
        CVE_CSV=$(IFS=,; echo "${CVES[*]}")
        while read -r ecve escore; do
            [[ -n "$ecve" ]] && EPSS_SCORES["$ecve"]="$escore"
        done < <(epss_lookup "$CVE_CSV")
        sleep "$EPSS_DELAY"
    fi

    CVE_JSON_OBJS=()
    for cve in "${CVES[@]}"; do
        EPSS_SCORE="${EPSS_SCORES[$cve]:-}"

        if [[ -n "$MIN_EPSS" && -n "$EPSS_SCORE" ]] && awk -v a="$EPSS_SCORE" -v b="$MIN_EPSS" 'BEGIN{exit !(a<b)}'; then
            POC_FOUND="skipped"
            REPO=""
            STARS=""
            URL=""
        else
            RESP=$(gh_search_cve "$cve")
            GH_STATUS=$?
            sleep "$GH_DELAY"

            POC_FOUND="no"
            REPO=""
            STARS=""
            URL=""
            if [[ $GH_STATUS -ne 0 ]]; then
                POC_FOUND="error"
            else
                TOTAL_POCS=$(jq '.total_count' <<< "$RESP")
                if [[ "$TOTAL_POCS" -gt 0 ]]; then
                    POC_FOUND="yes"
                    REPO=$(jq -r '.items[0].full_name' <<< "$RESP")
                    STARS=$(jq -r '.items[0].stargazers_count' <<< "$RESP")
                    URL="https://github.com/$REPO"
                fi
            fi
        fi

        report_cve "$pkg" "$ver" "$cve" "$POC_FOUND" "$REPO" "$STARS" "$URL" "$EPSS_SCORE"

        CVE_JSON_OBJS+=("$(jq -n --arg cve "$cve" --arg pf "$POC_FOUND" --arg repo "$REPO" \
            --arg stars "$STARS" --arg url "$URL" --arg epss "$EPSS_SCORE" \
            '{cve:$cve, poc_found:$pf, poc_repo:$repo, poc_stars:$stars, poc_url:$url, epss:$epss}')")
    done
    unset EPSS_SCORES

    if [[ "$NO_CACHE" -eq 0 ]]; then
        CVES_JSON=$(printf '%s\n' "${CVE_JSON_OBJS[@]}" | jq -s '.')
        cache_set "$CACHE_DIR" "$CACHE_KEY" "$CVES_JSON"
    fi
done

printf '\r\033[K' >&2
echo ""

ELAPSED=$(($(date +%s) - START_TIME))
if [[ "$ELAPSED" -ge 3600 ]]; then
    ELAPSED_STR="$((ELAPSED / 3600))h $(((ELAPSED % 3600) / 60))m $((ELAPSED % 60))s"
elif [[ "$ELAPSED" -ge 60 ]]; then
    ELAPSED_STR="$((ELAPSED / 60))m $((ELAPSED % 60))s"
else
    ELAPSED_STR="${ELAPSED}s"
fi

SUMMARY="Summary: $PKG_COUNT package(s) scanned ($EXCLUDED_COUNT excluded, $CACHE_HIT_COUNT from cache), $AFFECTED_COUNT affected, $CVE_COUNT CVE(s) found, $POC_COUNT with a public PoC."
[[ "$EPSS_SKIP_COUNT" -gt 0 ]] && SUMMARY="$SUMMARY $EPSS_SKIP_COUNT skipped by --min-epss."
[[ "$GH_ERROR_COUNT" -gt 0 ]] && SUMMARY="$SUMMARY $GH_ERROR_COUNT GitHub lookup(s) failed — re-run or set GITHUB_TOKEN."
[[ "$STALE_PKG_COUNT" -gt 0 ]] && SUMMARY="$SUMMARY $STALE_PKG_COUNT package(s) have a known CVE outside your -s $SINCE_VALUE window — widen it (e.g. -s all) to see them."
echo "$SUMMARY Took $ELAPSED_STR."
[[ -n "$OUTPUT" ]] && echo "CSV report written to $OUTPUT"

if [[ "$STALE_PKG_COUNT" -gt 0 ]]; then
    echo ""
    echo "Packages with a known CVE outside your -s $SINCE_VALUE window:"
    printf '  %s\n' "${STALE_PKGS[@]}"
    if [[ -n "$STALE_OUT" ]]; then
        printf '%s\n' "${STALE_PKGS[@]}" > "$STALE_OUT"
        echo "Written to $STALE_OUT — re-check just these with: $0 -f $STALE_OUT -s all"
    fi
fi

exit 0
