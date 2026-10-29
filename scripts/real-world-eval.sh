#!/usr/bin/env bash
# Run soroban-sec against widely used, audited Soroban codebases at pinned
# commits and print a per-rule summary.
#
# These repositories are maintained by Stellar, OpenZeppelin and Blend, so most
# of what the scanner reports on them should be either a true observation or a
# documented, deliberate pattern. A jump in the totals after a detector change is
# a false-positive regression worth investigating before merging.
#
# Usage: scripts/real-world-eval.sh [work-dir]
#   SOROBAN_SEC=path/to/soroban-sec  use an existing binary instead of building
#   MAX_FINDINGS=N                   exit non-zero if the total exceeds N
set -euo pipefail

work="${1:-target/real-world}"
mkdir -p "$work"

# name | repository | pinned commit
corpus=(
  "soroban-examples|https://github.com/stellar/soroban-examples|03d42aa"
  "stellar-contracts|https://github.com/OpenZeppelin/stellar-contracts|ddc327e"
  "blend-contracts-v2|https://github.com/blend-capital/blend-contracts-v2|0bf9b74"
)

if [[ -z "${SOROBAN_SEC:-}" ]]; then
  cargo build --quiet --release -p soroban-sec
  SOROBAN_SEC="target/release/soroban-sec"
fi

total=0
printf '%-20s %-9s %8s  %s\n' "repository" "commit" "findings" "by rule"
for entry in "${corpus[@]}"; do
  IFS='|' read -r name url commit <<<"$entry"
  dir="$work/$name"
  if [[ ! -d "$dir/.git" ]]; then
    git clone --quiet --filter=blob:none "$url" "$dir"
  fi
  git -C "$dir" checkout --quiet "$commit"

  report="$work/$name.json"
  "$SOROBAN_SEC" "$dir" --format json -o "$report"
  summary=$(python3 - "$report" <<'PY'
import collections, json, sys
findings = json.load(open(sys.argv[1]))["findings"]
rules = collections.Counter(f["rule"] for f in findings)
print(len(findings), " ".join(f"{rule}:{count}" for rule, count in sorted(rules.items())))
PY
)
  count="${summary%% *}"
  total=$((total + count))
  printf '%-20s %-9s %8s  %s\n' "$name" "$commit" "$count" "${summary#* }"
done
printf '%-20s %-9s %8s\n' "total" "" "$total"

if [[ -n "${MAX_FINDINGS:-}" && "$total" -gt "$MAX_FINDINGS" ]]; then
  echo "error: $total findings exceeds the budget of $MAX_FINDINGS" >&2
  exit 1
fi
