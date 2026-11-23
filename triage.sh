#!/usr/bin/env bash
# Triage AFL crashes into reproducible, deduplicated report directories.
# Usage: ./triage.sh afl-out/default/crashes [reports]
set -euo pipefail

crash_dir=${1:?usage: $0 AFL_CRASH_DIRECTORY [REPORT_DIRECTORY]}
report_dir=${2:-reports}
target=${TARGET:-./lfs-afl-asan}
timeout_s=${TIMEOUT:-5}
mkdir -p "$report_dir"

if [[ ! -x "$target" ]]; then
    echo "Target '$target' is not executable. Run 'make asan' or set TARGET." >&2
    exit 2
fi
target_abs=$(cd "$(dirname "$target")" && pwd)/$(basename "$target")

shopt -s nullglob
inputs=("$crash_dir"/id:*)
if ((${#inputs[@]} == 0)); then
    echo "No AFL crash files in $crash_dir" >&2
    exit 0
fi

run_target() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$timeout_s" "$target"
    else
        # macOS does not ship GNU timeout. perl's alarm is sufficient here
        # because the harness has no children and consumes only stdin.
        perl -e 'alarm shift; exec @ARGV' "$timeout_s" "$target"
    fi
}

new_count=0
duplicate_count=0
passed_count=0
echo "Checking ${#inputs[@]} crash inputs..."
for input in "${inputs[@]}"; do
    # The sanitizer backtrace is stable enough to group one root cause while
    # preserving the first AFL input as the exact reproducer.
    log=$(mktemp)
    set +e
    run_target < "$input" >"$log.out" 2>"$log"
    status=$?
    set -e
    if (( status == 0 )); then
        passed_count=$((passed_count + 1))
        rm -f "$log" "$log.out"
        continue
    fi
    signature_lines=$(sed -E \
        -e 's/0x[0-9a-f]+/ADDR/g' -e 's/\+0x[0-9a-f]+/+OFF/g' \
        -e 's/:[0-9]+/:LINE/g' "$log" | \
        rg -m 12 'ERROR:|SUMMARY:|#[0-9]+|runtime error:' || true)
    if [[ -n "$signature_lines" ]]; then
        signature=$(printf '%s\n' "$signature_lines" | shasum -a 256 | awk '{print $1}')
    else
        signature="exit-${status}"
    fi
    out="$report_dir/$signature"
    if [[ -e "$out" ]]; then
        duplicate_count=$((duplicate_count + 1))
        rm -f "$log" "$log.out"
        continue
    fi
    mkdir -p "$out"
    cp "$input" "$out/reproducer.bin"
    mv "$log" "$out/stderr.txt"
    mv "$log.out" "$out/stdout.txt"
    {
        echo "# littlefs fuzz finding"
        echo
        echo "- AFL input: $(basename "$input")"
        echo "- Exit status: $status"
        echo "- Signature: $signature"
        echo
        echo '## Reproduce'
        echo
        echo '```sh'
        echo "make asan"
        echo "$target_abs < reproducer.bin"
        echo '```'
        echo
        echo '## Minimize'
        echo
        echo '```sh'
        echo "afl-tmin -i reproducer.bin -o reproducer.min.bin -- $target_abs"
        echo '```'
        echo
        echo '## Sanitizer output'
        echo
        echo '```text'
        sed -n '1,80p' "$out/stderr.txt"
        echo '```'
    } > "$out/REPORT.md"
    new_count=$((new_count + 1))
done

{
    echo '# Crash reports'
    echo
    echo "Checked ${#inputs[@]} inputs: $new_count new reports, $duplicate_count already reported, $passed_count did not crash on replay."
    echo
    echo 'Each report includes the captured output and the input needed to reproduce it.'
    echo 'Reports grouped only by exit status may contain different causes; they had no sanitizer backtrace.'
    echo
    for report in "$report_dir"/*/REPORT.md; do
        [[ -f "$report" ]] || continue
        name=$(basename "$(dirname "$report")")
        echo "- [$name]($name/REPORT.md)"
    done
} > "$report_dir/README.md"
echo "Done: $new_count new reports, $duplicate_count already reported, $passed_count did not crash on replay."
echo "Open $report_dir/README.md to read the reports."
