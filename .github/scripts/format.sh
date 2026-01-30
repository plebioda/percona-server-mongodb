#!/bin/bash
#
# Consolidated format script for PSMDB CI
#
# This script runs all code formatters and reports which ones found issues.
# It continues running all formatters even if earlier ones make changes,
# then provides a cumulative summary.
#
# Usage:
#   ./.github/scripts/format.sh
#
# Exit codes:
#   0 - All formatters passed (no changes needed)
#   1 - One or more formatters found issues (changes were made)
#   2 - A formatter crashed/failed to run
#

set -o pipefail

declare -a FAILED_FORMATTERS=()
OVERALL_EXIT_CODE=0
FORMATTER_CRASHED=0

# Get a hash of the current git diff state
get_diff_hash() {
    git diff 2>/dev/null | md5sum | cut -d' ' -f1
}

# Run a formatter and check for changes
# Arguments:
#   $1 - Display name of the formatter
#   $2 - Command to run
run_formatter() {
    local name="$1"
    local cmd="$2"

    echo "Running $name"
    echo "Command: $cmd"
    echo ""

    # Capture git diff hash before running formatter
    local before_hash
    before_hash=$(get_diff_hash)

    # Run the formatter
    if ! eval "$cmd"; then
        echo ""
        echo "::error::$name crashed or failed to run"
        echo "ERROR: $name exited with non-zero status"
        FORMATTER_CRASHED=1
        return 1
    fi

    # Check if this formatter made any changes
    local after_hash
    after_hash=$(get_diff_hash)

    if [[ "$before_hash" != "$after_hash" ]]; then
        echo ""
        echo ">>> $name found formatting issues <<<"
        FAILED_FORMATTERS+=("$name")
        OVERALL_EXIT_CODE=1
    else
        echo ">>> $name: OK (no changes) <<<"
    fi
    echo ""
    return 0
}

echo "Starting format check..."
echo ""

# Run all formatters
run_formatter "clang-format" "python buildscripts/clang_format.py format" || true
run_formatter "pylinters" "python buildscripts/pylinters.py fix" || true
run_formatter "pylinters-scons" "python buildscripts/pylinters.py fix-scons" || true
run_formatter "eslint" "python buildscripts/eslint.py fix" || true

echo "SUMMARY"

if [[ $FORMATTER_CRASHED -ne 0 ]]; then
    echo ""
    echo "::error::One or more formatters crashed during execution"
    echo "Please check the logs above for details."
    exit 2
fi

if [[ ${#FAILED_FORMATTERS[@]} -gt 0 ]]; then
    echo ""
    echo "::error::Formatting issues detected"
    echo ""
    echo "Formatters that found issues:"
    for fmt in "${FAILED_FORMATTERS[@]}"; do
        echo "  - $fmt"
    done
    echo ""
    echo "To fix locally, run:"
    echo ""
    echo "    ./.github/scripts/format.sh"
    echo ""
    echo "Or run individual formatters:"
    echo ""
    echo "    python buildscripts/clang_format.py format"
    echo "    python buildscripts/pylinters.py fix"
    echo "    python buildscripts/pylinters.py fix-scons"
    echo "    python buildscripts/eslint.py fix"
    echo ""
    echo "and commit the resulting changes."
    echo ""
    echo "AFFECTED FILES"
    git diff --stat
    echo ""
    echo "CUMULATIVE DIFF (first 1000 lines)"
    git diff | head -n 1000
    exit 1
else
    echo ""
    echo "All formatters passed successfully!"
    exit 0
fi
