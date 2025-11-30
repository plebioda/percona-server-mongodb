#!/usr/bin/env python3
import sys
import os
import difflib
from typing import List, Tuple, Dict, Iterable

from git import Repo, BadName


LineRange = Tuple[int, int]  # inclusive, 1-based line numbers: (start, end)


def read_blob_lines(commit, path: str) -> List[str]:
    """Return file contents at given commit as list of lines (without newlines).

    If file does not exist at that commit, return empty list.
    """
    try:
        blob = commit.tree / path
    except KeyError:
        return []
    data = blob.data_stream.read()
    return data.decode("utf-8", errors="ignore").splitlines()


def read_worktree_lines(path: str) -> List[str]:
    """Return working-tree file contents as list of lines (without newlines)."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().splitlines()


def pr_changed_ranges_base_to_head(
    base_lines: List[str],
    head_lines: List[str],
) -> List[LineRange]:
    """
    Compute line ranges (in HEAD coordinates, 1-based) that changed between
    base -> HEAD, representing "lines changed by the PR".

    We treat 'replace' and 'insert' as changed lines in HEAD.
    ('delete' has no HEAD lines, so it doesn't give us coordinates to match.)
    """
    sm = difflib.SequenceMatcher(None, base_lines, head_lines)
    ranges: List[LineRange] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "insert"):
            if j1 != j2:
                start = j1 + 1  # HEAD is the second sequence
                end = j2
                if start <= end:
                    ranges.append((start, end))
    return ranges


def ranges_intersect(r1: LineRange, r2: LineRange) -> bool:
    """Return True if two inclusive line ranges intersect."""
    a_start, a_end = r1
    b_start, b_end = r2
    return not (a_end < b_start or b_end < a_start)


def any_intersection_with(
    target: LineRange,
    ranges: Iterable[LineRange],
) -> bool:
    for r in ranges:
        if ranges_intersect(target, r):
            return True
    return False


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base-commit>", file=sys.stderr)
        return 2

    base_ref = sys.argv[1]
    repo = Repo(".")

    if repo.bare:
        print("Repository appears to be bare; aborting.", file=sys.stderr)
        return 2

    try:
        base_commit = repo.commit(base_ref)
    except BadName:
        print(f"Invalid base commit-ish: {base_ref}", file=sys.stderr)
        return 2

    head_commit = repo.head.commit

    # Optional safety: ensure index == HEAD (no staged, uncommitted changes).
    if repo.is_dirty(index=True, working_tree=False):
        print(
            "Index has staged but uncommitted changes. "
            "This script assumes a clean index (HEAD == index).",
            file=sys.stderr,
        )
        return 2

    # Files with unstaged modifications (HEAD/index -> working tree)
    wt_diffs = repo.index.diff(None)
    wt_files = {d.a_path for d in wt_diffs if d.a_path is not None}

    if not wt_files:
        # Nothing changed after formatter => no issues
        return 0

    # Files changed between base and HEAD (PR diff)
    base_head_diffs = base_commit.diff(head_commit)
    base_head_files = {
        (d.b_path or d.a_path) for d in base_head_diffs if (d.b_path or d.a_path)
    }

    # Only care about files that:
    # - are changed in PR (base..HEAD)
    # - and have unstaged changes after formatter (HEAD..WT)
    candidate_files = sorted(base_head_files & wt_files)

    if not candidate_files:
        # Formatter touched only files unrelated to this PR
        return 0

    offending: Dict[str, List[LineRange]] = {}

    for path in candidate_files:
        # File must exist in HEAD and in working tree to be a formatter issue
        try:
            _ = head_commit.tree / path
        except KeyError:
            continue  # deleted in HEAD, ignore

        if not os.path.exists(path):
            continue  # deleted locally, ignore

        base_lines = read_blob_lines(base_commit, path)
        head_lines = read_blob_lines(head_commit, path)
        wt_lines = read_worktree_lines(path)

        pr_ranges_head = pr_changed_ranges_base_to_head(base_lines, head_lines)
        if not pr_ranges_head:
            # Technically changed in diff, but no HEAD lines we care about
            continue

        # Now see where HEAD differs from working tree (formatter output).
        # We'll create annotations on WT coordinates (j1/j2).
        sm_hw = difflib.SequenceMatcher(None, head_lines, wt_lines)
        file_offending_ranges: List[LineRange] = []

        for tag, i1, i2, j1, j2 in sm_hw.get_opcodes():
            # Any non-equal opcode means HEAD vs WT differ in some way
            if tag not in ("replace", "delete", "insert"):
                continue

            # HEAD-side span for this opcode, 1-based
            head_start = i1 + 1
            head_end = i2

            if head_start > head_end:
                # For pure inserts, there are no HEAD lines (i1 == i2).
                # They can't intersect lines-changed-in-PR in HEAD coords.
                continue

            if not any_intersection_with((head_start, head_end), pr_ranges_head):
                # Formatter changed this chunk, but it's outside PR-changed lines
                continue

            # WT-side span for this opcode, 1-based
            wt_start = j1 + 1
            wt_end = j2

            if wt_start <= wt_end:
                file_offending_ranges.append((wt_start, wt_end))

        if file_offending_ranges:
            offending[path] = file_offending_ranges

    if not offending:
        # Formatter changes either:
        # - didn't touch PR lines, or
        # - only touched files outside the PR
        return 0

    # Emit GitHub annotations and fail.
    # GitHub annotation format:
    # ::error file=path,line=1,endLine=1::message
    msg = (
        "Formatting problems detected in lines changed by this PR. "
        "Run the formatter only on your changes or fix manual edits."
    )

    for path, ranges in offending.items():
        for start, end in ranges:
            print(
                f"::error file={path},line={start},endLine={end}::{msg}",
                file=sys.stdout,  # annotations must go to stdout
            )

    return 1


if __name__ == "__main__":
    sys.exit(main())
