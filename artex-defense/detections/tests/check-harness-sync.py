#!/usr/bin/env python3
#
# Harness self-consistency check for the detection test suites. check-harness-sync.sh
# launches this inside a Python container with the detection tree and the CI
# workflow mounted read-only under /repo. It proves the one thing the eight
# detection suites cannot: that run-all.sh, the CI workflow, and the suite
# directories on disk all name the same suites in the same order.
#
# run-all.sh, CONTRIBUTING, and this directory's README all promise that
# "run-all.sh runs the same suites as CI, in the same order." Nothing enforced
# that promise. A suite added to only one of the three places — a new CI step with
# no SUITES entry, or a new directory never wired into either — passes every
# per-suite test while quietly breaking the promise: run-all.sh and CI run
# different sets, so a green run-all.sh locally no longer implies a green CI. This
# check closes that gap the same way the indicator test closes the
# CI-paths / pre-commit-regex gap: it reads the three sources of truth and asserts
# they agree.
#
#   A = the SUITES="..." list in run-all.sh                       (ordered)
#   B = the per-suite `run: detections/tests/<x>/run.sh` steps     (ordered)
#       in .github/workflows/detections.yml
#   C = the subdirectories of detections/tests/ that carry a       (a set)
#       run.sh
#
# It asserts A == B as ordered lists (so the documented "same order as CI" holds)
# and set(A) == C (so no directory is orphaned and no listed suite is missing on
# disk). It is deliberately not a detection suite: it is not in SUITES, not a
# `.../run.sh` CI step, and not a run.sh directory, so it never counts itself and
# the eight detection suites stay eight.
#
# It parses only the stable machine-readable lines (the SUITES assignment, the
# `run:` steps, the directory listing), never prose or the example-output blocks
# in the READMEs, so it cannot go brittle on documentation wording.
#
# Pure standard library (the slim image already ships python3); nothing is
# installed and nothing is written to the repo. Exits non-zero on any mismatch.
#
# Usage. check-harness-sync.sh runs this inside Docker with the repo mounted at
# /repo, which is why ROOT defaults to /repo below. To run it directly on the
# host instead, point ARTEX_REPO_ROOT at the repo root:
#
#     ARTEX_REPO_ROOT="$(git rev-parse --show-toplevel)" \
#         python3 detections/tests/check-harness-sync.py

import os
import re
import sys

# Default to /repo, the mount point check-harness-sync.sh uses inside Docker.
# Track whether the caller set the variable so a missing-path failure can tell a
# host-direct runner why ROOT is /repo (see main()).
ROOT = os.environ.get("ARTEX_REPO_ROOT", "/repo")
ROOT_FROM_ENV = "ARTEX_REPO_ROOT" in os.environ
TESTS_DIR = os.path.join(ROOT, "detections", "tests")
RUN_ALL = os.path.join(TESTS_DIR, "run-all.sh")
CI_WORKFLOW = os.path.join(ROOT, ".github", "workflows", "detections.yml")


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def suites_from_run_all(path):
    """Ordered suite names in the SUITES="..." assignment in run-all.sh."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r'^SUITES="([^"]*)"', text, re.MULTILINE)
    if not m:
        fail(f'could not find a SUITES="..." assignment in {path}')
    names = m.group(1).split()
    if not names:
        fail(f"SUITES in {path} is empty")
    return names


def suites_from_ci(path):
    """Ordered suite names in the per-suite `run:` steps of the CI workflow."""
    names = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.search(r"run:\s*detections/tests/([^/]+)/run\.sh\s*$", line)
            if m:
                names.append(m.group(1))
    if not names:
        fail(f"found no `run: detections/tests/<suite>/run.sh` steps in {path}")
    return names


def suites_from_dirs(path):
    """Suite directories under detections/tests/ that carry a run.sh."""
    names = set()
    for entry in sorted(os.listdir(path)):
        d = os.path.join(path, entry)
        if os.path.isdir(d) and os.path.isfile(os.path.join(d, "run.sh")):
            names.add(entry)
    if not names:
        fail(f"found no suite directories with a run.sh under {path}")
    return names


def main():
    for p in (RUN_ALL, CI_WORKFLOW, TESTS_DIR):
        if not os.path.exists(p):
            hint = ""
            if not ROOT_FROM_ENV:
                hint = (
                    "\n       ARTEX_REPO_ROOT is unset, so ROOT defaulted to /repo "
                    "(the path check-harness-sync.sh mounts the repo at inside Docker).\n"
                    "       To run this script directly on the host, point it at the "
                    "repo root:\n"
                    '         ARTEX_REPO_ROOT="$(git rev-parse --show-toplevel)" '
                    "python3 detections/tests/check-harness-sync.py\n"
                    "       or use the Docker wrapper: "
                    "detections/tests/check-harness-sync.sh"
                )
            fail(f"missing expected path: {p}{hint}")

    a = suites_from_run_all(RUN_ALL)
    b = suites_from_ci(CI_WORKFLOW)
    c = suites_from_dirs(TESTS_DIR)

    errors = []

    # A name repeated in an ordered source would make the comparisons below read
    # misleadingly, so surface it on its own first.
    for label, seq in (("run-all.sh SUITES", a), ("CI steps", b)):
        if len(seq) != len(set(seq)):
            dupes = sorted({x for x in seq if seq.count(x) > 1})
            errors.append(f"{label} names a suite more than once: {dupes}")

    if a != b:
        errors.append(
            "run-all.sh SUITES and the CI steps disagree (order matters: "
            "run-all.sh promises the same order as CI):\n"
            f"    run-all.sh: {a}\n"
            f"    CI steps  : {b}"
        )

    if set(a) != c:
        detail = []
        only_listed = sorted(set(a) - c)
        only_on_disk = sorted(c - set(a))
        if only_listed:
            detail.append(
                f"    listed in run-all.sh but no run.sh directory: {only_listed}"
            )
        if only_on_disk:
            detail.append(
                f"    run.sh directory present but not in run-all.sh: {only_on_disk}"
            )
        errors.append(
            "run-all.sh SUITES and the suite directories disagree:\n"
            + "\n".join(detail)
        )

    if errors:
        print("detection test harness is OUT OF SYNC:\n", file=sys.stderr)
        for e in errors:
            print(e + "\n", file=sys.stderr)
        print(
            "Wire the new suite into all three (SUITES in run-all.sh, a step in "
            ".github/workflows/detections.yml, and a run.sh directory) so a local "
            "run-all.sh runs exactly what CI runs.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"harness sync OK: run-all.sh, CI, and {len(c)} suite directories "
        "name the same suites in the same order:"
    )
    print("    " + " ".join(a))


if __name__ == "__main__":
    main()
