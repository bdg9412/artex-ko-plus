#!/usr/bin/env python3
#
# Source-of-truth consistency test for the ARTEX detection indicators. run.sh
# launches this inside a Python container with the detection rules and the
# upstream source packages they pin mounted read-only under /repo. It proves one
# property the other three detection tests do not: that each rule's pinned
# indicator is still the string ARTEX's own source actually emits.
#
# The Sigma test proves an indicator survives rule->query *compilation*; the
# ATT&CK test proves the layer matches the rules' tags; the Suricata test proves
# the network rule *fires*. None of them look back at the source the indicator
# claims to come from. So the realistic rot they miss is an upstream re-sync that
# bumps the prober User-Agent to "artex-enrich/2.0" or rewrites the guard marker:
# every rule still compiles, the layer still matches, the pcap test still fires on
# the synthesized capture — and the deployed rule silently stops matching real
# ARTEX traffic. This test turns detections/README's claim ("every indicator is
# grounded in a string verified in this repository's source, not inferred") and
# CONTRIBUTING's first contribution contract into a guard a reviewer can re-run.
#
# For every indicator it asserts, bidirectionally:
#   - source drift: the value is still present in the upstream source file(s)
#     that emit it (fails if an upstream re-sync changed the source but not the
#     rule -> the rule is now stale);
#   - rule drift: the value is still pinned in the rule(s) built on it (fails if a
#     rule edit moved the indicator away from the source).
# The enrichment UA also carries a Suricata prefix check, because that rule
# matches the User-Agent by `startswith` and so pins a prefix of the full value.
#
# The destructive-command tokens are handled separately and honestly: they are
# generic hunting leads, not unique ARTEX fingerprints, so the test only asserts
# the correspondence the rule actually claims — each token appears both in ARTEX's
# guard deny-list (db/db.go) and in the hunting rule that mirrors it.
#
# It then validates the published, machine-readable indicator list
# (detections/indicators/artex_indicators.csv): every row's value must still be
# present in the source file(s) it cites and pinned in the rule(s) it cites, and
# every fingerprint this test grounds must appear in the list — so the artifact a
# defender imports cannot silently drift from the source it claims to come from.
#
# Finally it closes the loop on the two gates that fire this test: the CI workflow
# (.github/workflows/detections.yml push/pull_request paths) and the local
# pre-commit hook (.pre-commit-config.yaml files regex). Every upstream source file
# this test reads must be covered by both, or a change touching only a newly pinned
# source (as cmd/artex/main.go once was) would skip the test on one of them: on CI
# the drift sails through the merge gate green, on the hook it is never caught
# locally even though the hook's comment promises "the same source scope as CI".
# The check derives the required set from the indicators it already asserts, so
# pinning a new source without wiring it into *both* gates fails here until they
# stay in sync.
#
# Pure standard library (the slim image already ships python3); nothing is
# installed and nothing is written to the repo. Exits non-zero on any failure.

import csv
import io
import os
import re
import sys

ROOT = os.environ.get("ARTEX_REPO_ROOT", "/repo")

# --- exact ARTEX fingerprints ------------------------------------------------
# Each value is an operational string ARTEX emits; a rule is built on it. If an
# upstream re-sync changes the source string, the rule must change with it.
INDICATORS = [
    {
        "label": "enrichment prober User-Agent",
        "value": "artex-enrich/1.0",
        "sources": ["enrich/enrich.go"],
        "rules": ["detections/sigma/artex_enrich_user_agent.yml"],
        # Suricata matches the UA by `startswith`, so it pins a prefix of the
        # full value rather than the whole string. (file, prefix)
        "prefix_rules": [("detections/suricata/artex.rules", "artex-enrich/")],
    },
    {
        "label": "self-update egress User-Agent",
        "value": "artex-selfupdate",
        "sources": ["selfupdate/github.go", "selfupdate/stage.go"],
        "rules": ["detections/sigma/artex_selfupdate_egress.yml"],
    },
    {
        "label": "platform-guard audit framing marker",
        "value": "【ARTEX 平台管控·非目标防御】",
        "sources": ["guard/guard.go"],
        "rules": ["detections/sigma/artex_guard_audit_framing.yml"],
    },
]

# --- generic destructive-command hunting leads -------------------------------
# NOT unique ARTEX fingerprints. These tokens are shared with ARTEX's own guard
# deny-list (db/db.go); the hunting rule mirrors that list. The test asserts only
# the correspondence the rule claims, so it catches an upstream re-sync that drops
# or renames a deny-list entry the rule says it mirrors.
DENYLIST = {
    "source": "db/db.go",
    "rule": "detections/sigma/destructive_command_hunting.yml",
    "tokens": ["rm -rf", "mkfs", "DROP DATABASE", "FLUSHALL"],
}

fail = 0


def note(s):
    print("  " + s)


def ok(s):
    note("PASS  " + s)


def bad(s):
    global fail
    note("FAIL  " + s)
    fail = 1


def read(rel):
    """Return the text of a repo-relative file, or None if it is missing."""
    try:
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def contains(rel, needle):
    text = read(rel)
    if text is None:
        return None  # file missing -> distinct from "present but absent"
    return needle in text


print("== 1/5  exact fingerprints are still emitted by the upstream source ==")
for ind in INDICATORS:
    value, label = ind["value"], ind["label"]
    present = [s for s in ind["sources"] if contains(s, value) is True]
    missing_files = [s for s in ind["sources"] if contains(s, value) is None]
    if present:
        ok("%s: %r emitted by %s" % (label, value, ", ".join(present)))
    elif missing_files:
        bad("%s: source file(s) missing: %s (upstream moved the emitter?)"
            % (label, ", ".join(missing_files)))
    else:
        bad("%s: %r NOT found in any source file %s "
            "(upstream drift — update the rule to match)"
            % (label, value, ind["sources"]))

print("== 2/5  each rule still pins the indicator it is built on ==")
for ind in INDICATORS:
    value, label = ind["value"], ind["label"]
    for rule in ind["rules"]:
        hit = contains(rule, value)
        if hit is True:
            ok("%s pins %r" % (rule, value))
        elif hit is None:
            bad("rule file missing: %s" % rule)
        else:
            bad("%s no longer pins %r (rule drift from source)" % (rule, value))
    for rfile, prefix in ind.get("prefix_rules", []):
        if not value.startswith(prefix):
            bad("%s: prefix %r is not a prefix of %r (internal inconsistency)"
                % (rfile, prefix, value))
            continue
        hit = contains(rfile, prefix)
        if hit is True:
            ok("%s pins prefix %r of %r" % (rfile, prefix, value))
        elif hit is None:
            bad("rule file missing: %s" % rfile)
        else:
            bad("%s no longer pins prefix %r" % (rfile, prefix))

print("== 3/5  destructive hunting tokens match ARTEX's guard deny-list ==")
src, rule, tokens = DENYLIST["source"], DENYLIST["rule"], DENYLIST["tokens"]
for tok in tokens:
    in_src = contains(src, tok)
    in_rule = contains(rule, tok)
    if in_src is None:
        bad("deny-list source missing: %s" % src)
    elif in_rule is None:
        bad("hunting rule missing: %s" % rule)
    elif in_src and in_rule:
        ok("%r present in both %s and %s" % (tok, src, rule))
    elif not in_src:
        bad("%r pinned by the rule but absent from %s "
            "(upstream dropped/renamed the deny-list entry)" % (tok, src))
    else:
        bad("%r in the deny-list but not pinned by %s" % (tok, rule))

print("== 4/5  the published indicator list matches source and rules ==")
CSV_REL = "detections/indicators/artex_indicators.csv"
EXPECTED_HEADER = ["id", "type", "value", "perspective", "source", "rule", "description"]
VALID_PERSPECTIVES = {"target", "forensic"}

csv_rows = []
csv_text = read(CSV_REL)
if csv_text is None:
    bad("published indicator list missing: %s" % CSV_REL)
else:
    rows = list(csv.reader(io.StringIO(csv_text)))
    if not rows:
        bad("%s is empty" % CSV_REL)
    elif rows[0] != EXPECTED_HEADER:
        bad("%s header is %r, expected %r" % (CSV_REL, rows[0], EXPECTED_HEADER))
    else:
        seen_ids = set()
        for lineno, row in enumerate(rows[1:], start=2):
            if len(row) != len(EXPECTED_HEADER):
                bad("%s line %d: %d fields, expected %d"
                    % (CSV_REL, lineno, len(row), len(EXPECTED_HEADER)))
                continue
            rec = dict(zip(EXPECTED_HEADER, row))
            csv_rows.append(rec)
            rid, value = rec["id"], rec["value"]
            if rid in seen_ids:
                bad("%s: duplicate id %r" % (CSV_REL, rid))
            seen_ids.add(rid)
            if not value:
                bad("%s: row %r has an empty value" % (CSV_REL, rid))
                continue
            if rec["perspective"] not in VALID_PERSPECTIVES:
                bad("%s: row %r perspective %r not in %s"
                    % (CSV_REL, rid, rec["perspective"], sorted(VALID_PERSPECTIVES)))
            src_files = [s for s in rec["source"].split(";") if s]
            if not src_files:
                bad("%s: row %r cites no source file" % (CSV_REL, rid))
            for s in src_files:
                hit = contains(s, value)
                if hit is True:
                    ok("%s: %r grounded in %s" % (rid, value, s))
                elif hit is None:
                    bad("%s: row %r source file missing: %s" % (CSV_REL, rid, s))
                else:
                    bad("%s: row %r value %r not found in source %s (drift)"
                        % (CSV_REL, rid, value, s))
            for r in [r for r in rec["rule"].split(";") if r]:
                hit = contains(r, value)
                if hit is True:
                    ok("%s: %r pinned in %s" % (rid, value, r))
                elif hit is None:
                    bad("%s: row %r rule file missing: %s" % (CSV_REL, rid, r))
                else:
                    bad("%s: row %r value %r not pinned in rule %s"
                        % (CSV_REL, rid, value, r))
        published = {rec["value"] for rec in csv_rows}
        for ind in INDICATORS:
            if ind["value"] in published:
                ok("tested fingerprint %r is published in the list" % ind["value"])
            else:
                bad("tested fingerprint %r is missing from %s" % (ind["value"], CSV_REL))


def paths_for_trigger(text, trigger):
    """Collect the quoted entries of `<trigger>: ... paths: [...]` in the detection
    workflow. Returns the set of listed paths, or None if the trigger is absent.
    A deliberately small parser for a known-shape file: it locates the trigger key
    under `on:`, then the `paths:` list nested in it, and reads the `- "..."` items
    until the indentation returns to the list's level."""
    lines = text.splitlines()
    t_indent = None
    start = None
    for idx, line in enumerate(lines):
        if re.match(r"^\s{2,}%s:\s*$" % re.escape(trigger), line):
            t_indent = len(line) - len(line.lstrip())
            start = idx + 1
            break
    if start is None:
        return None
    items = set()
    i = start
    while i < len(lines):
        line = lines[i]
        if line.strip():
            indent = len(line) - len(line.lstrip())
            if indent <= t_indent:
                break  # left this trigger block
            if re.match(r"^\s*paths:\s*$", line):
                p_indent = indent
                j = i + 1
                while j < len(lines):
                    pl = lines[j]
                    if pl.strip():
                        pind = len(pl) - len(pl.lstrip())
                        if pind <= p_indent:
                            break
                        m = re.match(r"""^\s*-\s*['"]?([^'"\s]+)['"]?\s*$""", pl)
                        if m:
                            items.add(m.group(1))
                    j += 1
                return items
        i += 1
    return items


print("== 5/5  CI and the pre-commit hook both fire this test on any pinned source ==")
# Two gates run this test only when a file they filter on changes: the CI workflow's
# paths filter and the pre-commit hook's files regex. Every upstream source this test
# reads must be covered by both, or a change touching only that source skips the test
# on the gate that misses it — on CI the drift above passes the merge gate green, on
# the hook it is never caught locally. The required set is derived from the indicators
# themselves, so pinning a new source without wiring it into both gates fails here.
# detections/** covers the rules, the CSV, and the tests, so only non-detections
# sources are required explicitly (plus a spot check that each gate still covers the
# detections/ tree at all).
WORKFLOW_REL = ".github/workflows/detections.yml"
PRECOMMIT_REL = ".pre-commit-config.yaml"
DETECTIONS_SAMPLE = "detections/sigma/artex_enrich_user_agent.yml"
needed_sources = set()
for ind in INDICATORS:
    needed_sources.update(ind["sources"])
needed_sources.add(DENYLIST["source"])
for rec in csv_rows:
    for s in rec["source"].split(";"):
        if s:
            needed_sources.add(s)
needed_sources = {s for s in needed_sources if not s.startswith("detections/")}

wf_text = read(WORKFLOW_REL)
if wf_text is None:
    bad("CI workflow missing: %s" % WORKFLOW_REL)
else:
    for trigger in ("push", "pull_request"):
        listed = paths_for_trigger(wf_text, trigger)
        if listed is None:
            bad("%s has no %s: trigger" % (WORKFLOW_REL, trigger))
            continue
        if "detections/**" not in listed:
            bad("%s %s paths is missing 'detections/**' "
                "(rule/CSV/test changes would not trigger the detection tests)"
                % (WORKFLOW_REL, trigger))
        for s in sorted(needed_sources):
            if s in listed:
                ok("%s %s paths covers %s" % (WORKFLOW_REL, trigger, s))
            else:
                bad("%s %s paths is missing %s — a PR touching only that source "
                    "would skip this test and let source drift pass the merge gate"
                    % (WORKFLOW_REL, trigger, s))

# The local hook gates on a files regex, not a paths list. Its comment promises the
# "same source scope as CI", so the same required set must match that regex. This is
# the sibling drift the CI check above does not see: CI paths can carry a source the
# hook's regex omits (as cmd/artex/main.go once did), leaving the local gate a false
# promise even while the merge gate is sound.
pc_text = read(PRECOMMIT_REL)
if pc_text is None:
    bad("pre-commit config missing: %s" % PRECOMMIT_REL)
else:
    m = re.search(r"^\s*files:\s*(.+?)\s*$", pc_text, re.M)
    if not m:
        bad("%s has no files: pattern on the detections hook" % PRECOMMIT_REL)
    else:
        pattern_src = m.group(1).strip().strip("'\"")
        try:
            pat = re.compile(pattern_src)
        except re.error as exc:
            bad("%s files pattern does not compile: %s" % (PRECOMMIT_REL, exc))
            pat = None
        if pat is not None:
            if pat.search(DETECTIONS_SAMPLE):
                ok("%s files covers the detections/ tree" % PRECOMMIT_REL)
            else:
                bad("%s files does not cover detections/ "
                    "(rule/CSV/test changes would not fire the local hook)"
                    % PRECOMMIT_REL)
            for s in sorted(needed_sources):
                if pat.search(s):
                    ok("%s files covers %s" % (PRECOMMIT_REL, s))
                else:
                    bad("%s files is missing %s — a commit touching only that source "
                        "would skip the local hook while CI still runs it (the hook's "
                        "'same source scope as CI' promise is false for this file)"
                        % (PRECOMMIT_REL, s))

print()
print("reference: %d exact fingerprints, %d deny-list tokens, %d published rows, "
      "%d pinned sources checked against CI paths and the pre-commit files regex"
      % (len(INDICATORS), len(tokens), len(csv_rows), len(needed_sources)))
print("RESULT: %s" % ("PASS" if fail == 0 else "FAIL"))
sys.exit(fail)
