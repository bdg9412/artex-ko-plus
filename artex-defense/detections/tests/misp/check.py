#!/usr/bin/env python3
#
# Consistency test for the MISP-format export of the ARTEX detection indicators.
# run.sh launches this inside a Python container with pymisp installed and the
# detection tree plus the CI workflow mounted read-only under /repo. It proves
# two properties the other detection tests do not touch:
#
#   1. the published MISP event
#      (detections/indicators/artex_indicators.misp.json) is a *valid MISP
#      document* — pymisp parses it and accepts every attribute type/category,
#      so a defender can import it into MISP (or export it on to STIX from
#      there) without hand-fixing the format; and
#   2. that MISP event stays in sync with the source-of-truth CSV
#      (detections/indicators/artex_indicators.csv) row for row — same values,
#      the intended MISP type/category for each CSV indicator type, and a
#      to_ids / disable_correlation flag that faithfully encodes the CSV's own
#      honesty (a row with a detection rule is an actionable indicator; a
#      host-forensic row without one is a triage hint, not a blocking IoC).
#
# The indicators source-of-truth test (../indicators/) already proves every CSV
# row is grounded in the upstream source and pinned in its rule; this test does
# not repeat that. It proves only that the MISP serialization a defender
# actually imports cannot silently drift away from that CSV — if a row is added,
# removed, retyped, or has its rule column changed, the MISP event must change
# with it or this test fails.
#
# Exits non-zero on any failed assertion.

import csv
import io
import json
import os
import re
import sys

ROOT = os.environ.get("ARTEX_REPO_ROOT", "/repo")
CSV_REL = "detections/indicators/artex_indicators.csv"
MISP_REL = "detections/indicators/artex_indicators.misp.json"
WORKFLOW_REL = ".github/workflows/detections.yml"

# The indicators README states the CSV `type` values "map onto the equivalent
# MISP/STIX attribute types". This is that mapping, made explicit and enforced:
# CSV indicator type -> (MISP attribute type, MISP attribute category).
TYPE_MAP = {
    "http.user-agent": ("user-agent", "Network activity"),
    "string": ("pattern-in-file", "Artifacts dropped"),
    "port": ("port", "Network activity"),
    "ip-dst|port": ("ip-dst|port", "Network activity"),
    # a host artifact that fits no network/file slot (e.g. a DB schema object
    # name); MISP's generic "other"/"Other" carries it as a triage lead.
    "other": ("other", "Other"),
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
    try:
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def misp_value_for(csv_type, csv_value):
    """The MISP value for a CSV row. MISP composite types join their parts with
    `|`, so the CSV's `ip:port` becomes `ip|port`; every other type is verbatim."""
    if csv_type == "ip-dst|port":
        return csv_value.replace(":", "|", 1)
    return csv_value


# --- load the source-of-truth CSV -------------------------------------------
EXPECTED_HEADER = ["id", "type", "value", "perspective", "source", "rule", "description"]
csv_rows = []
csv_text = read(CSV_REL)
if csv_text is None:
    bad("source CSV missing: %s" % CSV_REL)
else:
    rows = list(csv.reader(io.StringIO(csv_text)))
    if not rows or rows[0] != EXPECTED_HEADER:
        bad("%s header is %r, expected %r"
            % (CSV_REL, rows[0] if rows else None, EXPECTED_HEADER))
    else:
        for row in rows[1:]:
            if len(row) == len(EXPECTED_HEADER):
                csv_rows.append(dict(zip(EXPECTED_HEADER, row)))

# --- load the MISP event (raw JSON) -----------------------------------------
misp_text = read(MISP_REL)
event = None
attrs = []
if misp_text is None:
    bad("MISP event missing: %s" % MISP_REL)
else:
    try:
        doc = json.loads(misp_text)
    except ValueError as exc:
        bad("%s is not valid JSON: %s" % (MISP_REL, exc))
        doc = None
    if isinstance(doc, dict):
        event = doc.get("Event")
        if not isinstance(event, dict):
            bad("%s has no top-level Event object" % MISP_REL)
        else:
            if not event.get("info"):
                bad("%s Event has no info string" % MISP_REL)
            if not event.get("uuid"):
                bad("%s Event has no uuid" % MISP_REL)
            attrs = event.get("Attribute") or []
            if not isinstance(attrs, list) or not attrs:
                bad("%s Event has no Attribute list" % MISP_REL)
                attrs = []


print("== 1/5  the MISP event is a valid MISP document (pymisp parses it) ==")
# pymisp's object model rejects an unknown attribute type on load, so a parse
# here is a real check that every type we use is a genuine MISP type a MISP
# server would accept — not just a plausible-looking string.
if misp_text is None:
    bad("cannot validate: MISP event missing")
else:
    try:
        from pymisp import MISPEvent

        me = MISPEvent()
        me.load_file(os.path.join(ROOT, MISP_REL))
        ok("pymisp %s parsed the event (%d attributes, info=%r)"
           % (__import__("pymisp").__version__, len(me.attributes), me.info))
        if len(me.attributes) != len(attrs):
            bad("pymisp parsed %d attributes but the JSON has %d"
                % (len(me.attributes), len(attrs)))
    except Exception as exc:  # NewAttributeError, validation, import, ...
        bad("pymisp rejected the MISP event: %s: %s"
            % (type(exc).__name__, exc))


print("== 2/5  every published CSV row maps to one MISP attribute ==")
# value (transformed for composite types) -> list of matching MISP attributes
by_value = {}
for a in attrs:
    by_value.setdefault(a.get("value"), []).append(a)

expected_misp_values = set()
for rec in csv_rows:
    rid, ctype, cval = rec["id"], rec["type"], rec["value"]
    if ctype not in TYPE_MAP:
        bad("%s: CSV type %r has no MISP mapping (extend TYPE_MAP)" % (rid, ctype))
        continue
    want_type, want_cat = TYPE_MAP[ctype]
    want_val = misp_value_for(ctype, cval)
    expected_misp_values.add(want_val)
    matches = by_value.get(want_val, [])
    if not matches:
        bad("%s: no MISP attribute with value %r (CSV row not exported)"
            % (rid, want_val))
        continue
    if len(matches) > 1:
        bad("%s: %d MISP attributes share value %r" % (rid, len(matches), want_val))
    a = matches[0]
    if a.get("type") == want_type:
        ok("%s: %r is a %s" % (rid, want_val, want_type))
    else:
        bad("%s: value %r is type %r, expected %r"
            % (rid, want_val, a.get("type"), want_type))
    if a.get("category") != want_cat:
        bad("%s: value %r category %r, expected %r"
            % (rid, want_val, a.get("category"), want_cat))
    # A row with a detection rule is an actionable indicator (to_ids on); a
    # host-forensic row without one is a triage hint, not a blocking IoC
    # (to_ids off, and correlation disabled so a common port / loopback does
    # not pollute MISP correlations). This mirrors the CSV `rule` column.
    want_ids = bool(rec["rule"].strip())
    if bool(a.get("to_ids")) != want_ids:
        bad("%s: to_ids=%r, expected %r (rule column=%r)"
            % (rid, a.get("to_ids"), want_ids, rec["rule"]))
    if bool(a.get("disable_correlation")) != (not want_ids):
        bad("%s: disable_correlation=%r, expected %r"
            % (rid, a.get("disable_correlation"), not want_ids))
    if not (a.get("comment") or "").strip():
        bad("%s: MISP attribute has an empty comment (grounding/caveat lost)" % rid)


print("== 3/5  no MISP attribute is unaccounted for (bijection) ==")
actual_values = [a.get("value") for a in attrs]
if len(actual_values) != len(set(actual_values)):
    bad("the MISP event has duplicate attribute values")
extra = set(actual_values) - expected_misp_values
if extra:
    bad("MISP attribute(s) with no CSV row: %s" % ", ".join(sorted(map(repr, extra))))
elif csv_rows and not fail:
    ok("the %d MISP attributes are exactly the %d published CSV rows"
       % (len(attrs), len(csv_rows)))
elif not extra:
    ok("every MISP attribute corresponds to a CSV row")


print("== 4/5  the non-ASCII guard marker is preserved verbatim ==")
MARKER = "【ARTEX 平台管控·非目标防御】"
csv_has = any(r["value"] == MARKER for r in csv_rows)
misp_has = MARKER in actual_values
if csv_has and misp_has:
    ok("guard audit marker exported byte-for-byte")
elif not csv_has:
    bad("guard marker not found in the CSV (test assumption broke)")
else:
    bad("guard marker in the CSV but not exported to the MISP event")


def paths_for_trigger(text, trigger):
    """The quoted entries of `<trigger>: ... paths: [...]` in the workflow, or
    None if the trigger is absent. Small parser for a known-shape file."""
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
                break
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


print("== 5/5  CI triggers this test when the published indicators change ==")
# The MISP event derives only from the CSV, and both live under detections/**,
# so detections/** in the paths filter is the required and sufficient wiring:
# a change to the CSV or the MISP event triggers the detection workflow, which
# runs this suite and re-checks the two stay in sync. (The upstream Go sources
# the indicators are grounded in are enforced by the indicators suite's own
# CI-paths check, not here.)
wf_text = read(WORKFLOW_REL)
if wf_text is None:
    bad("CI workflow missing: %s" % WORKFLOW_REL)
else:
    for trigger in ("push", "pull_request"):
        listed = paths_for_trigger(wf_text, trigger)
        if listed is None:
            bad("%s has no %s: trigger" % (WORKFLOW_REL, trigger))
        elif "detections/**" in listed:
            ok("%s %s paths covers detections/** (CSV + MISP event)" % (WORKFLOW_REL, trigger))
        else:
            bad("%s %s paths is missing 'detections/**' — a change to the CSV or "
                "the MISP event would skip this test" % (WORKFLOW_REL, trigger))

print()
print("reference: %d CSV rows, %d MISP attributes, %d type mappings"
      % (len(csv_rows), len(attrs), len(TYPE_MAP)))
print("RESULT: %s" % ("PASS" if fail == 0 else "FAIL"))
sys.exit(fail)
