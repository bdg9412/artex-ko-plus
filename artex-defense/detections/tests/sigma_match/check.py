#!/usr/bin/env python3
#
# Live event-matching test for the ARTEX Sigma rules (../../sigma/). check.sh
# installs a pinned pySigma inside a container and runs this script with the rule
# tree mounted read-only at /sigma and this directory at /src.
#
# WHAT THIS PROVES, AND WHY IT IS DIFFERENT FROM THE sigma/ SUITE
# --------------------------------------------------------------
# The sigma/ suite proves each rule is structurally valid and COMPILES to a
# backend query, and that its indicator strings survive into that query. It does
# NOT prove the rule actually fires on a matching event, or stays quiet on a
# benign one: a field renamed to something the log never carries, a wildcard that
# silently dropped, or an over-broad token would all still compile cleanly. The
# README's own principle is that "a detection you cannot run is only a claim," and
# the Suricata suite already backs its network rule with a real pcap replay
# (fires on the probe UA, silent on a benign browser). This suite closes the same
# gap for the host/log-layer Sigma rules on two levels:
#   - ATOMIC rules (../../sigma/*.yml): for each rule a representative malicious
#     event MATCHES and a benign event DOES NOT.
#   - CORRELATION rules (../../sigma/correlation/*.yml): for each rule a positive
#     timeline (threshold met, inside the window, within one group) FIRES and
#     negative timelines (below threshold, threshold met but spread beyond the
#     window, split across groups, or missing a leg) stay QUIET.
#
# HOW IT MATCHES (trust model)
# ----------------------------
# It does not hand-parse the YAML or re-implement Sigma's modifier logic. pySigma
# parses each rule and compiles its modifiers and condition into a tree:
# `|contains` becomes a wildcard-wrapped value, `|all` becomes an AND over values,
# `1 of selection_*` becomes an OR over the selection groups. This script only
# walks that compiled tree (AND / OR / NOT / field-equals / keyword) and tests
# each leaf against the event, so the authoritative parsing stays in pySigma. A
# leaf value or condition node this script does not explicitly support raises
# rather than passing silently (fail-closed), so a future rule using an
# unsupported construct surfaces loudly here instead of being waved through.
#
# For a correlation rule, pySigma likewise parses the aggregation spec — type
# (event_count / value_count / temporal), group-by fields, timespan, the
# threshold condition, and the resolved references to the atomic base rules. This
# script walks that parsed spec and applies it to a timeline, deciding which
# events feed each referenced rule with the very same atomic matcher above, so the
# Sigma logic again stays in pySigma; only the windowed aggregation is applied
# here. The correlation rules reference their atomics by id, so each is parsed in a
# collection that also holds every atomic rule (pySigma resolves the reference).
#
# SCOPE AND HONESTY (read before trusting a green run)
# ----------------------------------------------------
#  - The CORRELATION window is the standard sliding-window interpretation: a
#    window of `timespan` seconds anchored at each matching event, with inclusive
#    bounds. Each timeline event carries an integer `ts` in relative seconds. A
#    real SIEM's windowing (tumbling vs sliding, bound inclusivity, late arrival)
#    may differ; this is a regression test for the rule's group-by / timespan /
#    threshold logic — that it fires when they are satisfied and not when they are
#    not — rather than a bit-exact model of any one backend's correlation engine.
#  - Matching is CASE-INSENSITIVE. This mirrors the default of the splunk backend
#    the sigma/ suite targets, and the destructive rule's own false-positive note
#    assumes it (it warns that lowercase coreutils `truncate` shares the uppercase
#    `TRUNCATE ` token and must be allow-listed). Your SIEM's case handling and
#    field normalisation may differ; this is a regression test for the rules'
#    field/value/condition logic, not a substitute for validating in your stack.
#  - Keyword matching (the audit-framing rule) is modelled as a full-text
#    substring search across all event field values, the common interpretation of
#    an unbound Sigma keyword.
#
# Exits non-zero on any failure. Standard library only beyond pySigma.

import glob
import json
import os
import re
import sys

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.types import (
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

SIGMA_DIR = os.environ.get("SIGMA_DIR", "/sigma")
EVENTS_DIR = os.environ.get("EVENTS_DIR", "/src/events")
CORR_DIR = os.path.join(SIGMA_DIR, "correlation")
CORR_EVENTS_DIR = os.path.join(EVENTS_DIR, "correlation")

fail = 0


def note(msg):
    print(f"  {msg}")


def passed(msg):
    note(f"PASS  {msg}")


def bad(msg):
    global fail
    note(f"FAIL  {msg}")
    fail = 1


# --- matcher -------------------------------------------------------------------


def sigmastring_to_regex(value):
    """Compile a pySigma SigmaString (literal text plus wildcards) to an anchored,
    case-insensitive regex. `|contains` already wrapped the value in multi
    wildcards upstream, so a plain string compiles to an exact match and a
    contains-value compiles to a substring match — exactly the Sigma semantics."""
    parts = []
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(part, str):
            parts.append(re.escape(part))
        else:
            raise ValueError(f"unsupported SigmaString part: {part!r}")
    return re.compile("^" + "".join(parts) + "$", re.DOTALL | re.IGNORECASE)


def field_match(field, value, event):
    if field not in event:
        return False
    observed = str(event[field])
    if isinstance(value, SigmaString):
        return sigmastring_to_regex(value).search(observed) is not None
    if isinstance(value, SigmaNumber):
        return observed == str(value.number)
    if isinstance(value, SigmaNull):
        return event.get(field) is None
    if isinstance(value, SigmaRegularExpression):
        return re.search(value.regexp, observed) is not None
    raise ValueError(f"unsupported field value type: {type(value).__name__}")


def keyword_match(value, event):
    """Unbound keyword: full-text substring search across all field values."""
    if not isinstance(value, SigmaString):
        raise ValueError("unsupported keyword value type")
    if any(not isinstance(p, str) for p in value.s):
        raise ValueError("wildcard in keyword is not supported by this matcher")
    token = "".join(value.s)
    haystack = " ".join(str(v) for v in event.values())
    return token.lower() in haystack.lower()


def evaluate(node, event):
    if isinstance(node, ConditionAND):
        return all(evaluate(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(evaluate(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not evaluate(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return field_match(node.field, node.value, event)
    if isinstance(node, ConditionValueExpression):
        return keyword_match(node.value, event)
    raise ValueError(f"unsupported condition node: {type(node).__name__}")


def rule_matches(rule, event):
    return any(evaluate(c.parsed, event) for c in rule.detection.parsed_condition)


# --- correlation evaluator -----------------------------------------------------


def group_key(event, fields):
    if any(f not in event for f in fields):
        return None
    return tuple(event[f] for f in fields)


def correlation_fires(corr, timeline):
    """Apply a parsed SigmaCorrelationRule's aggregation to a timeline of events
    (each carrying an integer `ts` in seconds). pySigma has parsed the rule into a
    type, group-by fields, a timespan, a threshold condition, and resolved rule
    references; this walks that parsed structure. Membership in a referenced rule
    is decided by the same rule_matches the atomic suite uses, so the Sigma
    detection logic stays in pySigma. The window is the standard sliding window:
    `timespan` seconds anchored at each matching event, inclusive bounds."""
    ctype = str(corr.type)
    span = corr.timespan.seconds
    group_by = corr.group_by or []
    refs = [ref.rule for ref in corr.rules]

    if ctype in ("event_count", "value_count"):
        # A count correlation may reference several base rules; an event feeds the
        # count if it matches ANY of them — the same union the temporal branch
        # applies below. Looking at refs[0] alone would silently drop events
        # matching the other referenced rules, a fail-open this suite's header
        # forbids. With a single reference this reduces to the one-rule case, so
        # the existing rules (each referencing one base rule) are unchanged.
        matched = [e for e in timeline if any(rule_matches(r, e) for r in refs)]
        groups = {}
        for e in matched:
            key = group_key(e, group_by)
            if key is None:
                continue
            groups.setdefault(key, []).append(e)
        threshold = corr.condition.count
        fieldref = corr.condition.fieldref
        for members in groups.values():
            members = sorted(members, key=lambda e: e["ts"])
            for anchor in members:
                window = [
                    e for e in members if anchor["ts"] <= e["ts"] <= anchor["ts"] + span
                ]
                if ctype == "event_count":
                    if len(window) >= threshold:
                        return True
                else:
                    distinct = {e[fieldref] for e in window if fieldref in e}
                    if len(distinct) >= threshold:
                        return True
        return False

    if ctype == "temporal":
        groups = {}
        for e in timeline:
            key = group_key(e, group_by)
            if key is None:
                continue
            groups.setdefault(key, []).append(e)
        for members in groups.values():
            members = sorted(members, key=lambda e: e["ts"])
            for anchor in members:
                window = [
                    e for e in members if anchor["ts"] <= e["ts"] <= anchor["ts"] + span
                ]
                if all(any(rule_matches(r, e) for e in window) for r in refs):
                    return True
        return False

    raise ValueError(f"unsupported correlation type: {ctype}")


def require_ts(events, stem, label):
    for e in events:
        if not isinstance(e.get("ts"), int):
            raise ValueError(
                f"{stem} ({label}): every timeline event needs an integer 'ts' "
                f"(seconds); got {e!r}"
            )


# --- loaders -------------------------------------------------------------------


def load_atomic_rules():
    rules = {}
    for path in sorted(glob.glob(os.path.join(SIGMA_DIR, "*.yml"))):
        stem = os.path.splitext(os.path.basename(path))[0]
        collection = SigmaCollection.from_yaml(open(path, encoding="utf-8").read())
        for rule in collection.rules:
            # Only plain atomic rules; correlation rules carry a `.type` and are
            # handled separately below.
            if type(rule).__name__ != "SigmaRule":
                continue
            rules[stem] = rule
    return rules


def load_correlation_rules():
    """A correlation rule references its atomic base rules by id, so it must be
    parsed in a collection that also contains those atomics. For each correlation
    file, merge every atomic YAML with that one correlation YAML, parse the
    collection (pySigma resolves the reference), and key the resulting
    SigmaCorrelationRule by filename stem so it pairs with
    events/correlation/<stem>.json."""
    atomic_docs = [
        open(p, encoding="utf-8").read()
        for p in sorted(glob.glob(os.path.join(SIGMA_DIR, "*.yml")))
    ]
    corrs = {}
    for path in sorted(glob.glob(os.path.join(CORR_DIR, "*.yml"))):
        stem = os.path.splitext(os.path.basename(path))[0]
        merged = "\n---\n".join(atomic_docs + [open(path, encoding="utf-8").read()])
        collection = SigmaCollection.from_yaml(merged)
        found = [r for r in collection.rules if type(r).__name__ == "SigmaCorrelationRule"]
        if len(found) != 1:
            raise ValueError(f"{stem}: expected exactly 1 correlation rule, got {len(found)}")
        corrs[stem] = found[0]
    return corrs


def load_events(directory):
    events = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        stem = os.path.splitext(os.path.basename(path))[0]
        events[stem] = json.load(open(path, encoding="utf-8"))
    return events


def main():
    rules = load_atomic_rules()
    events = load_events(EVENTS_DIR)

    print("== atomic 1/3  every atomic rule is paired with a sample-event file ==")
    rule_stems = set(rules)
    event_stems = set(events)
    orphan_rules = sorted(rule_stems - event_stems)
    orphan_events = sorted(event_stems - rule_stems)
    if orphan_rules:
        bad(f"atomic rules with no events/<name>.json: {orphan_rules}")
    if orphan_events:
        bad(f"event files with no matching atomic rule: {orphan_events}")
    if not orphan_rules and not orphan_events:
        passed(
            f"rule/sample pairing: {len(rules)} atomic rules, "
            f"{len(events)} event files, no orphans"
        )

    print("== atomic 2/3  each rule matches its malicious sample events (true positives) ==")
    for stem in sorted(rule_stems & event_stems):
        rule = rules[stem]
        positives = events[stem].get("positive", [])
        if not positives:
            bad(f"{stem}: no positive sample events")
            continue
        missed = [e for e in positives if not rule_matches(rule, e)]
        if missed:
            bad(f"{stem}: {len(missed)}/{len(positives)} positive events did NOT match")
            for e in missed:
                note(f"        unmatched: {json.dumps(e, ensure_ascii=False)}")
        else:
            passed(f"{stem}: {len(positives)}/{len(positives)} positive events matched")

    print("== atomic 3/3  each rule rejects its benign sample events (true negatives) ==")
    for stem in sorted(rule_stems & event_stems):
        rule = rules[stem]
        negatives = events[stem].get("negative", [])
        if not negatives:
            bad(f"{stem}: no negative sample events")
            continue
        fired = [e for e in negatives if rule_matches(rule, e)]
        if fired:
            bad(f"{stem}: {len(fired)}/{len(negatives)} benign events WRONGLY matched")
            for e in fired:
                note(f"        wrongly matched: {json.dumps(e, ensure_ascii=False)}")
        else:
            passed(
                f"{stem}: {len(negatives)}/{len(negatives)} benign events correctly "
                "not matched"
            )

    corr_rules = load_correlation_rules()
    corr_events = load_events(CORR_EVENTS_DIR)

    print("== correlation 1/3  every correlation rule is paired with a timeline file ==")
    corr_stems = set(corr_rules)
    ce_stems = set(corr_events)
    orphan_corr = sorted(corr_stems - ce_stems)
    orphan_tl = sorted(ce_stems - corr_stems)
    if orphan_corr:
        bad(f"correlation rules with no events/correlation/<name>.json: {orphan_corr}")
    if orphan_tl:
        bad(f"timeline files with no matching correlation rule: {orphan_tl}")
    if not orphan_corr and not orphan_tl:
        passed(
            f"rule/timeline pairing: {len(corr_rules)} correlation rules, "
            f"{len(corr_events)} timeline files, no orphans"
        )

    print("== correlation 2/3  each rule fires on its positive timelines (true positives) ==")
    for stem in sorted(corr_stems & ce_stems):
        corr = corr_rules[stem]
        positives = corr_events[stem].get("positive", [])
        if not positives:
            bad(f"{stem}: no positive timelines")
            continue
        for tl in positives:
            require_ts(tl["events"], stem, tl["label"])
            if correlation_fires(corr, tl["events"]):
                passed(f"{stem}: fired — {tl['label']}")
            else:
                bad(f"{stem}: did NOT fire on a positive timeline — {tl['label']}")

    print("== correlation 3/3  each rule stays quiet on its negative timelines (true negatives) ==")
    for stem in sorted(corr_stems & ce_stems):
        corr = corr_rules[stem]
        negatives = corr_events[stem].get("negative", [])
        if not negatives:
            bad(f"{stem}: no negative timelines")
            continue
        for tl in negatives:
            require_ts(tl["events"], stem, tl["label"])
            if correlation_fires(corr, tl["events"]):
                bad(f"{stem}: WRONGLY fired on a benign timeline — {tl['label']}")
            else:
                passed(f"{stem}: quiet — {tl['label']}")

    print()
    try:
        import importlib.metadata as md

        print(f"reference: pySigma {md.version('pysigma')}, atomic + correlation rules")
    except Exception:
        pass
    print("RESULT: PASS" if fail == 0 else "RESULT: FAIL")
    sys.exit(fail)


if __name__ == "__main__":
    main()
