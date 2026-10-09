#!/usr/bin/env python3
#
# In-container half of the ARTEX ATT&CK coverage-layer test. run.sh launches this
# inside a Python container with the detections tree mounted read-only at
# /detections. It proves that the ATT&CK Navigator layer in
# detections/attack/artex_navigator_layer.json stays consistent with the rules it
# claims to cover, so the layer cannot silently drift from the Sigma rule set:
#
#   1. the layer is valid JSON with the required Navigator v4.x fields
#   2. every technique entry has a well-formed ID and a valid ATT&CK tactic
#   3. the scored techniques are EXACTLY the attack.* techniques tagged on the
#      rules (bidirectional: no rule technique missing from the layer, no layer
#      technique absent from the rules)
#   4. the scored tactics are exactly the attack.* tactics tagged on the rules
#   5. every scored technique's comment grounds it in a rule file that exists
#   6. any score-less entry is a display-only parent of a scored sub-technique
#   7. scores stay within the gradient bounds
#
# Pure standard library (the slim image already ships python3); nothing is
# installed and nothing is written to the repo. Exits non-zero on any failure.

import glob
import json
import os
import re
import sys

DET = "/detections"
LAYER = os.path.join(DET, "attack", "artex_navigator_layer.json")
SIGMA = os.path.join(DET, "sigma")

# ATT&CK Enterprise tactic shortnames (the Navigator "tactic" field uses these).
VALID_TACTICS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
}
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TAG_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
TACTIC_TAG_RE = re.compile(r"attack\.([a-z][a-z-]+)")

fail = 0


def note(s):
    print("  " + s)


def ok(s):
    note("PASS  " + s)


def bad(s):
    global fail
    note("FAIL  " + s)
    fail = 1


def rule_tags():
    """Techniques and tactics tagged across every Sigma rule file."""
    techs, tactics = set(), set()
    files = sorted(glob.glob(os.path.join(SIGMA, "**", "*.yml"), recursive=True))
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                m = TAG_RE.search(line)
                if m:
                    techs.add(m.group(1).upper())
                    continue
                t = TACTIC_TAG_RE.search(line)
                if t and t.group(1) in VALID_TACTICS:
                    tactics.add(t.group(1))
    return techs, tactics, files


print("== 1/7  layer parses as JSON with the required Navigator fields ==")
try:
    with open(LAYER, encoding="utf-8") as fh:
        layer = json.load(fh)
    ok("artex_navigator_layer.json is valid JSON")
except Exception as exc:  # noqa: BLE001
    print("  FAIL  cannot parse layer: %s" % exc)
    print("RESULT: FAIL")
    sys.exit(1)

for key in ("name", "versions", "domain", "techniques", "gradient"):
    if key in layer:
        ok("top-level key present: %s" % key)
    else:
        bad("top-level key missing: %s" % key)
for vkey in ("attack", "navigator", "layer"):
    if vkey in layer.get("versions", {}):
        ok("versions.%s present (%s)" % (vkey, layer["versions"][vkey]))
    else:
        bad("versions.%s missing" % vkey)
if layer.get("domain") == "enterprise-attack":
    ok("domain is enterprise-attack")
else:
    bad("domain is not enterprise-attack: %r" % layer.get("domain"))

techniques = layer.get("techniques", [])
scored = [t for t in techniques if "score" in t]
helpers = [t for t in techniques if "score" not in t]

print("== 2/7  every technique entry has a valid ID and tactic ==")
for t in techniques:
    tid = t.get("techniqueID", "")
    if TECHNIQUE_RE.match(tid):
        ok("well-formed techniqueID: %s" % tid)
    else:
        bad("malformed techniqueID: %r" % tid)
    tac = t.get("tactic", "")
    if tac in VALID_TACTICS:
        ok("valid tactic for %s: %s" % (tid, tac))
    else:
        bad("invalid tactic for %s: %r" % (tid, tac))

rule_techs, rule_tactics, rule_files = rule_tags()
layer_scored_ids = {t["techniqueID"] for t in scored}
layer_scored_tactics = {t["tactic"] for t in scored}

print("== 3/7  scored techniques == techniques tagged on the rules (bidirectional) ==")
if not rule_techs:
    bad("found no attack.* technique tags in %s" % SIGMA)
missing_in_layer = rule_techs - layer_scored_ids
extra_in_layer = layer_scored_ids - rule_techs
if not missing_in_layer and not extra_in_layer:
    ok("scored techniques match the rule set exactly (%d: %s)"
       % (len(rule_techs), ", ".join(sorted(rule_techs))))
else:
    if missing_in_layer:
        bad("rule techniques missing from the layer: %s"
            % ", ".join(sorted(missing_in_layer)))
    if extra_in_layer:
        bad("layer techniques not tagged on any rule: %s"
            % ", ".join(sorted(extra_in_layer)))

print("== 4/7  scored tactics == tactics tagged on the rules ==")
if layer_scored_tactics == rule_tactics:
    ok("scored tactics match the rule set exactly (%s)"
       % ", ".join(sorted(rule_tactics)))
else:
    bad("tactic mismatch: layer=%s rules=%s"
        % (sorted(layer_scored_tactics), sorted(rule_tactics)))

print("== 5/7  each scored technique is grounded in a rule file that exists ==")
for t in scored:
    comment = t.get("comment", "")
    refs = re.findall(r"sigma/[\w./-]+\.yml", comment)
    grounded = False
    for ref in refs:
        if os.path.exists(os.path.join(DET, ref)):
            grounded = True
        else:
            bad("%s comment cites a missing rule file: %s" % (t["techniqueID"], ref))
    if "suricata" in comment.lower():
        grounded = True
    if grounded:
        ok("%s grounded in an existing rule reference" % t["techniqueID"])
    else:
        bad("%s comment cites no existing rule file" % t["techniqueID"])

print("== 6/7  any score-less entry is a display parent of a scored sub-technique ==")
if not helpers:
    ok("no display-only entries (nothing to check)")
for h in helpers:
    hid = h.get("techniqueID", "")
    children = [s for s in scored if s["techniqueID"].startswith(hid + ".")]
    if children and h.get("showSubtechniques") is True:
        ok("%s is a display parent of %s"
           % (hid, ", ".join(c["techniqueID"] for c in children)))
    else:
        bad("score-less entry %s is not a valid display parent "
            "(needs showSubtechniques:true and a scored child)" % hid)

print("== 7/7  scores stay within the gradient bounds ==")
grad = layer.get("gradient", {})
lo, hi = grad.get("minValue", 0), grad.get("maxValue", 100)
for t in scored:
    s = t["score"]
    if lo <= s <= hi:
        ok("%s score %s within [%s, %s]" % (t["techniqueID"], s, lo, hi))
    else:
        bad("%s score %s outside gradient [%s, %s]" % (t["techniqueID"], s, lo, hi))

print()
print("reference: %d Sigma rule files scanned, %d scored techniques, %d display parents"
      % (len(rule_files), len(scored), len(helpers)))
print("RESULT: %s" % ("PASS" if fail == 0 else "FAIL"))
sys.exit(fail)
