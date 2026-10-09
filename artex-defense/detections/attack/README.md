# ARTEX ATT&CK coverage

English · [한국어](README.ko.md)

> 한국어: 이 디렉터리는 [`../`](../)의 ARTEX 탐지 규칙(Sigma·Suricata)이 다루는 공격 기법을
> [MITRE ATT&CK](https://attack.mitre.org/) 전술·기법으로 정리한 **커버리지 레이어**입니다.
> 각 기법은 저장소 소스에 근거가 있는 규칙의 `attack.*` 태그에서만 가져왔고, 추정으로 넣은 항목은
> 없습니다. [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)에 그대로 올려
> 어떤 ARTEX 행위에 어떤 규칙이 걸리는지 한눈에 볼 수 있습니다. 이 레이어는 자신이 소유하거나 서면
> 허가를 받은 시스템을 지키는 **방어·탐지 목적에만** 쓰십시오. 한국어 전체 문서는
> **[README.ko.md](README.ko.md)** 를 보십시오.

A [MITRE ATT&CK](https://attack.mitre.org/) Navigator layer that maps the detection rules in this
repository to the ATT&CK (Enterprise) techniques they tag. It is built by hand from the `attack.*` tags on
the [Sigma rules](../sigma/) — every technique is grounded in a rule whose indicator is a string or
behaviour verified in this repository's source, and the [consistency test](../tests/attack/run.sh)
keeps the layer and the rules from drifting apart.

- **`artex_navigator_layer.json`** — the layer, in ATT&CK Navigator v4.5 format.

## What the score means

Coverage here means "this repository ships a detection that tags this technique", not "this technique is
fully covered". The score is deliberately honest about detection strength:

- **100 — ARTEX-specific signature or behaviour.** A static indicator unique to ARTEX (the
  `artex-enrich/1.0` / `artex-selfupdate` User-Agents, the guard audit marker) or a behaviour rule built
  on one (enrichment velocity / fan-out, guard-block burst).
- **50–65 — generic hunting lead.** Destructive-command hunting mirrored from the ARTEX guard deny list.
  The same commands are run by legitimate administrators, so these fire on benign activity too; treat a
  hit as a lead, not an attribution. 65 marks the case where a correlation rule raises specificity by
  pairing the command with the ARTEX guard marker.

## Techniques covered

Eight techniques across six tactics. Each maps to the rule(s) that tag it:

- **Reconnaissance — T1595 (Active Scanning), T1592 (Gather Victim Host Information).**
  [`sigma/artex_enrich_user_agent.yml`](../sigma/artex_enrich_user_agent.yml),
  [`sigma/correlation/artex_enrich_scan_velocity.yml`](../sigma/correlation/artex_enrich_scan_velocity.yml),
  [`sigma/correlation/artex_enrich_fanout.yml`](../sigma/correlation/artex_enrich_fanout.yml), and the
  [Suricata rules](../suricata/artex.rules) (sid 1000001 / 1000002).
- **Command and Control — T1105 (Ingress Tool Transfer).**
  [`sigma/artex_selfupdate_egress.yml`](../sigma/artex_selfupdate_egress.yml).
- **Execution — T1059 (Command and Scripting Interpreter).**
  [`sigma/artex_guard_audit_framing.yml`](../sigma/artex_guard_audit_framing.yml),
  [`sigma/correlation/artex_guard_block_burst.yml`](../sigma/correlation/artex_guard_block_burst.yml),
  [`sigma/correlation/artex_guard_marker_then_destructive.yml`](../sigma/correlation/artex_guard_marker_then_destructive.yml).
- **Impact — T1485 (Data Destruction), T1561.002 (Disk Wipe: Disk Structure Wipe), T1489 (Service Stop).**
  [`sigma/destructive_command_hunting.yml`](../sigma/destructive_command_hunting.yml), with T1485 also
  reinforced by
  [`sigma/correlation/artex_guard_marker_then_destructive.yml`](../sigma/correlation/artex_guard_marker_then_destructive.yml).
- **Credential Access / Collection — T1557 (Adversary-in-the-Middle).**
  [`sigma/artex_recording_proxy_ca.yml`](../sigma/artex_recording_proxy_ca.yml) — the MITM root-CA artifact
  ARTEX's embedded traffic recorder installs (`traffic/traffic.go`) to decrypt and log the worker tools'
  traffic. A host/forensic hunting lead.

## How to use it

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. Choose **Open Existing Layer → Upload from local**, and select `artex_navigator_layer.json` (or point
   it at the raw file URL from this repository).
3. The scored techniques appear colour-graded by detection strength, each with a comment naming the rule
   file(s) and the defense-guide section behind it.

## Scope and honesty

- **Coverage is not completeness.** A technique scored here means a rule tags it, not that every variant
  of the technique is detected. Only two ARTEX-unique User-Agents are visible on the wire — the enrichment
  prober (`artex-enrich/1.0`) in the reconnaissance phase and the norma SDK WebFetch tool (`norma/0.4`) in
  the attack phase — while the rest of the attack traffic follows tool-default fingerprints; the durable
  detection is behavioural
  (see the defense guide, [Korean](../../docs/defense-ko.md) · [English](../../docs/defense-en.md), sections 1–2 and 4.1–4.2). The pure web multi-stage
  case still needs base rules specific to your environment.
- **Static indicators can be changed.** An operator can set a different User-Agent, so the absence of a
  tagged indicator does not imply safety. This is the same caveat the rule files carry.

## Validate and contribute

Run the [consistency test](../tests/attack/run.sh) — it needs only Docker and asserts that the layer's
scored techniques and tactics are exactly the `attack.*` tags on the rules, with every technique grounded
in a rule file that exists:

```sh
detections/tests/attack/run.sh
```

When you add or retag a rule, update this layer to match — the test fails if a rule technique is missing
from the layer or a layer technique is absent from the rules. See [`../README.md`](../README.md) and
[`../../CONTRIBUTING.en.md`](../../CONTRIBUTING.en.md).
