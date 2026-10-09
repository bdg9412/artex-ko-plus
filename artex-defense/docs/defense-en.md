# Defending Against and Detecting Autonomous AI Attacks

> This document helps **defenders** understand how an **autonomous AI penetration agent** such as ARTEX operates, so that you can build the capability to **detect and block** such attacks. It is not a guide to carrying out attacks. Use everything here only to protect systems you own or have explicit written authorization to test. Probing or attacking someone else's information and communications network without authorization is itself a crime (see the [security and misuse warning in the top-level README](../README.en.md)).
>
> 한국어판: **[자율 AI 공격 방어·탐지 가이드 (defense-ko.md)](defense-ko.md)**.

An autonomous AI attack tool turns a penetration test — once a manual process a single operator ran by hand — into a 24/7 automated process in which an LLM agent **breaks goals down on its own, executes real tools, and accumulates discoveries**. The adversary a defender faces shifts from "one skilled attacker" to "a swarm of agents that never tire and never rest." This guide sets out what that shift demands of detection and response.

---

## 1. How an autonomous AI attack differs from a traditional scanner

A traditional vulnerability scanner (for example a fixed-signature tool) fires a predefined checklist in order and stops. An autonomous agent like ARTEX is structured differently. As described in the [system architecture](../README.en.md#system-architecture), the following elements combine to **run multi-stage attack chains to completion without human intervention**:

- **Role-separated multi-agents.** The work is split across `goals` (which decomposes objectives), a `planner` (the only producer of intents, which decides the next direction), multiple `worker`s (each of which executes one intent with real tools), and a `mainagent` (the human-in-the-loop point). The planner is the sole intent generator, and the workers carry those intents out in parallel.
- **State accumulated in a dual graph.** "What exists" (the asset graph) and "how far it has been tested" (the exploration graph) are built separately and joined by anchors. As a result the attack **deepens incrementally**, revisits the same asset from new angles, and builds each next step on prior observations.
- **An event-driven closed loop.** Every time the graph changes, the planner wakes, assigns the next intent, and the worker's writes trigger the next round in turn. This cycle does not stop until a goal is proven.
- **Stable progression of serial attack chains.** The planner records dependency ordering — "find an injection point → obtain credentials → move laterally → escalate privileges" — once into a shared todolist, and only assigns an intent to the next step once its predecessor is satisfied. So the attack chain runs to completion without derailing, even in a stateless session environment.
- **The LLM varies payloads per context.** Because the tools and payloads it executes are not fixed constants in code but values the LLM generates by reading the situation, the shape of each individual request varies slightly.

### Why this is harder to detect

- **Fixed signatures match poorly.** Because payloads change with context, rules that match a known malicious string exactly (WAF signatures) are easy to slip past.
- **It can proceed slowly, and in human-like bursts.** The agent rests between rounds and changes direction based on findings, so detection based purely on rate ("many requests in a short window") can miss it.
- **Reconnaissance and intrusion run as one flow.** The gap in which a human reviews recon results and then attacks manually days later disappears, so the time from first contact to data exfiltration shrinks dramatically.

### Why it can still be detected — behavior is hard to hide

Static fingerprints (the User-Agent, a specific payload string) can be changed at the operator's discretion. But the **behavioral pattern of an autonomous agent** is the essence of the attack and is hard to change. Sections 2 through 4 below weight this behavior-based view.

- A single source (or a small set of rotating sources) **chains requests of several different characters** (reconnaissance → enumeration → authentication attempts → exploitation) **within a coherent session**.
- Exploration that **continues without pause** even during hours when a human would stop out of fatigue.
- Adaptive, non-random progression that **systematically mutates the next request** using hints from failed responses.

---

## 2. Fingerprints a defender can observe (IoCs and signatures)

Split the fingerprints into two views. **(a) The target (victim) view** — what you can see in ARTEX traffic aimed at your system. **(b) The operator/forensic view** — what you can see on a host where ARTEX actually ran (or on a compromised relay). It is important not to mix the two. The static fingerprints visible from the target side are limited; the behavioral fingerprints are the core.

### (a) Target view — traffic aimed at your system

- **The enrichment lookup User-Agent `artex-enrich/1.0`.** When ARTEX automatically enriches an asset (DNS and HTTP checks), it sends a direct `GET` to the target with this User-Agent (`enrich/enrich.go`). This path is generated by ARTEX itself, independent of the LLM, and is characterized by **not following redirects, disabling keep-alive, and reading only the start of the response to extract the `<title>`**. The default concurrency is 4. So when lookups with the `artex-enrich/1.0` UA that **open a short-lived connection, issue a single GET, read only the title, and disconnect** arrive at several assets at once, they strongly suggest ARTEX-family enrichment traffic. However, the operator can change the UA, so **its absence does not mean safety**.
- **The actual attack traffic follows the tool's default fingerprint.** The worker sends requests through the real tools it runs (external tools executed via Bash, plus HTTP). To route this traffic through its own recording proxy, ARTEX injects `HTTP_PROXY` and the proxy CA path into the subprocess environment variables — but it **does not force an ARTEX-specific User-Agent onto attack traffic**. So the User-Agent and headers the target sees are **the defaults of whatever tool ran at that moment** (the default UA of the various command-line tools). If the operator did not customize it, a common automation-tool fingerprint remains; if they did customize it, the traffic may be disguised to look like a normal browser. Therefore, **do not rely on single-UA matching; combine it with behavior-based detection**.
- **The worker's built-in WebFetch tool leaves a `norma/0.4` User-Agent.** Unlike the external tools the worker runs via Bash (above), the HTTP lookups ARTEX performs directly through the norma SDK (`github.com/Autumn-27/norma`) — its WebFetch tool — carry that SDK's default User-Agent `norma/0.4` during the attack phase. It is observable on the wire where traffic is plaintext HTTP (or inspected at a TLS-terminating point), and a [Suricata rule (sid 1000003)](../detections/suricata/) matches this prefix (`norma/`). However, this UA is **not ARTEX-unique** — other tools built on the norma SDK share it — so, like `artex-enrich/1.0`, it is a supporting clue rather than proof, and because Bash-run tools use their own UAs, **its absence does not mean safety**.
- **There is no built-in rate limit.** ARTEX itself has no target-traffic rate limiting, and the request rate is decided by the external tools the LLM drives. Instead, by default 3 workers per task run in parallel, so **several intents may proceed against one target simultaneously**. That means the attack can appear as a "slow single session" or as "multiple angles running at once," so a single fixed threshold is hard to catch it with.
- **Behavioral signatures (most important).** The **co-occurrence** of the patterns below points to an autonomous agent:
  - From one source (or a small set of rotating sources), **reconnaissance → directory/endpoint enumeration → parameter probing → authentication/injection attempts chain at short intervals**.
  - Consecutive requests to the same endpoint that **mutate systematically in response to the status code and length** of the reply (adaptive, not random fuzzing).
  - A session that **continues without pause for long stretches**, outside normal human operating hours.
  - Persistence that keeps trying **bypass variations** even after failures (401/403/429) instead of stopping.

### (b) Operator/forensic view — a host where ARTEX ran

Use these when, during an intrusion investigation, you look for traces of ARTEX installed and run on a relay/transit host.

- **Default listening port `:8787`.** This is the default HTTP listening address of the ARTEX server (`cmd/artex/main.go`, changeable with `--addr`). If an internal host is serving the management UI (dashboard, tasks, asset graph) on this port, that is grounds to suspect an ARTEX instance.
- **The recording MITM proxy `127.0.0.1:8788`.** This is the default address of the local proxy that intercepts and records every worker Bash/HTTP execution end to end (the default of `--proxy` in `cmd/artex/main.go`, loopback only). Because it generates its own CA to decrypt and record TLS (`mitmproxy-ca-cert.pem`), two clues help: whether the host carries **a trusted CA certificate installed by ARTEX**, and whether there are traces of `HTTP_PROXY` and proxy-CA-path environment variables being injected into subprocesses. This injection goes into every worker tool ARTEX spawns and the variable names are hard-coded in the source (`agent/worker.go`), so **a running process carrying a proxy var together with a mitmproxy CA-trust var** is a more specific tell than the bare port. The [host-triage tool](../detections/triage/README.md) checks for this combination in `/proc` (or, for a forensic image, a captured env dump).
- **The self-update callback `artex-selfupdate`.** This is the User-Agent used when the self-updater queries GitHub releases (`selfupdate/`). If egress logs show requests leaving for a code-repository host with this UA, that suggests the presence of an ARTEX binary.
- **The dual graph in PostgreSQL.** A database with tables such as `exploration_nodes`, `assets`, `companies`, and `activity`, plus an `agent_prompts` seed, is characteristic of the ARTEX data store.
- **DB-backed regex approval rules and audit log.** The intercept rules that evaluate tool calls are stored in the DB and evaluated by priority as regular expressions (`intercept/`). Blocked calls are recorded in the audit log (`GET /api/audit`) together with a control framing that begins with `【ARTEX 平台管控·非目标防御】` (a "platform control / non-target defense" framing). So if this string appears in a compromised host's audit records, it supports the conclusion that ARTEX ran there.
- **Destructive-command hunting indicators.** The command patterns ARTEX's own guard embeds as block targets are, in effect, the mirror image of the command family an autonomous agent **might attempt**. In host command auditing, treat the following as hunting indicators: `rm -rf`, `mkfs`, `dd of=/dev/`, `shred`/`wipe`, SQL `DROP DATABASE`/`DROP TABLE`/`TRUNCATE`, MongoDB `drop`/`dropDatabase`, Redis `FLUSHALL`/`FLUSHDB`, `-X DELETE` on `curl`/`wget`, and data-exfiltration pipes of the form `curl … | nc …`. That said, the data-exfiltration pipe at the end is different in kind. It is not a destruction command but a signal that data is being carried out (exfiltration), and unlike the destruction patterns above, ARTEX's guard embeds this one rule disabled by default (its curl/wget/nc pipe pattern misfires on legitimate pentest reverse-shell and data-transfer pipes). The deployable destructive-command hunting rule ([`destructive_command_hunting.yml`](../detections/sigma/destructive_command_hunting.yml)) is scoped to destruction and does not include it, so hunt the exfiltration pipe as a separate, heavily tuned indicator rather than blocking it outright.

> In short: **anchor target-side defense on behavioral fingerprints, and use static UAs (`artex-enrich/1.0`, `norma/0.4`, and the like) only as supporting clues.** The operator/forensic fingerprints (`:8787`, `127.0.0.1:8788`, `artex-selfupdate`, the DB schema, the audit-log framing) are valid **when investigating a compromised transit host**.

### Why IP-address blocking is a weak first line of defense

When a security incident becomes known, posts that say "here is a shared list of attacker IPs — block them at your firewall" commonly circulate on social media and community forums. Whatever the good intent of those sharing them, **we do not recommend dropping an unofficial IP list of unclear provenance straight into your block rules** — and this holds especially against autonomous AI attacks.

- **The source is hard to verify.** For an unofficial list posted by an individual, there is no way to confirm who collected it or on what basis, and no way to filter out the IPs unrelated to the incident that may be mixed in.
- **It ages quickly.** An autonomous agent constantly rotates its origin IP through VPNs, cloud instances, and hijacked relay servers (the "small number of rotating sources" in (a) above). An attack IP observed yesterday was likely already discarded today, so blocking the list still lets the attacker return from a different IP.
- **The false-blocking risk is high.** If the list mixes in shared ranges, CDNs, or legitimate cloud IPs, the moment you block them you also cut off healthy customer traffic or internal services. Combined with automatic blocking (section 6 below), the false-block damage spreads even faster.

This does not mean IP blocking is useless. It becomes meaningful **when you receive official indicators of compromise (IoCs) from a response agency or trusted threat intelligence and apply them after reviewing their validity window and false-positive potential.** But blocking a single IP line is only a stopgap that chases a rotating origin; what lasts is the **behavior** that is hard to change (the behavior-based detection in sections 2–4) and the **reduction of attack surface** (the hardening in sections 3 and 5 — trimming exposed assets, patching, MFA). This guide's premise — fingerprints can change, but behavior is hard to hide — applies here too.

---

## 3. Entry points attackers target, and hardening

An autonomous agent targets the **same weaknesses** a human attacker does, but repeats them faster and more relentlessly. Below are the priority hardening points from a defender's view.

### 3.1 Externally exposed attack surface and known (n-day) vulnerabilities

The first and most reliable entry point an autonomous agent targets is not a clever zero-day but a **known, already-disclosed vulnerability left exposed and unpatched**. Typical targets are perimeter devices (VPNs, firewalls), externally reachable management/operations consoles, application servers, middleware, and frameworks (for example widely exploited WebLogic- or Struts-class software), and **auxiliary systems attached for partners, recruitment, or employees rather than the main service**. An autonomous agent enumerates the exposed surface automatically from its asset graph, then targets n-days with public exploits (PoCs) **before the patch is applied**, across hundreds of assets at once. The speed of this find-an-exposed-weakness-and-try-it loop is where the asymmetry with a human attacker opens up.

- **Reduce the attack surface.** Continuously maintain an inventory of internet-exposed assets, management consoles, and auxiliary systems, and move anything that does not need to be external behind the internal network, a VPN, or an allowlist.
- **Patch known vulnerabilities fast.** Disclosed vulnerabilities (n-days) in perimeter devices, web servers, application servers, and middleware are an autonomous agent's top target, so keep the patch-application interval as short as possible, starting with components that have public PoCs. To decide what to patch first, use a catalog of vulnerabilities with confirmed in-the-wild exploitation as a prioritization input: cross-reference the [CISA KEV (Known Exploited Vulnerabilities) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) with the domestic advisories in 7.1 (KISA / Boho Nara). Relying on a living official list like this, rather than pinning specific CVE numbers in a document, keeps you from falling behind as an autonomous agent shifts to whichever n-day is circulating next.
- **Tighten interfaces that must stay exposed.** For management/operations interfaces you cannot avoid exposing, add source restrictions (IP allowlists), MFA, and a VPN to block unauthenticated enumeration itself.
- **Manage auxiliary systems to the same standard as the main service.** Keep partner, recruitment, and employee auxiliary systems at the same patch and monitoring level as the main service. The entry point an autonomous agent works through is often one of these auxiliary paths rather than the main service. Hardening of the authentication flow itself continues in 3.2 below.

For detection, requests that target a specific vulnerability's known path (URL, parameters) arriving from outside in a short-interval chain are a signal of n-day scanning. This signal shows up best when combined with the behavioral fingerprints in Section 2 and the same-source multi-stage correlation rule in Section 4.

### 3.2 Auxiliary authentication and identity-verification flows

**Authentication and identity-verification flows attached through a different path than the main service** — add-on services, partner channels, recruitment channels — are often loosely validated and become bypass targets. An autonomous agent enumerates these paths automatically and reads response differences to find bypass conditions systematically.

- Unify identity-verification and authentication steps **to the same strength as the main service**, and audit every auxiliary path that could be bypassed.
- **Re-verify authentication state transitions** (unauthenticated → authenticated, user → privileged) **on the server**, and do not blindly trust the trust markers the client sends (cookies, headers, parameters).
- Check the **lifetime, reuse, and guessability** of identity-verification tokens and one-time codes.

### 3.3 API authentication and authorization (IDOR and privilege escalation)

- Enforce a **server-side ownership/authorization check** on every object access (block IDOR, where changing only an identifier opens someone else's resource).
- Enumerate horizontal and vertical privilege-escalation paths yourself. Because an autonomous agent mechanically increments and decrements identifiers and tries them in bulk, it quickly finds **holes that a single manual test missed**.

### 3.4 Credential stuffing

Attacks that replay leaked ID/password lists are amplified by an autonomous agent through **speed and distribution**.

- Apply **adaptive rate limiting** (based on IP, account, device, and behavior) to login and identity-verification endpoints.
- Enforce **multi-factor authentication (MFA)** on sensitive operations. Even if stuffing lands a correct password, the second factor blocks it.
- Block preemptively with **compromised-credential detection** (checking against known leak lists; anomalous login location/velocity).
- Alert on **distribution shifts** in login failures and successes (a sudden low-and-wide attempt).

### 3.5 Session, token, and secret management

- Minimize the **scope, lifetime, and renewal** of session tokens, and re-authenticate at every sensitive transition.
- **Do not expose** API keys or internal tokens in responses, logs, or error messages (an autonomous agent actively harvests clues from error responses).

---

## 4. Detection rules and log patterns (practical)

Written as product-independent **pseudo-rules**. Translate them into your own WAF/IPS/SIEM syntax. The rules below that rest on static fingerprints are shipped as ready-to-deploy [Sigma rules (`detections/sigma/`)](../detections/). The core behavior and correlation detection (4.1 and 4.2) does not reduce to a single rule either, but the behavioral indicators grounded in ARTEX's source are shipped as deployable [Sigma correlation rules (`detections/sigma/correlation/`)](../detections/) — enrichment velocity, enrichment fan-out, guard-block burst, and the guard marker co-occurring with a destructive command on one host. The pure web multi-stage correlation (enumerate → probe → authenticate) still needs base rules specific to your environment, because that multi-stage pattern does not reduce to a single ARTEX-unique User-Agent; a ready-to-tune generic Sigma base template for it is provided in 4.2 below — adapt it to your SIEM and baseline as a starting point. The two ARTEX User-Agents observable on the wire — the enrichment prober's `artex-enrich/1.0` (sid 1000001–1000002) and the norma SDK WebFetch tool's attack-phase `norma/0.4` (sid 1000003) — are also shipped as [Suricata rules (`detections/suricata/`)](../detections/suricata/).

### 4.1 WAF/IPS (behavior-based)

- When **requests of different characters** from a single source (a low share of static-resource requests, a high share of enumeration, parameter probing, and authentication attempts) **continue as one session**, raise the score.
- Weight **consecutive requests that mutate in response** to status code and body length (high entropy but an adaptive, non-random pattern).
- Tag a known automation UA such as `artex-enrich/1.0` as **immediately high-risk**, but do not read the absence of a UA as safety.

### 4.2 SIEM correlation rules

- **Same-source multi-stage correlation:** when (a) directory/endpoint enumeration, (b) parameter probing, and (c) authentication/injection attempts are **all observed within a short window** from the same IP/ASN/session, raise an "autonomous attack suspected" alert.
- **Time-of-day anomaly:** a single session that **continues without pause for a long stretch**, outside the service's normal traffic distribution.
- **Persistence after failure:** a source that receives 403/429 and keeps going with **bypass variations** instead of stopping.

A deployable base template for the **same-source multi-stage correlation** above follows. Because the attack traffic carries no ARTEX-unique User-Agent, this template is a **generic behavioral rule**, unlike the ARTEX-source-grounded rules under `detections/sigma/`. It watches only the behavior — "one source runs enumeration, probing, and authentication within a short window" — not any attack tool's fingerprint. It is self-contained: three sub-rules plus a temporal correlation that fires only when one client satisfies all three within the window.

```yaml
# ── Generic behavioural template (NOT an ARTEX-specific signature) ──
# The same-source multi-stage web pattern in defense guide section 4.2
# (enumeration -> probe -> auth). ARTEX's attack traffic carries no ARTEX
# fingerprint, so unlike the rules under detections/sigma/ this is a generic
# behavioural starting point, not grounded in ARTEX source. Field names
# (SigmaHQ webserver taxonomy) and the thresholds/window WILL need tuning to
# your own logs and baseline. Self-contained: three sub-rules plus a temporal
# correlation that fires only when all three occur from one client in the window.
title: Web Endpoint Enumeration Burst From One Source
id: f03c360c-dc33-4a8a-afa8-821b1ff5c4e3
status: experimental
description: |
    Stage 1 of the same-source multi-stage pattern in the ARTEX defense guide section 4.2: a
    burst of endpoint or directory enumeration from a single client, seen as a high rate of 404
    and 400 responses in a short window. This is generic behaviour, not an ARTEX-specific
    signature; tune the count and window to your own baseline. On its own this leg is low signal
    and earns weight only inside the correlation below.
references:
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-ko.md
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-en.md
author: artex-ko defense guide (generic template)
date: 2026-10-07
tags:
    - attack.reconnaissance
    - attack.t1595
logsource:
    category: webserver
detection:
    enum_misses:
        sc-status:
            - 404
            - 400
    condition: enum_misses
falsepositives:
    - Broken links, authorised vulnerability scanners, or misconfigured clients that generate
      many 404 responses.
level: low
---
title: Web Parameter Or Path Injection Probe From One Source
id: f9296e55-6b7a-4030-b5f7-5f7b146233be
status: experimental
description: |
    Stage 2 of the same-source multi-stage pattern: parameter or path probing, matched here as
    query strings carrying common injection or traversal markers. This leg is unavoidably
    signature-like and noisy on its own, so it is scored low and earns weight only inside the
    correlation below. Extend the marker list to your own probe corpus and WAF categories; it is
    a coarse proxy for the broader "adapts requests to responses" behaviour the guide describes.
references:
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-ko.md
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-en.md
author: artex-ko defense guide (generic template)
date: 2026-10-07
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: webserver
detection:
    probe_markers:
        cs-uri-query|contains:
            - '../'
            - "' or "
            - ' union select '
            - '<script'
            - '; drop '
    condition: probe_markers
falsepositives:
    - Legitimate request payloads that resemble probe markers; tune the marker list to your
      application.
level: low
---
title: Authentication Or Identity-Verification Attempt From One Source
id: 2614cacb-7455-46ad-9af2-7b9633f12d7b
status: experimental
description: |
    Stage 3 of the same-source multi-stage pattern: requests to login, authentication, or
    identity-verification endpoints, or 401 and 403 responses. Map the paths and your own
    authentication-event fields to your application; auxiliary, affiliate, and broker channels
    often expose weaker identity-verification endpoints than the main service and belong here
    too. This leg is broad by design and is only meaningful inside the correlation below.
references:
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-ko.md
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-en.md
author: artex-ko defense guide (generic template)
date: 2026-10-07
tags:
    - attack.credential-access
    - attack.t1110
logsource:
    category: webserver
detection:
    auth_path:
        cs-uri-stem|contains:
            - '/login'
            - '/auth'
            - '/verify'
            - '/otp'
    auth_deny:
        sc-status:
            - 401
            - 403
    condition: auth_path or auth_deny
falsepositives:
    - Ordinary users signing in; this leg is broad and only meaningful inside the correlation.
level: low
---
title: Same-Source Multi-Stage Web Attack (Enumeration, Probe, Auth)
id: 9b7c7b86-702f-42b8-be99-3e60a188ec5b
status: experimental
description: |
    The behaviour-based core of ARTEX defense guide section 4.2 as a deployable template: one
    client runs endpoint enumeration, parameter or path probing, and an authentication or
    identity-verification attempt within the same short window. This is the pattern an autonomous
    agent drives at machine speed and keeps driving past 403 and 429 responses. It is UA-free and
    carries no ARTEX fingerprint, so it is a GENERIC behavioural rule, not one of the
    ARTEX-source-grounded rules under detections/sigma/. Normalise the client field (c-ip, or a
    session identifier if you have one) and tune the window to your baseline. If three legs are
    too strict and miss cases, relax to any two of the three.
references:
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-ko.md
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-en.md
author: artex-ko defense guide (generic template)
date: 2026-10-07
tags:
    - attack.initial-access
    - attack.t1190
correlation:
    type: temporal
    rules:
        - f03c360c-dc33-4a8a-afa8-821b1ff5c4e3
        - f9296e55-6b7a-4030-b5f7-5f7b146233be
        - 2614cacb-7455-46ad-9af2-7b9633f12d7b
    group-by:
        - c-ip
    timespan: 10m
falsepositives:
    - An authorised vulnerability scan or QA run from a single source; allow-list its address.
level: high
```

Notes for using this template:

- This block was validated with the same tooling the detection pack uses: `sigma check` with the full SigmaHQ convention set passes with 0 errors and 0 issues, and `sigma convert -t splunk` produces a query (the three sub-rules binned to a 10-minute window, grouped by `c-ip`, firing when all three are present). It is kept out of the tested `detections/` rule tree because it cannot be grounded in ARTEX source — that preserves the tree's promise to ship only what is "confirmed in this repository's source, not assumed." These facts are not a one-time measurement: [`detections/tests/check-defense-template.sh`](../detections/tests/check-defense-template.sh) re-runs them in CI on every change to this guide (the `sigma check` pass, the splunk/eql/loki conversions, the lucene/kusto rejection, and that the Korean and English copies carry a byte-identical rule body), so the claims here cannot silently drift from an upstream `sigma-cli` change.
- Because this template is a correlation rule, whether `sigma convert` emits the whole template or only the three sub-rules depends on the backend's support for Sigma correlation conversion. Measured with the same pinned `sigma-cli` 3.1.0: the whole template converts on Splunk (`-t splunk`), Elasticsearch EQL (`-t eql`), and Grafana Loki (`-t loki`). On the Microsoft `kusto` backend (Sentinel and Defender) and Elasticsearch Lucene (`-t lucene`) the correlation does not convert (`Backend does not support correlation rules`), so convert the three sub-rules only and express the 10-minute, same-`c-ip` correlation natively in the product (for example, a Sentinel scheduled-analytics `summarize ... by bin(TimeGenerated, 10m), <client>`). This is the same portability the detection pack documents; the measured support matrix is in [Sigma backend portability](../detections/README.md#sigma-backend-portability).
- Stage 2 (probing) rests on a list of injection/traversal markers and is a coarse, noisy signal on its own. That is why the three sub-rules are scored `low` and only the correlation — all three from one source — raises a high alert.
- The client is grouped by `c-ip`. Behind a proxy or CDN, switch to the real client address recovered from `X-Forwarded-For`, or to a session identifier. If requiring all three stages is too strict and misses cases, relax it to any two of the three.

### 4.3 Authentication logs

- **Sudden shifts in the login failure rate** per account/IP, **slow distributed attempts** spread across a wide range of accounts (characteristic of stuffing), and an **abnormal failure-to-success transition speed**.
- **Enumeration-style access** to identity-verification and one-time-code endpoints.

### 4.4 Egress and forensics

- Requests leaving an internal host for a code-repository host with the `artex-selfupdate` UA.
- Processes bound internally to `:8787` (the management UI) or `127.0.0.1:8788` (the recording proxy).
- A DNS/HTTP enrichment pattern that looks up a large number of external assets in a short time with the `artex-enrich/1.0` UA.

---

## 5. Hardening checklist

Summarized so a defending team can check it right away.

- [ ] Applied **adaptive rate limiting** (IP, account, device, behavior) to login, identity-verification, and sensitive APIs.
- [ ] Enforces **MFA** on sensitive operations.
- [ ] Has a **server-side ownership/authorization check** on every object access (blocks IDOR).
- [ ] **Re-verifies authentication state transitions on the server** and does not blindly trust client trust markers.
- [ ] Unified the identity-verification strength of **auxiliary/partner/recruitment channels** with the main service.
- [ ] Operates **compromised-credential detection/matching** for leaked credentials.
- [ ] Runs the WAF in **behavior-based mode** and does not rely on fixed signatures alone.
- [ ] **Does not apply circulating unofficial IP block lists as-is**, and instead takes official indicators of compromise (IoCs) from a trusted source and applies them after reviewing their validity window and false-blocking risk.
- [ ] Added a **same-source multi-stage correlation rule** to the SIEM.
- [ ] **Retains authentication, access, and egress logs for a sufficient period** (autonomous attacks are fast, so after-the-fact tracing material matters).
- [ ] Maintains an **inventory of internet-exposed assets, management consoles, and auxiliary systems to reduce the attack surface**, and **patches known (n-day) vulnerabilities fast** in perimeter devices, application servers, and middleware.
- [ ] Reduced the blast radius of lateral movement and privilege escalation with network **segmentation**.
- [ ] **Does not expose** secrets (keys, tokens) in responses, logs, or error messages.
- [ ] Prepared **automatic blocking/isolation** response (waiting only on human approval cannot keep up with autonomous attack speed).

---

## 6. Incident response summary

The defining trait of an autonomous AI attack is **speed**. An agent can run to completion, in a far shorter time, the intrusion and exfiltration that would take a person a year. Design your response on the premise of this speed.

- **Automatic blocking first.** Set up measures such as isolating a suspect source, invalidating sessions, and sharply cutting the rate so they can **fire automatically** before human approval. Binding everything to a human-approval loop cannot keep up with the attack's speed.
- **Decide in advance which logs to retain.** Authentication logs, access logs (including request bodies within the extent you can capture), egress logs, DNS queries. Autonomous attacks accumulate traces quickly, so this material is what you need to reconstruct the attack chain afterward.
- **Track the scope of compromise asset by asset.** Because the attack spreads along the asset graph, you must reconstruct the **entire path** from the initial entry asset through lateral movement and privilege escalation to prevent re-intrusion.

### 6.1 Triage procedure for a suspected host or traffic

This lays out, in order, what to check first when ARTEX involvement is suspected. As Section 2 split the fingerprints into two perspectives, triage also splits into **(a) whether your service was targeted** and **(b) whether ARTEX ran on a given host**. At any step, do not conclude from a single hit alone; judge by whether several indicators and behavioral signals appear together. Even if the static indicators are all absent, keep investigating when a behavioral signal shows up.

**(a) Target side — was your service targeted by ARTEX**

1. Query your access/authentication logs for the enrichment User-Agent `artex-enrich/1.0`. Check whether single `GET` requests that do not follow redirects arrive across several assets at once in a short interval (Section 2 (a)). Since an operator can change the User-Agent, move to the next step even if nothing matches.
2. Look for a **multi-stage chain** from the same source (or a few rotating sources): reconnaissance leading to endpoint enumeration, parameter probing, and authentication/injection attempts in short succession, adapting to response codes and lengths, and not stopping its evasive variations even after 401/403/429. This behavioral signal lasts longer than a static User-Agent (Section 2 (a) behavioral signatures).
3. If you run a SIEM, catch this behavior with the [Sigma correlation rules](../detections/README.md) (enrichment velocity, fan-out, guard-block burst, and the guard marker co-occurring with a destructive command), and escalate any matched source to isolation and session invalidation per the "automatic blocking first" principle above.

**(b) Host forensics — did ARTEX run on a given host**

On a suspected host, check the following. The basis for each indicator is in Section 2 (b) and in the machine-readable [indicator list](../detections/indicators/artex_indicators.csv). The first four of the five read-only checks below (listening ports, egress logs, audit logs, state and recording stores) are run in one pass by the [host-triage script](../detections/triage/) (`detections/triage/artex_host_triage.py`). The fifth, the command audit, the script does not automate: destructive commands are a hunting lead that legitimate administrators also run, not an ARTEX fingerprint, so they are deliberately kept out of the automated indicators — check that one by hand against the host's command history. Run the script first when you have shell access but no SIEM, and treat each hit as a lead, as described below.

1. **Listening ports.** Check on the host itself whether the default server port `:8787` and the loopback traffic-recording proxy `127.0.0.1:8788` are open.
   ```sh
   ss -ltnp | grep -E ':8787|:8788'   # use netstat -ltnp if ss is unavailable
   ```
   These two ports can be changed with the `--addr` and `--proxy` flags, so even if this query is empty, also review all open ports and whether an internal admin UI is up.
2. **Egress logs.** Check whether requests went out to the code-repository host (GitHub releases) with the self-update User-Agent `artex-selfupdate` in your egress logs (`selfupdate/`). This suggests an ARTEX binary ran on the host.
3. **Audit logs.** If the guard control marker `【ARTEX 平台管控·非目标防御】` appears in audit records, it supports an ARTEX-execution finding (`guard/guard.go`). It is written with this framing on every blocked tool call.
4. **State and recording stores.** ARTEX keeps its exploration graph in PostgreSQL (the `exploration_nodes`, `assets`, `companies`, `activity` tables and the `agent_prompts` seed) and leaves its state and recordings in the data directory next to the executable (the `--data` default in `cmd/artex/main.go`). Directly under that directory are the per-task `tasks/` and conversation `transcripts/` subdirectories, while the recording proxy's artifacts sit one level deeper in a `traffic/` subdirectory (`server/manager.go` opens `traffic/` under the data directory as the recorder's store). So the trust CA certificate is at `traffic/_ca/mitmproxy-ca-cert.pem`, the traffic index at `traffic/_index/index.sqlite`, and the recorded request/response bodies at `traffic/_blobs/`. The case strengthens when these appear together with `tasks/` and `transcripts/`.
5. **Command auditing.** Compare the destructive-command hunting indicators (the end of Section 2 (b): `rm -rf`, `DROP DATABASE`, `FLUSHALL`, exfiltration pipes, and the like) against the host's command history. A legitimate administrator uses the same commands, so treat them only as leads.

Static indicators (ports, User-Agents, markers) can be changed or deleted by an operator. So **absence does not mean safety**, and the key to triaging an autonomous AI attack is to gather the behavioral signals from (a) and the host traces from (b) and judge them together.

---

## 7. Korean official channels: indicators, advisories, and reporting duties

Defending teams in Korea should take their indicators of compromise and security advisories from official channels, and, when an incident occurs, meet the reporting duties the law sets. Make the official sources below your first reference instead of circulating unofficial lists.

### 7.1 Where to get indicators and advisories

- **KISA (Korea Internet & Security Agency), via [Boho Nara / KrCERT/CC](https://www.boho.or.kr)**, publishes security advisories, vulnerability notices, and incident-response information, and shares threat intelligence across organizations through C-TAS (the Cyber Threat Analysis and Sharing system; unlike the open portal, C-TAS is shared among enrolled organizations and takes a separate application).
- **[FSI (Financial Security Institute)](https://www.fsec.or.kr)** shares intrusion and threat information across the financial sector (the finance-sector ISAC). If you are in finance, watch this channel as well.
- **[PIPC (Personal Information Protection Commission)](https://www.pipc.go.kr)** publishes the criteria for breach notification and the guidance on protective measures.

These channels are exactly what the section 5 hardening checklist means by "take official indicators of compromise from a trusted source." Even an official IoC is applied only after you review its validity window and false-blocking risk, the same principle explained in section 2, "Why IP-address blocking is a weak first line of defense."

### 7.2 Reporting duties under Korean law

Because autonomous attacks spread fast, build the statutory reporting steps into your section 6 incident-response procedure in advance. The following is a summary; confirm the exact scope, deadlines, and conditions against each authority's current rules.

- **Personal-data breach:** under Article 34 of the Personal Information Protection Act, within 72 hours of becoming aware of the breach, report to the PIPC or KISA and notify the affected data subjects (the reporting conditions include a breach affecting 1,000 or more data subjects, a breach of sensitive or unique-identifier data, and a breach caused by unlawful external access).
- **Security incident:** under the Network Act, an information and communications service provider reports the incident to the Ministry of Science and ICT and KISA (KrCERT/CC) within 24 hours of becoming aware of it.
- **Financial companies:** under financial-sector supervisory rules you may additionally have to report to bodies such as the Financial Supervisory Service and FSI, so check those rules as well.

To actually file: report a security incident through [Boho Nara](https://www.boho.or.kr) or by calling 118 with no area code (the KISA cyber help center), and a personal-data breach through the PIPC [personal-information portal](https://www.privacy.go.kr). The deadlines are short, so record the responsible owner and the contact path in your section 6 incident-response procedure in advance.

---

## References

- Upstream project: [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX) (AGPL-3.0). This document is the defensive material of its Korean-edition repository.
- The top-level [README security and misuse warning, scope of use, and legal notice](../README.en.md).
- This edition is localized for Korea; where personal data is involved, Korean law (the Network Act and the Personal Information Protection Act) applies. Unauthorized testing is a crime in most jurisdictions regardless — always secure written authorization and an agreed scope first.
- Standard references for general web-security hardening: [OWASP Top 10](https://owasp.org/www-project-top-ten/), [OWASP ASVS (Application Security Verification Standard)](https://owasp.org/www-project-application-security-verification-standard/), [OWASP API Security Top 10](https://api-security.owasp.org/).

> This guide is continually expanded to support defense and detection capability. Suggestions for additional detection rules or hardening items are welcome as repository issues.
