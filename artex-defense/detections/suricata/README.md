# ARTEX detection rules (Suricata / network)

English · [한국어](README.ko.md)

> 한국어: 이 디렉터리는 [방어·탐지 가이드(docs/defense-ko.md)](../../docs/defense-ko.md) 2·4절의
> 네트워크 관측 지문을 실제로 배포 가능한 [Suricata](https://suricata.io) 규칙으로 옮긴 것입니다.
> 로그·호스트 계층은 [`../sigma/`](../sigma/)(Sigma)가 담당합니다. 모든 규칙은 자신이 소유하거나
> 서면 허가를 받은 시스템을 지키는 **방어·탐지 목적에만** 사용하십시오. 한국어 전체 문서는
> **[README.ko.md](README.ko.md)** 를 보십시오.

The network-layer companion to the [Sigma rules](../sigma/). These [Suricata](https://suricata.io)
signatures cover the two ARTEX artifacts that are observable on the wire, and every indicator is grounded in a
string or behaviour verified in this repository's source, not inferred. The host, log, and SIEM layers live
under [`../sigma/`](../sigma/); the defense guide ([Korean](../../docs/defense-ko.md) ·
[English](../../docs/defense-en.md)) explains the full picture.

## Rules — [`artex.rules`](artex.rules)

- **sid 1000001** — `ARTEX enrichment prober User-Agent`. An inbound HTTP `GET` whose User-Agent starts with
  `artex-enrich/` — the asset-enrichment prober (`enrich/enrich.go:233`). The single-request presence
  indicator. `classtype: attempted-recon`.
- **sid 1000002** — `ARTEX enrichment prober high-rate enumeration`. The same User-Agent crossing a
  `detection_filter` rate of **30 requests in 300 s per source** — the machine-speed velocity a single-hit
  rule misses. Mirrors the Sigma correlation `artex_enrich_scan_velocity`. `classtype: attempted-recon`.
- **sid 1000003** — `ARTEX worker WebFetch User-Agent`. An inbound HTTP request whose User-Agent starts with
  `norma/` — the norma SDK's WebFetch tool (`github.com/Autumn-27/norma/tool/webfetch.go`). This UA is hardcoded across all norma
  versions (v0.1.0–v0.4.3, verified) and reaches the target through the recording proxy, which does not
  modify request headers (`traffic/traffic.go`). Unlike the enrich prober, this fires during the **attack
  phase** (active vulnerability probing). `classtype: attempted-recon`.

## Scope and honesty — read before deploying

- **Two ARTEX User-Agents are network-observable.** The enrich prober sends `artex-enrich/1.0`
  (`enrich/enrich.go:233`) during reconnaissance; the norma SDK's WebFetch tool sends `norma/0.4`
  (`github.com/Autumn-27/norma/tool/webfetch.go`) during the attack phase. The recording proxy (`traffic/traffic.go`) does not
  modify request headers, so both UAs reach the target on the wire. Other worker tools (Bash subprocesses
  like `curl`, `nmap`) use their own User-Agents — detect those with generic scanner signatures and the
  behavioural SIEM rules under [`../sigma/`](../sigma/).
- **The User-Agent is only visible in plaintext.** It appears where traffic is plaintext HTTP or inspected at
  a TLS-terminating proxy / WAF. End-to-end TLS encrypts it, so deploy these where you actually see the HTTP
  request buffer.
- **A static User-Agent can be changed** by the operator, so its absence does **not** mean safety. The durable
  signal is behaviour — rate and breadth — which is why sid 1000002 (and the Sigma correlation layer) key on
  velocity, and why pure web multi-stage detection needs base rules specific to your environment.
- **Deliberately omitted.** The self-update User-Agent `artex-selfupdate` travels over HTTPS to GitHub and is
  not network-observable (TLS SNI alone is too common to alert on). The audit-control marker is an
  operator-side log artifact, not target-facing traffic — detect it with
  [`../sigma/artex_guard_audit_framing.yml`](../sigma/artex_guard_audit_framing.yml). The server port `:8787`
  and recording proxy `127.0.0.1:8788` (`cmd/artex/main.go`) are host-forensic (`ss`/`netstat`), not a
  network signature.
- **One indicator rests on a pinned dependency, not this repository's own source.** The opening line says
  every indicator is verified in this repository's source; sid 1000003 is the single carve-out. Its `norma/`
  User-Agent is hardcoded in the norma SDK (`github.com/Autumn-27/norma/tool/webfetch.go`), which ARTEX pins
  at `v0.4.3` in `go.mod` rather than vendoring into this tree, so the string is grounded in that pinned
  upstream dependency (hardcoded across v0.1.0–v0.4.3, verified), not a file here. This is why the
  indicator-source test re-reads ARTEX's own emitters but not this one. The
  [indicators list](../indicators/README.md) states the same caveat; it is noted here too so the
  "verified in this repository's source" claim above holds without an unstated exception.

## Validate and test

Validated with Suricata 8. The load test needs no traffic and always runs:

```sh
# syntax + engine load test (expect: "Configuration provided was successfully loaded")
docker run --rm -v "$PWD/detections/suricata":/r -w /r jasonish/suricata:latest \
  suricata -T -S artex.rules -l /tmp --init-errors-fatal
```

`--init-errors-fatal` makes a rule that parses but fails to initialise a hard error too, so the load test
cannot pass with a silently dropped signature.

To confirm the rules actually fire, a reproducible regression test lives in
[`../tests/suricata/`](../tests/suricata/). It runs this same load check first, then synthesizes a
deterministic capture with scapy, runs `suricata -r` over it, and asserts the alert counts — needing only
Docker:

```sh
detections/tests/suricata/run.sh
```

It asserts that sid 1000001 fires exactly once per probe (35 over a 35-flow capture), that sid 1000002
trips past the 30-in-300 s rate (**5** alerts on Suricata 8.0.7, flows 31–35), and that the same capture
with a benign browser User-Agent produces **0** alerts — confirming the signatures are specific. See
[`../tests/README.md`](../tests/README.md). To check against your own traffic instead, capture a loopback
`curl -A 'artex-enrich/1.0'` against a local server and read the alerts:

```sh
suricata -r enrich.pcap -S artex.rules -l out && \
  grep -c '"signature_id":1000001' out/eve.json    # presence: one per probe
```

## Contributing

Detection contributions are welcome. New rules should keep every indicator grounded in an observable fact,
state limitations in a comment, pass `suricata -T` cleanly, and avoid any content that reads as attack
guidance. See [`../../CONTRIBUTING.en.md`](../../CONTRIBUTING.en.md) and the Sigma layer in
[`../sigma/`](../sigma/) / [`../README.md`](../README.md).
