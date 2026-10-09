# ARTEX host triage

English · [한국어](README.ko.md)

> 한국어: [`artex_host_triage.py`](artex_host_triage.py) 는 ARTEX 가 돌았다고 의심되는 **호스트 한 대에서 직접**
> 돌리는 읽기 전용 분류(triage) 스크립트입니다. SIEM(Sigma)·네트워크 센서(Suricata)·위협 인텔리전스
> 플랫폼(지표 CSV·MISP)을 쓰는 방어자 말고, SIEM 없이 의심 호스트의 셸 앞에 선 대응자를 위한 것입니다.
> 리슨 포트·기록 프록시 아티팩트·로그 마커·PostgreSQL 스키마를 저장소 소스에 근거해 점검하고, 각 발견에
> 같은 한계(포트는 바꿀 수 있음, CA 파일명은 단독 mitmproxy 와 공유됨 등)를 함께 적습니다. 자신이 소유하거나
> 서면 허가를 받은 호스트에만 사용하십시오. 한국어 전체 문서는 **[README.ko.md](README.ko.md)** 를 보십시오.

A read-only triage helper you run **on a single suspected host** to answer "did ARTEX run here?" from
local state. The rest of this directory serves defenders who run a SIEM ([Sigma](../sigma/)), a network
sensor ([Suricata](../suricata/)), or a threat-intelligence platform (the [indicators](../indicators/)).
This script serves the other responder: the one at a host's shell, with no SIEM, who needs a quick,
defensible answer from what is on the box.

It operationalizes the same fingerprints the rest of the directory ships, **plus the three host/DB
indicators the [indicator list](../indicators/artex_indicators.csv) deliberately carries without a Sigma
rule** because they are not log- or network-observable and can only be checked on the host itself
(`server-listen-port`, `recording-proxy-endpoint`, `postgres-exploration-schema`).

## What it checks

Every check is grounded in a string or path verified in this repository's source, and every finding
carries the same honest caveat as the matching Sigma rule or indicator row.

- **Listening ports** — `:8787` (admin UI) and `127.0.0.1:8788` (recording proxy), the defaults of the
  `--addr` / `--proxy` flags in [`cmd/artex/main.go`](../../cmd/artex/main.go). Parsed from `ss`/`netstat`/`lsof`
  on the live host, or from a file you pass with `--ports-from`.
- **Recording-proxy artifacts** — the MITM CA the recorder writes on first start,
  `<data-dir>/traffic/_ca/mitmproxy-ca-cert.pem`, and the sibling `_index/index.sqlite` and `_blobs/`
  ([`traffic/traffic.go`](../../traffic/traffic.go); the data directory default is `data/` next to the binary).
  The CA is the trust anchor of an adversary-in-the-middle traffic recorder (ATT&CK T1557).
- **Log markers** — the enrichment prober UA `artex-enrich/1.0` ([`enrich/enrich.go`](../../enrich/enrich.go)),
  the self-update egress UA `artex-selfupdate` ([`selfupdate/github.go`](../../selfupdate/github.go)), and
  the platform-guard audit marker ([`guard/guard.go`](../../guard/guard.go); kept verbatim, including the
  non-ASCII framing, so the grep matches) in the log file(s) you point it at. Rotated logs compressed as
  `.gz`/`.bz2`/`.xz` are decompressed and scanned too, so the host's log history is covered; a format with
  no standard-library codec (`.zst`/`.lz4`) is reported as **skipped** rather than silently treated as
  clean — decompress it first or `grep` it by hand.
- **PostgreSQL exploration schema** — the dual-graph tables (`exploration_nodes`/`_edges`/`_anchors` with
  `assets`/`companies`/`activity` and the `agent_prompts` seed) in the ARTEX store
  ([`db/schema.sql`](../../db/schema.sql)). Run against a DSN with `psql` if available; otherwise the
  script prints the exact read-only query for you to run by hand.
- **Process env injection** — a running process whose environment carries a proxy var (`HTTP_PROXY` /
  `HTTPS_PROXY` / `ALL_PROXY`) **together with** a toolchain CA-trust var (`SSL_CERT_FILE` /
  `CURL_CA_BUNDLE` / `REQUESTS_CA_BUNDLE` / `GIT_SSL_CAINFO` / `NODE_EXTRA_CA_CERTS`) pointing at a
  `mitmproxy-ca-cert.pem`. ARTEX injects exactly these into every worker tool it spawns
  ([`agent/worker.go`](../../agent/worker.go) `proxyEnv`, asserted by
  [`agent/proxyenv_test.go`](../../agent/proxyenv_test.go)). The variable **names are hard-coded** in the
  source (only the values are configurable), so this tell survives an operator renaming the binary or
  changing the ports — a stronger signal than the bare listen port. Read from `/proc` on the live Linux
  host, or from a captured dump with `--proc-from`. A proxy and a mitmproxy CA together are reported high;
  a mitmproxy CA alone, or the ARTEX default proxy endpoint (`127.0.0.1:8788`) alone, is medium; a
  corporate proxy with no mitmproxy CA is deliberately not flagged.

A hit is a **triage lead, not an attribution**, and the absence of every finding is **not** a clean bill
of health: an operator can rename the binary, move the data directory, or change the ports.

## Platform support

The script is pure Python 3 (standard library only), so it runs wherever Python 3 does — verified on
Linux (the CI self-test) and macOS. Two checks are OS-specific, and both degrade cleanly rather than
failing:

- **Live port scan** — tries `ss`, then `netstat`, then `lsof`, and uses the first that produces output.
  On Linux that is `ss`/`netstat`; on macOS/BSD, where `ss` is absent and `netstat` does not take the
  Linux `-ltnp` flags (it exits with empty output), it falls through to `lsof -nP -iTCP -sTCP:LISTEN`,
  parsed the same way. Pass `--ports-from` to read a saved listing instead of scanning live.
- **Live process-env scan** — reads `/proc`, so it runs only on Linux. On a host without `/proc`
  (macOS/BSD) it is reported as **skipped**, not clean; capture a dump on the Linux host and pass it with
  `--proc-from` (see Usage).

The remaining checks — recording-proxy artifacts, log markers, and the PostgreSQL schema — read the
filesystem, log files, and (with a DSN) `psql`, so they are OS-independent.

## Usage

```sh
# check a host end to end
detections/triage/artex_host_triage.py \
    --data-dir /opt/artex/data \
    --log /var/log/syslog --log-dir /var/log/artex \
    --pg-dsn "$ARTEX_PG_DSN"

# machine-readable findings, and exit non-zero if anything fired
detections/triage/artex_host_triage.py --data-dir /opt/artex/data --json --exit-code

# offline / forensic image: read a captured process-environment dump
#   make the dump on the host with:
#   for p in /proc/[0-9]*; do echo "# $p"; tr '\0' '\n' < "$p/environ"; echo; done > proc_env_dump.txt
detections/triage/artex_host_triage.py --proc-from proc_env_dump.txt

# reproducible fixture test (no host state touched)
detections/triage/artex_host_triage.py --self-test
```

The script is pure Python 3 standard library: no install, no network, and it writes nothing anywhere
except the `--self-test`'s own temporary directory. It reads host state (open ports, a data directory,
log files, and — only if you pass a DSN — the database) and prints what it found. Exit code is `0` by
default (triage, not a gate); pass `--exit-code` to make it `1` when any indicator fired.

## How this stays honest

The `--self-test` builds a synthetic host — a data directory with a planted CA, index, and blob store; a
log containing each marker; a port listing; and a captured process-environment dump — and asserts every
check fires on it, then asserts a clean host, a benign log, and a corporate-proxy process produce **zero**
findings (no false positives). It is wired into the
[`detections` CI workflow](../../.github/workflows/detections.yml) and re-run by
[`detections/tests/run-all.sh`](../tests/run-all.sh), so a change that breaks a check, or that drifts an
indicator away from the source string it greps for, fails the merge gate. A detection you cannot run is
only a claim.
