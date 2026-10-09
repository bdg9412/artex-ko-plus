#!/usr/bin/env python3
#
# ARTEX host triage — a read-only responder helper for a suspected ARTEX host.
#
# The rest of detections/ serves defenders who run a SIEM (Sigma), a network
# sensor (Suricata), or a threat-intel platform (the MISP / CSV indicators). This
# script serves the other responder: the one standing at a single suspect host's
# shell, with no SIEM, who needs to answer "did ARTEX run here?" from local state.
# It operationalizes the same indicators the rest of the directory ships, plus the
# three host/DB indicators the indicator list deliberately carries WITHOUT a Sigma
# rule because they are not log- or network-observable and can only be checked on
# the box itself (see detections/indicators/artex_indicators.csv — the rows whose
# `rule` column is empty: server-listen-port, recording-proxy-endpoint,
# postgres-exploration-schema).
#
# It is a TRIAGE LEAD generator, not an alerting rule. Every check is grounded in
# a string or path verified in this repository's source, and every finding carries
# the same honest caveat the matching Sigma rule or indicator row carries: ports
# are configurable, the MITM CA filename is shared with standalone mitmproxy, the
# guard marker also appears in logs that merely quote this guide. A hit is a reason
# to look closer, never an attribution on its own, and the absence of every finding
# is NOT a clean bill of health — an operator can rename the binary, move the data
# directory, or change the ports.
#
# What it checks (each cites the source it is grounded in):
#   1. Listening ports        :8787 (admin UI) and 127.0.0.1:8788 (recording proxy)
#                             — defaults of the --addr / --proxy flags in
#                               cmd/artex/main.go. Parsed from `ss`/`netstat`/`lsof`
#                               on the live host, or from --ports-from FILE.
#   2. Recording-proxy MITM    <data-dir>/traffic/_ca/mitmproxy-ca-cert.pem and the
#      CA + stores             sibling _index/index.sqlite and _blobs/ the recorder
#                             writes on first start (traffic/traffic.go; the data
#                               dir default is data/ next to the binary — see
#                               cmd/artex/main.go). The CA is the trust anchor of an
#                               adversary-in-the-middle traffic recorder (ATT&CK
#                               T1557).
#   3. Log markers            the enrichment prober UA `artex-enrich/1.0`
#                               (enrich/enrich.go), the self-update egress UA
#                               `artex-selfupdate` (selfupdate/github.go), and the
#                               platform-guard audit marker (guard/guard.go) in the
#                               log file(s) you point it at. Rotated logs that
#                               logrotate compressed as .gz/.bz2/.xz are read
#                               through their standard-library codec so their
#                               history is scanned too; a format with no stdlib
#                               codec (.zst/.lz4) is reported as skipped, never
#                               silently treated as clean.
#   4. PostgreSQL schema      the dual-graph exploration tables (exploration_nodes /
#                               _edges / _anchors with assets / companies / activity
#                               and the agent_prompts seed) in the ARTEX store
#                               (db/schema.sql). Run against a DSN with `psql` if
#                               available; otherwise the script prints the exact
#                               read-only query for you to run by hand.
#   5. Process env injection  a running process whose environment carries the
#                               recording proxy (HTTP_PROXY / HTTPS_PROXY / ALL_PROXY)
#                               together with a toolchain CA-trust var (SSL_CERT_FILE /
#                               CURL_CA_BUNDLE / REQUESTS_CA_BUNDLE / GIT_SSL_CAINFO /
#                               NODE_EXTRA_CA_CERTS) pointing at a mitmproxy-ca-cert.pem.
#                               ARTEX injects exactly these into every worker tool it
#                               spawns (agent/worker.go proxyEnv, asserted by
#                               agent/proxyenv_test.go). The variable NAMES are
#                               hard-coded in the source, so this tell survives an
#                               operator renaming the binary or changing the ports —
#                               a stronger signal than the bare listen port. Read from
#                               /proc on the live Linux host, or from --proc-from FILE.
#
# Safety: pure Python standard library, no network, no writes anywhere except the
# self-test's own temporary directory. It reads host state (open ports, a data
# directory, log files, the environments of running processes via /proc, and — only
# if you pass a DSN — the database) and prints what it found. Use it only on a host
# you own or are authorized in writing to inspect.
#
# Usage:
#   detections/triage/artex_host_triage.py --data-dir /opt/artex/data \
#       --log /var/log/syslog --log-dir /var/log/artex
#   detections/triage/artex_host_triage.py --pg-dsn "$ARTEX_PG_DSN"
#   detections/triage/artex_host_triage.py --proc-from proc_env_dump.txt  # offline
#   detections/triage/artex_host_triage.py --self-test     # reproducible fixture test
#   detections/triage/artex_host_triage.py --json          # machine-readable findings
#
# Exit code: 0 by default (triage, not a gate). With --exit-code, exits 1 if any
# finding fired. --self-test exits non-zero on any self-test failure.

import argparse
import bz2
import gzip
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile

# --- grounded constants (every value is verified in this repository's source) ---

# Default listen / recording-proxy ports (cmd/artex/main.go --addr / --proxy).
SERVER_PORT = 8787
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8788

# Recording-proxy artifacts under <data-dir>/traffic/ (traffic/traffic.go;
# server/manager.go opens traffic.Open(filepath.Join(dir, "traffic"), ...)).
TRAFFIC_SUBDIR = "traffic"
CA_RELPATH = os.path.join("_ca", "mitmproxy-ca-cert.pem")
INDEX_RELPATH = os.path.join("_index", "index.sqlite")
BLOBS_RELDIR = "_blobs"

# Log markers. The guard marker is the original (untranslated) framing string the
# platform guard writes to the audit log on a blocked tool call (guard/guard.go);
# it is kept verbatim here because that is the exact byte sequence a responder
# greps for, and translating it would stop the match.
LOG_MARKERS = [
    {
        "value": "artex-enrich/1.0",
        "title": "enrichment prober User-Agent",
        "source": "enrich/enrich.go",
        "severity": "high",
        "caveat": "An operator can change the User-Agent; absence is not safety.",
    },
    {
        "value": "artex-selfupdate",
        "title": "self-update egress User-Agent",
        "source": "selfupdate/github.go",
        "severity": "medium",
        "caveat": "Seen in outbound logs from a host running ARTEX; the string is configurable.",
    },
    {
        "value": "【ARTEX 平台管控·非目标防御】",
        "title": "platform-guard audit-log framing marker",
        "source": "guard/guard.go",
        "severity": "high",
        "caveat": "Also appears in logs that merely quote this defense guide or the ARTEX source.",
    },
]

# Dual-graph exploration schema fingerprint (db/schema.sql). Their presence
# together is the host-forensic tell; any one table name is generic.
SCHEMA_TABLES = [
    "exploration_nodes",
    "exploration_edges",
    "exploration_anchors",
    "assets",
    "companies",
    "activity",
    "agent_prompts",
]

# Recording-proxy environment injection into spawned worker tools (agent/worker.go
# proxyEnv; asserted by agent/proxyenv_test.go). ARTEX routes every worker tool's
# traffic through the recording MITM proxy and, when a CA is present, makes the
# toolchain trust it — by setting these exact variables in the subprocess env. The
# variable NAMES are hard-coded in worker.go (only the values are configurable), so
# a tool process carrying a recording-proxy address in a proxy var AND a CA var
# pointing at a mitmproxy-ca-cert.pem is a far more specific tell than the bare
# listen port: it survives the operator renaming the binary or moving the data dir.
PROXY_ENV_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy",
)
CA_ENV_VARS = (
    "SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS",
)
CA_BASENAME = "mitmproxy-ca-cert.pem"  # basename of CA_RELPATH; the value a CA var points at
# The recording-proxy default endpoint (cmd/artex/main.go --proxy). An operator can
# point --proxy elsewhere, so the CA var is the anchor and this is only the fallback.
PROXY_DEFAULT_ENDPOINT = f"{PROXY_HOST}:{PROXY_PORT}"  # 127.0.0.1:8788


class Finding:
    def __init__(self, check, severity, title, detail, source, caveat):
        self.check = check
        self.severity = severity
        self.title = title
        self.detail = detail
        self.source = source
        self.caveat = caveat

    def as_dict(self):
        return {
            "check": self.check,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "caveat": self.caveat,
        }


# --- check 1: listening ports -------------------------------------------------

# Parse a port-listing produced by `ss -ltnp`, `netstat -ltnp`, or
# `lsof -nP -iTCP -sTCP:LISTEN`. Kept a pure function of its text input so the
# self-test can feed synthetic output without opening a real socket. Returns the
# set of (host, port) LISTEN endpoints it can parse out of any of those formats.
LISTEN_RE = re.compile(
    r"(?P<host>\[?[0-9a-fA-F:.*]+\]?):(?P<port>\d{1,5})\b"
)


def parse_listen_endpoints(listing):
    endpoints = set()
    for line in listing.splitlines():
        low = line.lower()
        # ss/netstat lines for listeners contain the LISTEN state; lsof lines
        # contain "(LISTEN)". Skip anything that is not a listening socket so a
        # connected session to :8787 elsewhere is not misread as a local listener.
        if "listen" not in low:
            continue
        for m in LISTEN_RE.finditer(line):
            host = m.group("host").strip("[]")
            try:
                port = int(m.group("port"))
            except ValueError:
                continue
            if 0 < port < 65536:
                endpoints.add((host, port))
    return endpoints


def gather_listen_listing():
    """Run the first available port tool; return its stdout, or '' if none work."""
    for cmd in (
        ["ss", "-ltnp"],
        ["netstat", "-ltnp"],
        ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
    ):
        if shutil.which(cmd[0]) is None:
            continue
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if out.stdout:
            return out.stdout
    return ""


def check_listening_ports(listing):
    findings = []
    endpoints = parse_listen_endpoints(listing)
    for host, port in sorted(endpoints):
        if port == SERVER_PORT:
            findings.append(
                Finding(
                    "listening-port",
                    "medium",
                    "ARTEX default admin-UI port is listening",
                    f"a process is listening on {host}:{port} (ARTEX --addr default :{SERVER_PORT})",
                    "cmd/artex/main.go",
                    "The port is configurable; confirm the process with `ss -ltnp` / `lsof`.",
                )
            )
        if port == PROXY_PORT and (host == PROXY_HOST or host in ("*", "0.0.0.0", "::")):
            findings.append(
                Finding(
                    "listening-port",
                    "high",
                    "ARTEX recording-proxy loopback port is listening",
                    f"a process is listening on {host}:{port} (ARTEX --proxy default {PROXY_HOST}:{PROXY_PORT})",
                    "cmd/artex/main.go",
                    "Loopback-only and configurable; correlate with the MITM CA file under traffic/_ca/.",
                )
            )
    return findings


# --- check 2: recording-proxy artifacts --------------------------------------


def check_recording_proxy_artifacts(data_dir):
    findings = []
    traffic = os.path.join(data_dir, TRAFFIC_SUBDIR)
    ca = os.path.join(traffic, CA_RELPATH)
    if os.path.isfile(ca):
        findings.append(
            Finding(
                "recording-proxy-ca",
                "medium",
                "ARTEX recording-proxy MITM CA certificate present",
                f"found {ca}",
                "traffic/traffic.go",
                "A bare mitmproxy-ca-cert.pem is shared with standalone mitmproxy; "
                "the traffic/_ca/ layout narrows it to ARTEX.",
            )
        )
    index = os.path.join(traffic, INDEX_RELPATH)
    if os.path.isfile(index):
        findings.append(
            Finding(
                "recording-proxy-index",
                "medium",
                "ARTEX recording-proxy traffic index store present",
                f"found {index}",
                "traffic/traffic.go",
                "The recorder's SQLite index of captured HTTP(S) exchanges; a forensic artifact of a run.",
            )
        )
    blobs = os.path.join(traffic, BLOBS_RELDIR)
    if os.path.isdir(blobs):
        findings.append(
            Finding(
                "recording-proxy-blobs",
                "low",
                "ARTEX recording-proxy body blob store present",
                f"found {blobs}/",
                "traffic/traffic.go",
                "Spilled response bodies from the traffic recorder; corroborates the index/CA.",
            )
        )
    return findings


# --- check 3: log markers -----------------------------------------------------

# logrotate (and journald) compress rotated logs. gzip is the historical default;
# bzip2 and xz show up when configured. Open those through their standard-library
# codec so the markers inside a rotated file are scanned too — a bare text open()
# would read the compressed bytes as UTF-8 and silently miss every marker in the
# host's log history, exactly the kind of "absence is not safety" gap this tool
# warns about. Formats with no stdlib codec (zstd, lz4) cannot be read here; they
# are reported as skipped so the responder decompresses them by hand rather than
# mistaking an unscanned file for a clean one.
STDLIB_LOG_OPENERS = {
    ".gz": gzip.open,
    ".bz2": bz2.open,
    ".xz": lzma.open,
    ".lzma": lzma.open,
}
UNSUPPORTED_COMPRESSED_EXTS = {".zst", ".zstd", ".lz4", ".lz", ".zip", ".7z", ".br"}


def open_log_stream(path):
    """Return a UTF-8 text stream for a log file, transparently decompressing a
    gzip/bzip2/xz rotated log by extension. The caller uses it as a context
    manager. Plaintext and anything unrecognized fall through to a plain open."""
    opener = STDLIB_LOG_OPENERS.get(os.path.splitext(path)[1].lower())
    if opener is not None:
        return opener(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def iter_log_files(logs, log_dirs):
    seen = set()
    for p in logs:
        if os.path.isfile(p) and p not in seen:
            seen.add(p)
            yield p
    for d in log_dirs:
        if not os.path.isdir(d):
            continue
        for root, _dirs, files in os.walk(d):
            for name in sorted(files):
                p = os.path.join(root, name)
                if p not in seen:
                    seen.add(p)
                    yield p


def scan_logs(logs, log_dirs):
    """Scan the log files/dirs for ARTEX markers. Returns (findings, skipped),
    where skipped lists paths in a compressed format with no stdlib codec
    (e.g. .zst/.lz4) that could not be read and so were NOT scanned."""
    findings = []
    skipped = []
    for path in iter_log_files(logs, log_dirs):
        if os.path.splitext(path)[1].lower() in UNSUPPORTED_COMPRESSED_EXTS:
            # No stdlib codec: do not read gibberish and do not pretend it is
            # clean — record it so run_checks can tell the responder to grep it
            # by hand (zstdcat / lz4cat).
            skipped.append(path)
            continue
        # Stream line by line instead of f.read(): the sanctioned log targets are
        # whole syslogs (--log /var/log/syslog) that can be hundreds of MB, and all
        # three markers live within a single line, so a line at a time keeps memory
        # bounded to one line while matching exactly what a full read would.
        # open_log_stream transparently decompresses a .gz/.bz2/.xz rotated log so
        # its history is scanned too. Report each marker at most once per file (the
        # full-read "value in text" did too), and stop early once all have fired.
        fired = set()
        try:
            with open_log_stream(path) as f:
                for line in f:
                    for marker in LOG_MARKERS:
                        if marker["value"] in fired:
                            continue
                        if marker["value"] in line:
                            fired.add(marker["value"])
                            findings.append(
                                Finding(
                                    "log-marker",
                                    marker["severity"],
                                    f"ARTEX {marker['title']} in log",
                                    f"{path!r} contains {marker['value']!r}",
                                    marker["source"],
                                    marker["caveat"],
                                )
                            )
                    if len(fired) == len(LOG_MARKERS):
                        break
        except (OSError, EOFError, lzma.LZMAError):
            # Unreadable or a corrupt/mislabeled compressed file (gzip.BadGzipFile
            # and bz2 errors are OSError subclasses; lzma raises LZMAError). Skip it
            # the same way the plain-read path always skipped an unreadable file.
            continue
    return findings, skipped


# --- check 4: PostgreSQL exploration schema -----------------------------------

# A single read-only query: how many of the dual-graph tables exist in the public
# schema. Printed for manual use when psql is unavailable or no DSN was given.
SCHEMA_QUERY = (
    "SELECT count(*) FROM information_schema.tables "
    "WHERE table_schema='public' AND table_name IN ("
    + ", ".join(f"'{t}'" for t in SCHEMA_TABLES)
    + ");"
)


def check_pg_schema(dsn):
    findings = []
    if not dsn:
        return findings, (
            "PostgreSQL schema check skipped (no --pg-dsn / ARTEX_PG_DSN). "
            "To check by hand, run this read-only query against the suspected store:\n"
            f"    psql <DSN> -c \"{SCHEMA_QUERY}\"\n"
            f"    (a count at or near {len(SCHEMA_TABLES)} of these tables together is the dual-graph tell; db/schema.sql)"
        )
    if shutil.which("psql") is None:
        return findings, (
            "PostgreSQL schema check skipped (psql not found on PATH). "
            f"Run by hand:\n    psql <DSN> -c \"{SCHEMA_QUERY}\""
        )
    try:
        out = subprocess.run(
            ["psql", dsn, "-tAc", SCHEMA_QUERY],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return findings, f"PostgreSQL schema check could not run: {e}"
    if out.returncode != 0:
        return findings, (
            "PostgreSQL schema check could not connect: "
            + (out.stderr.strip().splitlines()[-1] if out.stderr.strip() else "psql returned non-zero")
        )
    count = out.stdout.strip()
    try:
        n = int(count)
    except ValueError:
        return findings, f"PostgreSQL schema check returned an unexpected result: {count!r}"
    if n >= 4:
        findings.append(
            Finding(
                "postgres-schema",
                "high" if n >= 6 else "medium",
                "ARTEX dual-graph exploration schema present",
                f"{n} of {len(SCHEMA_TABLES)} ARTEX exploration-graph tables found in the public schema",
                "db/schema.sql",
                "Inspect the database to confirm; a few table names overlap generic apps, the set does not.",
            )
        )
    return findings, f"PostgreSQL schema check: {n} of {len(SCHEMA_TABLES)} ARTEX tables present."


# --- check 5: recording-proxy env injection in running processes --------------


def _proxy_env_hit(env):
    """First proxy var set to a non-empty value, as (var, value), else None."""
    for var in PROXY_ENV_VARS:
        val = env.get(var, "").strip()
        if val:
            return var, val
    return None


def _ca_env_hit(env):
    """First CA-trust var pointing at a mitmproxy-ca-cert.pem, as (var, value), else None."""
    for var in CA_ENV_VARS:
        val = env.get(var, "").strip()
        if val and os.path.basename(val) == CA_BASENAME:
            return var, val
    return None


def scan_process_env(label, env):
    """Findings for one process's environment dict. Pure function of its input so
    the self-test can feed synthetic env without reading /proc. The strongest tell
    is a proxy var AND a mitmproxy CA var together (the worker proxyEnv signature);
    a mitmproxy CA alone, or the ARTEX default proxy endpoint alone, is a weaker
    lead. A corporate proxy with no mitmproxy CA is deliberately not flagged."""
    proxy = _proxy_env_hit(env)
    ca = _ca_env_hit(env)
    if ca and proxy:
        pv, pval = proxy
        cv, cval = ca
        return [Finding(
            "process-env-injection", "high",
            "ARTEX recording-proxy env injection in a running process",
            f"{label}: {pv}={pval} with {cv}={cval} — the worker proxyEnv signature "
            "(routes through a proxy and trusts a mitmproxy CA)",
            "agent/worker.go",
            "A standalone mitmproxy or a MITM test harness can set these too; a proxy "
            "together with a trusted mitmproxy-ca-cert.pem matches ARTEX's worker "
            "injection. Capture can be disabled (--proxy ''), so absence is not safety.",
        )]
    if ca:
        cv, cval = ca
        return [Finding(
            "process-env-injection", "medium",
            "A running process is told to trust a mitmproxy CA",
            f"{label}: {cv}={cval} points a toolchain CA-trust var at a mitmproxy-ca-cert.pem",
            "agent/worker.go",
            "The recording proxy injects this CA path into worker tools; the bare "
            "filename is shared with standalone mitmproxy, so correlate with "
            "traffic/_ca/ and the proxy port.",
        )]
    if proxy and PROXY_DEFAULT_ENDPOINT in proxy[1]:
        pv, pval = proxy
        return [Finding(
            "process-env-injection", "medium",
            "A running process routes through the ARTEX recording-proxy default endpoint",
            f"{label}: {pv}={pval} (ARTEX --proxy default {PROXY_DEFAULT_ENDPOINT})",
            "agent/worker.go",
            "The endpoint is the --proxy default and is configurable; correlate with "
            "the MITM CA under traffic/_ca/.",
        )]
    return []


def _parse_environ_bytes(raw):
    """Parse a NUL-separated /proc/<pid>/environ blob into a KEY->VALUE dict."""
    env = {}
    for tok in raw.split(b"\x00"):
        if not tok:
            continue
        s = tok.decode("utf-8", "replace")
        if "=" in s:
            k, v = s.split("=", 1)
            env[k] = v
    return env


def parse_proc_dump(text):
    r"""Parse a captured process-environment dump into [(label, env), ...]. Blocks
    are separated by a blank line; a line starting with '#' sets the block label;
    other entries are KEY=VALUE (NUL or newline separated). Produce such a dump on
    the host with:
        for p in /proc/[0-9]*; do echo "# $p"; tr '\0' '\n' < "$p/environ"; echo; done
    """
    procs = []
    for block in re.split(r"\n[ \t]*\n", text.replace("\x00", "\n")):
        label = None
        env = {}
        for line in block.splitlines():
            if not line.strip():
                continue
            if line.lstrip().startswith("#"):
                label = line.lstrip()[1:].strip() or label
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v
        if env:
            procs.append((label or "process", env))
    return procs


def gather_process_envs():
    """(procs, note, unreadable): read each /proc/<pid>/environ on the live Linux
    host. note is non-empty when /proc is unavailable (non-Linux) or some environs
    were unreadable, so the caller never mistakes 'did not run' for 'clean'."""
    if not sys.platform.startswith("linux") or not os.path.isdir("/proc"):
        return [], (
            "process-env check skipped (no /proc on this OS; run on the Linux host, "
            "or pass --proc-from a captured env dump)."
        ), 0
    procs = []
    unreadable = 0
    mypid = str(os.getpid())
    try:
        pids = os.listdir("/proc")
    except OSError as e:
        return [], f"process-env check could not list /proc: {e}", 0
    for pid in pids:
        if not pid.isdigit() or pid == mypid:
            continue
        try:
            with open(os.path.join("/proc", pid, "environ"), "rb") as f:
                raw = f.read()
        except OSError:
            unreadable += 1
            continue
        env = _parse_environ_bytes(raw)
        if not env:
            continue
        comm = pid
        try:
            with open(os.path.join("/proc", pid, "comm"), "r", encoding="utf-8", errors="replace") as f:
                comm = f.read().strip() or pid
        except OSError:
            pass
        procs.append((f"pid {pid} ({comm})", env))
    note = ""
    if unreadable:
        note = (
            f"process-env check: {unreadable} process(es) had an unreadable "
            "/proc/<pid>/environ — run as root to cover every process; absence is not safety."
        )
    return procs, note, unreadable


# --- reporting ----------------------------------------------------------------

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def run_checks(args):
    findings = []
    notes = []

    if args.ports_from:
        try:
            with open(args.ports_from, "r", encoding="utf-8", errors="replace") as f:
                listing = f.read()
        except OSError as e:
            listing = ""
            notes.append(f"could not read --ports-from {args.ports_from}: {e}")
    else:
        listing = gather_listen_listing()
        if not listing:
            notes.append(
                "listening-port check skipped (no ss/netstat/lsof output; "
                "run on the host as a user that can see listeners, or pass --ports-from)."
            )
    findings += check_listening_ports(listing)

    if args.data_dir:
        for d in args.data_dir:
            findings += check_recording_proxy_artifacts(d)
    else:
        notes.append(
            "recording-proxy artifact check skipped (no --data-dir; "
            "ARTEX's default is data/ next to the binary — cmd/artex/main.go)."
        )

    if args.log or args.log_dir:
        log_findings, skipped = scan_logs(args.log, args.log_dir)
        findings += log_findings
        if skipped:
            notes.append(
                f"log-marker check could not read {len(skipped)} compressed log "
                "file(s) with no standard-library codec (e.g. .zst/.lz4), so their "
                "history was NOT scanned — decompress them first or grep them by "
                "hand (e.g. `zstdcat FILE | grep -F artex-`): "
                + ", ".join(sorted(skipped))
            )
    else:
        notes.append("log-marker check skipped (no --log / --log-dir).")

    pg_findings, pg_note = check_pg_schema(args.pg_dsn or os.environ.get("ARTEX_PG_DSN"))
    findings += pg_findings
    if pg_note:
        notes.append(pg_note)

    if args.proc_from:
        try:
            with open(args.proc_from, "r", encoding="utf-8", errors="replace") as f:
                dump = f.read()
        except OSError as e:
            dump = ""
            notes.append(f"could not read --proc-from {args.proc_from}: {e}")
        procs = parse_proc_dump(dump)
        if not procs and dump.strip():
            notes.append(
                "process-env check: --proc-from file parsed no process blocks "
                "(expected '# label' + KEY=VALUE lines, blocks split by a blank line)."
            )
        for label, env in procs:
            findings += scan_process_env(label, env)
    else:
        procs, proc_note, _unreadable = gather_process_envs()
        for label, env in procs:
            findings += scan_process_env(label, env)
        if proc_note:
            notes.append(proc_note)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.check, f.title))
    return findings, notes


def print_report(findings, notes):
    print("ARTEX host triage — read-only; findings are triage leads, not attribution.")
    print("Use only on a host you own or are authorized in writing to inspect.\n")
    if findings:
        print(f"{len(findings)} indicator(s) fired:\n")
        for f in findings:
            print(f"  [{f.severity.upper():6}] {f.title}")
            print(f"           {f.detail}")
            print(f"           grounded in: {f.source}")
            print(f"           caveat: {f.caveat}\n")
    else:
        print("No ARTEX indicators fired in the checks that ran.")
        print("This is NOT a clean bill of health: an operator can rename the binary,")
        print("move the data directory, or change the ports. Absence is not safety.\n")
    if notes:
        print("Notes:")
        for n in notes:
            print("  - " + n.replace("\n", "\n    "))


# --- self-test ----------------------------------------------------------------


def self_test():
    failures = []

    def check(name, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(name)

    # 1. parse_listen_endpoints across ss / netstat / lsof shapes.
    ss_out = (
        "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        "LISTEN 0      4096   *:8787            *:*               users:((\"artex\"))\n"
        "LISTEN 0      4096   127.0.0.1:8788    0.0.0.0:*         users:((\"artex\"))\n"
        "LISTEN 0      128    127.0.0.1:5432    0.0.0.0:*         users:((\"postgres\"))\n"
    )
    eps = parse_listen_endpoints(ss_out)
    check("ports: ss output parses :8787 and 127.0.0.1:8788", ("*", 8787) in eps and ("127.0.0.1", 8788) in eps)
    pf = check_listening_ports(ss_out)
    checks_hit = {f.title for f in pf}
    check("ports: both ARTEX listeners reported", len(pf) == 2)
    check("ports: admin-UI listener reported", any("admin-UI" in t for t in checks_hit))
    check("ports: recording-proxy listener reported", any("recording-proxy" in t for t in checks_hit))

    lsof_out = "artex 42 root 7u IPv4 TCP 127.0.0.1:8788 (LISTEN)\n"
    check("ports: lsof shape parses the proxy listener", ("127.0.0.1", 8788) in parse_listen_endpoints(lsof_out))

    # a connected (non-LISTEN) session to :8787 must not be read as a local listener
    estab = "ESTAB 0 0 10.0.0.5:51000 93.184.216.34:8787\n"
    check("ports: a non-LISTEN session to :8787 is ignored", len(check_listening_ports(estab)) == 0)

    with tempfile.TemporaryDirectory() as tmp:
        # 2. recording-proxy artifacts under <data>/traffic/
        data = os.path.join(tmp, "data")
        traffic = os.path.join(data, TRAFFIC_SUBDIR)
        os.makedirs(os.path.join(traffic, "_ca"))
        os.makedirs(os.path.join(traffic, "_index"))
        os.makedirs(os.path.join(traffic, "_blobs"))
        open(os.path.join(traffic, CA_RELPATH), "w").close()
        open(os.path.join(traffic, INDEX_RELPATH), "w").close()
        af = check_recording_proxy_artifacts(data)
        kinds = {f.check for f in af}
        check("ca: CA + index + blobs all reported", kinds == {"recording-proxy-ca", "recording-proxy-index", "recording-proxy-blobs"})

        # 3. log markers
        logpath = os.path.join(tmp, "app.log")
        with open(logpath, "w", encoding="utf-8") as f:
            f.write("GET / HTTP/1.1 artex-enrich/1.0\n")
            f.write("outbound artex-selfupdate to release host\n")
            f.write("blocked: " + LOG_MARKERS[2]["value"] + " this operation is denied\n")
            f.write("a normal line with no markers\n")
        lf, _ = scan_logs([logpath], [])
        check("logs: all three markers fire", len(lf) == 3)

        # 3b. rotated (compressed) logs under a --log-dir are scanned too, not
        # silently skipped. A responder pointing at /var/log/artex expects the
        # rotated history to be covered; a plain read of the compressed bytes
        # would miss every marker inside. Plant one marker per container: a
        # plaintext current log, a .gz, a .bz2, and an .xz rotation.
        rot = os.path.join(tmp, "rotated")
        os.makedirs(rot)
        with open(os.path.join(rot, "artex.log"), "w", encoding="utf-8") as f:
            f.write("outbound artex-selfupdate to release host\n")
        with gzip.open(os.path.join(rot, "artex.log.1.gz"), "wt", encoding="utf-8") as f:
            f.write("GET / HTTP/1.1 artex-enrich/1.0\n")
        with bz2.open(os.path.join(rot, "artex.log.2.bz2"), "wt", encoding="utf-8") as f:
            f.write("blocked: " + LOG_MARKERS[2]["value"] + " this operation is denied\n")
        with lzma.open(os.path.join(rot, "artex.log.3.xz"), "wt", encoding="utf-8") as f:
            f.write("another GET / artex-enrich/1.0 probe\n")
        rf, rskip = scan_logs([], [rot])
        rtitles = [f.title for f in rf]
        check("rotated: plaintext + .gz + .bz2 + .xz markers all fire via --log-dir", len(rf) == 4)
        check("rotated: the .gz/.xz enrichment markers (missed by a plain read) are found",
              sum("enrichment prober" in t for t in rtitles) == 2)
        check("rotated: nothing is reported as skipped when every file has a stdlib codec", rskip == [])

        # 3c. a format with no stdlib codec (.zst) is reported as skipped, never
        # silently treated as clean.
        zstpath = os.path.join(rot, "artex.log.4.zst")
        with open(zstpath, "wb") as f:
            f.write(b"\x28\xb5\x2f\xfd and bytes a plain read would mis-handle")
        _rf2, rskip2 = scan_logs([], [rot])
        check("rotated: a .zst log (no stdlib codec) is reported as skipped", zstpath in rskip2)

        # 4. clean host: nothing fires, no false positives
        clean = os.path.join(tmp, "clean")
        os.makedirs(clean)
        cleanlog = os.path.join(tmp, "clean.log")
        with open(cleanlog, "w", encoding="utf-8") as f:
            f.write("nothing to see here\nGET /health 200\n")
        clean_lf, clean_skip = scan_logs([cleanlog], [])
        check("clean: no artifact findings on an empty data dir", len(check_recording_proxy_artifacts(clean)) == 0)
        check("clean: no log findings on a benign log", len(clean_lf) == 0 and clean_skip == [])
        check("clean: no port findings on empty listing", len(check_listening_ports("")) == 0)

    # 5. pg schema: skipped path returns a manual-query note, no finding
    pgf, pgnote = check_pg_schema("")
    check("pg: no DSN yields a manual-query note and no finding", len(pgf) == 0 and "psql" in pgnote and SCHEMA_TABLES[0] in SCHEMA_QUERY)

    # 6. recording-proxy env injection in running processes (agent/worker.go proxyEnv)
    dump = (
        "# pid 101 (curl)\n"
        "PATH=/usr/bin\n"
        "HTTP_PROXY=127.0.0.1:8788\n"
        "HTTPS_PROXY=127.0.0.1:8788\n"
        "REQUESTS_CA_BUNDLE=/opt/artex/data/traffic/_ca/mitmproxy-ca-cert.pem\n"
        "\n"
        "# pid 202 (nginx)\n"
        "PATH=/usr/sbin\n"
        "HOME=/var/www\n"
        "\n"
        "# pid 303 (apt)\n"
        "HTTP_PROXY=http://corp-proxy.local:3128\n"
        "\n"
        "# pid 404 (python)\n"
        "REQUESTS_CA_BUNDLE=/opt/artex/data/traffic/_ca/mitmproxy-ca-cert.pem\n"
        "\n"
        "# pid 505 (wget)\n"
        "https_proxy=127.0.0.1:8788\n"
    )
    procs = parse_proc_dump(dump)
    check("procenv: dump parses five process blocks", len(procs) == 5)
    by_label = {label: env for label, env in procs}
    inj = scan_process_env("pid 101 (curl)", by_label.get("pid 101 (curl)", {}))
    check("procenv: proxy + mitmproxy CA fires one HIGH injection finding",
          len(inj) == 1 and inj[0].severity == "high" and inj[0].check == "process-env-injection")
    benign = scan_process_env("pid 202 (nginx)", by_label.get("pid 202 (nginx)", {}))
    check("procenv: a benign process fires nothing", len(benign) == 0)
    corp = scan_process_env("pid 303 (apt)", by_label.get("pid 303 (apt)", {}))
    check("procenv: a corporate proxy (not :8788, no mitm CA) is not a false positive", len(corp) == 0)
    caonly = scan_process_env("pid 404 (python)", by_label.get("pid 404 (python)", {}))
    check("procenv: a mitmproxy CA alone fires one MEDIUM finding",
          len(caonly) == 1 and caonly[0].severity == "medium")
    proxyonly = scan_process_env("pid 505 (wget)", by_label.get("pid 505 (wget)", {}))
    check("procenv: the ARTEX default proxy endpoint alone fires one MEDIUM finding",
          len(proxyonly) == 1 and proxyonly[0].severity == "medium")

    print()
    if failures:
        print(f"RESULT: FAIL ({len(failures)} assertion(s) failed)")
        return 1
    print("RESULT: PASS")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        description="Read-only host triage for a suspected ARTEX host (detections/triage).",
    )
    p.add_argument("--data-dir", action="append", default=[], metavar="PATH",
                   help="ARTEX data directory to check for recording-proxy artifacts (repeatable).")
    p.add_argument("--log", action="append", default=[], metavar="PATH",
                   help="log file to scan for ARTEX markers (repeatable).")
    p.add_argument("--log-dir", action="append", default=[], metavar="PATH",
                   help="directory of log files to scan recursively; rotated "
                        ".gz/.bz2/.xz logs are decompressed and scanned too, while "
                        ".zst/.lz4 (no stdlib codec) are reported as skipped "
                        "(repeatable).")
    p.add_argument("--pg-dsn", default=None, metavar="DSN",
                   help="PostgreSQL DSN to check for the exploration schema (defaults to $ARTEX_PG_DSN).")
    p.add_argument("--ports-from", default=None, metavar="FILE",
                   help="read a port listing from FILE instead of running ss/netstat/lsof.")
    p.add_argument("--proc-from", default=None, metavar="FILE",
                   help="read a captured process-environment dump from FILE instead of "
                        "reading /proc on the live host (offline / forensic-image triage). "
                        "Format: '# label' + KEY=VALUE lines, process blocks split by a blank line.")
    p.add_argument("--json", action="store_true", help="emit findings as JSON.")
    p.add_argument("--exit-code", action="store_true",
                   help="exit 1 if any indicator fired (default: always exit 0).")
    p.add_argument("--self-test", action="store_true",
                   help="run the built-in fixture test and exit.")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.self_test:
        return self_test()
    findings, notes = run_checks(args)
    if args.json:
        print(json.dumps(
            {"findings": [f.as_dict() for f in findings], "notes": notes},
            ensure_ascii=False, indent=2,
        ))
    else:
        print_report(findings, notes)
    if args.exit_code and findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
