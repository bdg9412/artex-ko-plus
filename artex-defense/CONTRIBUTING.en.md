# Contributing

[한국어](CONTRIBUTING.md) · English

Thank you for your interest in the Korean edition of ARTEX (`artex-ko`). This document
gathers the scope, policies, and procedures you should know before you start contributing.
Before you send a contribution, please read [Authorized use and legal responsibility](#authorized-use-and-legal-responsibility)
and [Localization policy](#localization-policy) first.

- To report a bug or suggest a feature → use the [issue templates](https://github.com/jiwoochris/artex-ko/issues/new/choose).
- If you find a translation or localization error → use the "translation/localization error" issue template.
- If you find a security vulnerability → **do not open a public issue**; follow the procedure in [SECURITY.en.md](SECURITY.en.md).
- Everyone who takes part must follow the [Code of Conduct (CODE_OF_CONDUCT.en.md)](CODE_OF_CONDUCT.en.md).

---

## Authorized use and legal responsibility

ARTEX is an offensive-security tool in which an LLM multi-agent system performs penetration
testing **autonomously**. Contributors are bound by the same scope limits as users.

- When you verify code, run the tool only against **a target you own or have explicit written
  authorization for**, or against a **locally isolated environment** (for example an
  intentionally vulnerable target you own, such as OWASP Juice Shop or DVWA launched with Docker).
- We do not accept code that scans, probes, or exploits real, production, or remote systems
  outside the authorized scope, nor changes that encourage such use.
- In the Republic of Korea, intruding into another party's information and communications
  network without authorization, or causing a disruption to it, violates the Act on Promotion
  of Information and Communications Network Utilization and Information Protection; and any
  personal data collected or exposed falls under the Personal Information Protection Act. The
  full notice is in the [README](README.en.md#️-read-first--authorized-use-and-legal-notice).

Legal responsibility for how the code or documentation you contribute is used rests with the
user who runs it. This repository is provided "AS IS."

---

## Localization policy

The reason this repository exists is to **preserve the original
[Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)'s judgment performance exactly while
changing only the user-facing output to Korean**. Translation contributions that depart from
this policy can degrade performance, so we do not accept them.

- **Do not translate the agent's internal reasoning prompts (the behavior-instruction body).**
  The behavior benchmarked in the original language (Chinese) must be preserved. This body
  lives in `agent/promptcatalog.go` and the DB seed (`agent_prompts`). Translating it causes
  drift in the agent's judgment.
- **Only user-facing output is forced into Korean.** This covers detection findings
  (`report_finding`), fact summaries (`record_fact`), the final report, and chat responses.
  The enforcement is a code-fixed tail called `langDirective()` in `agent/prompt.go`, appended
  to the end of each role's system prompt. To change the output language, modify this function.
- **Commands, payloads, code, URLs, and log text are not translated.** They are the originals
  needed for analysis, so they are left as is.
- **The original Chinese is preserved.** Documents keep the original in `README.zh.md` and UI
  strings keep it in `web/messages/zh.json`, so that changes in the upstream repository are
  easy to compare against. Korean translations are filled into `web/messages/ko.json`.
- When you translate a new UI string, do not hard-code it; add it as a key in the message files.
- **The output-language enforcement is a prompt nudge, not a hard cap.** `langDirective()`
  **instructs** the model to output Korean; it does not force-lock the language. Korean fidelity
  therefore varies with the model's capability, the role, and the context. Use a capable
  (frontier-class) model when you verify localization changes. Cheap or small models can revert
  reports and summaries to the original language (Chinese), so do not judge whether a translation
  is applied correctly from a cheap model's output alone. The `max_tokens` pitfall when using
  OpenAI-family models is covered in the
  [README's "Model selection and output language" section](README.en.md#model-selection-and-output-language).
- **The procedure for keeping up with upstream changes is in the maintainer document.** When
  the original ARTEX is updated, the runbook for distinguishing preserved assets from
  translation targets, reflecting them, and checking translation symmetry and drift is in
  [MAINTAINING.en.md](MAINTAINING.en.md).

---

## Development environment

This project consists of a **Go backend** (with the frontend embedded in a single binary) plus
a **Next.js frontend**.

The design intent of the main features is documented in the design docs under `docs/`. When you
work on the feature that links vulnerabilities to traffic evidence (the report agent's automatic
binding, `report_finding`'s `traffic_refs`, and so on), read the
[vulnerability multi-traffic-evidence design doc](docs/finding-traffic-evidence-en.md) first.
The original (Chinese) is preserved as `finding-traffic-evidence-zh.md` in the same folder.

### Required versions

- Go 1.26 or later (per `go.mod`)
- Node.js 22 or later (per the release workflow)
- Docker and Docker Compose (for local runs and verification)

### Backend (Go)

If Go is installed locally, run the following from the repository root.

```bash
go build ./...
go vet ./agent/
go test ./agent/
```

If you do not have Go locally, you can verify the same way with Docker. Keeping the module and
build caches in named volumes makes re-runs faster.

```bash
docker run --rm -v "$PWD":/src -w /src \
  -v artexko-gomod:/go/pkg/mod -v artexko-gocache:/root/.cache/go-build \
  golang:1.26 sh -c 'go build ./... && go vet ./agent/ && go test ./agent/'
```

#### DB integration tests (postgres required)

The `go test ./agent/` above **quietly skips the DB integration tests** that only run when
connected to PostgreSQL. Six packages — `agent`, `config`, `db`, `evidence`, `llmrec`,
`server` — contain tests that require a real database; if there is no `ARTEX_PG_DSN`
environment variable and no `database` entry in the config file, those tests are skipped with
`--- SKIP` and the package still ends in `ok`. As a result, if you fix one of these six
packages and verify without a DSN, **it can pass locally (ok) while the PR's `go-db` job
fails.**

To run these tests locally, bring up PostgreSQL and pass `ARTEX_PG_DSN`. The example below
launches the same `postgres:16-alpine` as CI on an isolated network, reusing the named volumes
from above.

```bash
# 1) Bring up an isolated network and an empty postgres (same image and account as CI).
docker network create artexko-db 2>/dev/null || true
docker run -d --name artexko-pg --network artexko-db \
  -e POSTGRES_USER=artex -e POSTGRES_PASSWORD=artex -e POSTGRES_DB=artex \
  postgres:16-alpine
until docker exec artexko-pg pg_isready -U artex -d artex >/dev/null 2>&1; do sleep 1; done

# 2) Pass the DSN to run the DB integration packages (the DSN host is the container name).
#    To run only the package you fixed, replace ./agent/ with config, db, evidence, llmrec, or server.
docker run --rm --network artexko-db -v "$PWD":/src -w /src \
  -v artexko-gomod:/go/pkg/mod -v artexko-gocache:/root/.cache/go-build \
  -e ARTEX_PG_DSN='postgres://artex:artex@artexko-pg:5432/artex?sslmode=disable' \
  golang:1.26 sh -c 'go test ./agent/ -count=1'

# 3) Clean up.
docker rm -f artexko-pg && docker network rm artexko-db
```

CI's `go-db` job **isolates each of these six packages with its own postgres** and forces them
to run before merge (`.github/workflows/ci.yml`). If you changed a DB integration package, we
recommend verifying that package directly with the method above before you open the PR.

### Frontend (web)

```bash
cd web
npm ci
npm run dev          # dev server
npm run build        # production build
npm run build:static # static-export build (merge gate; includes TypeScript type checking)
npm run check        # Biome lint/format check (informational; not a merge gate yet, due to pre-existing debt)
npm run check:fix    # auto-fix
```

Formatting and linting before commit are managed with Biome. `lint-staged` automatically runs
`biome check --write` on staged files.

### Full run (Docker Compose)

```bash
cp .env.example .env     # set POSTGRES_PASSWORD
docker compose up -d     # start artex + postgres → http://localhost:8787
```

---

## Contribution process

1. **Open an issue first.** For large changes it is better to align on direction via an issue
   before you start. For small fixes (typos, links, obvious bugs) you can send a PR directly.
2. **Fork** the repository and create a topic branch. Prefix the branch name with the nature of
   the change, as in `feat/...`, `fix/...`, `docs/...`, `i18n/...`.
3. Write the change and **run the relevant verification yourself.** For a Go change, make the
   `build`/`vet`/`test` above pass. For a web change, make `npm run build:static` pass (it also
   performs the merge gate and the TypeScript type checking). `npm run check` (Biome) still has
   pre-existing lint debt inherited from upstream and is not a merge gate yet — `web.yml` runs it
   only as an informational step — so you do not need to make all of it pass. Instead, just
   confirm that **your change does not add new errors** (when you commit, `lint-staged`
   automatically applies `biome check --write` to the files you staged). If you changed
   documentation (`.md`), run `python3 -I scripts/check-doc-links.py` to confirm that in-repo
   link/image references and document anchor (`#heading`) links are not broken. Anchors are built
   from headings into slugs with the same rule as GitHub and matched, so if you change a heading's
   text without also fixing the anchor links that pointed to it, it is caught here (CI's `docs`
   workflow enforces the same check as a merge gate). This check is also wired as the `docs` hook in
   the repository root's [`.pre-commit-config.yaml`](.pre-commit-config.yaml), so if you run
   `pre-commit install` it runs automatically on every commit (it uses only the Python standard
   library and no network, so it finishes without Docker).
4. **Open a PR.** Follow the [PR template](.github/PULL_REQUEST_TEMPLATE.md) for the title and
   description, and write what you changed, why, and how you verified it. If you changed the UI,
   attach screenshots.
5. For a user-facing change (feature, localization, documentation, detection rule, and so on),
   add one line to the `[Unreleased]` section of the [changelog (CHANGELOG.en.md)](CHANGELOG.en.md).
   Internal refactoring or test-only changes may be omitted.

### Commit messages

Follow the convention of the existing commit history. The format is `type(scope): description`,
and the description is written in Korean.

- `type`: `feat` · `fix` · `docs` · `chore` · `refactor` · `test` · `i18n`, and so on
- `scope`: the changed area (`agent` · `web` · `server`, and so on); optional

Examples.

```
feat(agent): 사용자 노출 출력을 한국어로 강제 (langDirective)
docs: 한국어 README 작성, 원본은 README.zh.md 로 보존
i18n(web): 대시보드 네비게이션 라벨 한국어 번역
```

---

## Contributing detection rules and detection tests

This repository also keeps, in [`detections/`](detections/), rules for **defending against and
detecting** autonomous AI attacks like ARTEX. It consists of deployable [Sigma](https://sigmahq.io)
rules ([`detections/sigma/`](detections/sigma/)), network [Suricata](https://suricata.io) rules
([`detections/suricata/`](detections/suricata/)), a [MITRE ATT&CK](https://attack.mitre.org/)
coverage layer ([`detections/attack/`](detections/attack/)), and tests that reproducibly prove
these rules actually fire ([`detections/tests/`](detections/tests/)). When you add or change a
detection rule, please honor the contract below. Seven test suites mechanically enforce much of
this contract, so if you change only a rule and do not update the tests/layer, the tests fail.

- **Ground every indicator in an observable fact.** The strings, User-Agents, and behavioral
  thresholds a rule uses must be ones actually found in this repository's source, and must not be
  inferred. State the source file that is the basis for the rule (for example, the `artex-enrich/1.0`
  indicator is confirmed in `enrich/enrich.go`). The indicator-match tests
  ([`detections/tests/indicators/`](detections/tests/indicators/)) check that each indicator is
  still present in both the upstream source and the rule, so if an upstream resync changes a source
  string, the test fails unless you fix the rule along with it. If you change the machine-readable
  indicator list ([`detections/indicators/artex_indicators.csv`](detections/indicators/artex_indicators.csv)),
  also update the MISP event that carries those same indicators
  ([`detections/indicators/artex_indicators.misp.json`](detections/indicators/artex_indicators.misp.json)).
  The MISP export test ([`detections/tests/misp/`](detections/tests/misp/)) enforces that the two
  files match row by row and that the event is a valid MISP document loadable by pymisp.
- **State limitations honestly.** Write what a rule cannot catch and its false-positive potential
  in the Sigma rule's `description` and in the Suricata rule's comments. If something is a general
  hunting lead (for example, a destructive command) rather than an ARTEX-specific signature, say so,
  so that a single hit does not get used to conclude the attacker is ARTEX.
- **Pass static validation.** A Sigma rule must pass the SigmaHQ validator criteria with zero issues
  (`sigma check --validation-config detections/tests/sigma_lint/validators.yml`). Plain `sigma check`
  runs only pySigma's core validators, so SigmaHQ conventions such as title casing, field/logsource
  classification, and reference links are filtered only by this config. The four exceptions are
  SigmaHQ monorepo conventions that do not fit a standalone rule set, and their rationale is recorded
  in [`detections/tests/sigma_lint/validators.yml`](detections/tests/sigma_lint/validators.yml). A
  Suricata rule must load cleanly with `suricata -T`.
- **Ship a reproducible test with it.** Prove that the rule fires (or that its structure is valid)
  with a test under [`detections/tests/`](detections/tests/). Generate the input deterministically
  each time rather than committing binaries to the repository; assert properties that are independent
  of the engine version (firing exists, no false positives) exactly; and for figures that fluctuate
  with the version, assert a lower bound and record the baseline separately. If you add or change a
  Sigma correlation rule, the backend portability test
  ([`detections/tests/sigma_backends/`](detections/tests/sigma_backends/)) checks that the rule
  converts across multiple backends, so keep it consistent with the backend-support description in
  [`detections/README.md`](detections/README.md).
- **Update the ATT&CK layer with it.** If you add or change an `attack.*` tag on a rule, update the
  techniques and scores in [`detections/attack/artex_navigator_layer.json`](detections/attack/artex_navigator_layer.json)
  to match. The consistency test enforces a bidirectional rule↔layer match, so it fails if there is a
  rule tag missing from the layer or a layer technique missing from the rules.
- **Do not include anything that reads as attack guidance.** The detection material in this repository
  maintains a defense/detection posture only. We do not accept write-ups that aid an attack, such as
  how to carry out an exploit or techniques for evading detection.

The eight test suites run as-is with only Docker, and do not commit their artifacts to the repository.
Each script exits with a non-zero code if any single assertion fails, so it can be dropped straight
into CI or a pre-commit hook.

```bash
detections/tests/sigma/run.sh           # Sigma: sigma check + backend conversion + indicator preservation
detections/tests/sigma_match/run.sh     # Sigma: atomic rules fire on malicious sample events, stay quiet on benign
detections/tests/sigma_lint/run.sh      # Sigma: full SigmaHQ-convention validators + documented criteria
detections/tests/sigma_backends/run.sh  # Sigma portability: does a correlation rule convert across backends
detections/tests/suricata/run.sh        # Suricata: synthesize pcap → suricata -r → assert alert counts
detections/tests/attack/run.sh          # ATT&CK: bidirectional layer ↔ rule consistency
detections/tests/indicators/run.sh      # Indicators: rule's pinned indicators ↔ upstream source, both ways
detections/tests/misp/run.sh            # MISP: indicator CSV ↔ MISP event sync + pymisp validity
```

To run all eight at once, use [`detections/tests/run-all.sh`](detections/tests/run-all.sh). It runs the
eight sequentially in the same order as CI, runs the rest to the end even if an earlier suite fails, then
prints a per-suite PASS/FAIL summary, and exits with a non-zero code if any one fails. An example of
wiring this runner directly as a pre-commit hook is in the repository root's
[`.pre-commit-config.yaml`](.pre-commit-config.yaml). If you install it with `pip install pre-commit &&
pre-commit install`, the runner runs only on commits that change detection rules or the upstream source
those rules pin (the same scope as CI), catching rule/test mismatches before push. The same config file
also includes the `docs` hook that checks in-repo link/image/anchor references (the `check-doc-links.py`
from step 3 of the contribution flow above).

These eight tests are run by the repository CI
([`.github/workflows/detections.yml`](.github/workflows/detections.yml)) on every push/PR that changes
anything under `detections/`. The indicator-match test also runs when the upstream source files those
indicators point to (`enrich/`, `selfupdate/`, `guard/`, `db/`, `cmd/artex/main.go`) change, catching the
case where an upstream resync changes a User-Agent, marker, or default port and silently makes a rule
stale. So a change that updates only a rule without updating the tests/layer, a rule that breaks a SigmaHQ
convention, or a rule that is inconsistent with the source shows up red in CI before merge.

The rule index and each rule's basis and limitations are in [`detections/README.md`](detections/README.md),
and the tests' assertions and how to run them are in [`detections/tests/README.md`](detections/tests/README.md).

---

## License

This project is distributed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. By
submitting a contribution, you are taken to **agree that your contribution is also released under
AGPL-3.0**. In particular, if you modify this project and provide it to users over a network (for
example, as an online service), you must disclose the complete corresponding source code to those
users. The full terms are in the [LICENSE](LICENSE) file.
