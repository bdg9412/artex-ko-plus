#!/usr/bin/env python3
"""추적되는 마크다운 문서가 가리키는 외부 링크(http·https)가 아직 살아 있는지 점검한다.

자매 스크립트 `check-doc-links.py` 는 저장소 안 내부 링크·앵커만 보고 외부 URL 은
설계상 건너뛴다(네트워크에 의존해 flaky 하므로 머지 게이트에서 다루지 않는다). 이
스크립트가 그 "별도 점검"을 맡는다. README 최상단·방어 가이드·detections README 가
방문자와 방어자에게 "여기로 가 보라"고 안내하는 외부 링크(사고 신고 창구 boho.or.kr·
privacy.go.kr·pipc.go.kr·fsec.or.kr, CISA KEV, OWASP·SigmaHQ·Suricata·MITRE·MISP,
원본 데모 artex-demo.vercel.app, GitHub 배지 등)가 변질·이동·폐쇄되면 조용히 깨진
채로 남는데, 그것을 주기적으로·수동으로 잡아낸다.

점검 대상 URL 을 고르는 규칙
- 추적되는 모든 `.md` 를 훑되, fenced code block(``` 또는 ~~~)과 인라인 코드 스팬
  (`` `...` ``) 안의 URL 은 건너뛴다. 그 안의 URL 은 명령 예시·설정 값·인용된 외부
  자산(예: 곁질문 검증 문서의 `id.redhaze.top`)이라 "독자가 따라갈 참조 링크"가 아니다.
- 마크다운 링크·이미지(`[text](url)`·`![alt](url)`), 자동 링크(`<url>`), 그리고 남은
  산문 안의 맨 URL 에서 http·https 주소를 모은다.
- 예약·플레이스홀더 호스트는 제외한다: localhost·사설/루프백 IP(127.·10.·192.168.·
  169.254.·172.16~31.·0.0.0.0·::1), RFC 2606/6761 예약(example.com/org/net/edu·
  `*.example.*`·`.test`·`.invalid`·`.local`·`.tld`), 점이 없어 FQDN 이 아닌 이름(예: `target`).

살아 있는지 확인하는 방법 (MAINTAINING.md 8.2 의 교훈을 코드로 옮긴 것)
국내 공공·보안 기관 사이트는 HEAD 요청·기본 User-Agent 를 거부하거나 여러 번
리다이렉트하므로, 단순 확인은 멀쩡한 링크를 깨진 것으로 오인한다. 그래서 이 스크립트는
**브라우저 User-Agent 로, GET 으로, 리다이렉트를 따라가며** 확인한다. 상태를 세 가지로
나눈다.
- OK: 최종 상태가 2xx·3xx. 링크가 유효하다.
- RESTRICTED: 401·403·405·429. 호스트는 살아 있으나 확인 방법이 서버 접근 정책(봇 차단·
  메서드 거부·속도 제한)에 막힌 것일 뿐 깨진 링크가 아니다. 보고하되 실패로 치지 않는다.
- DOWN: 404·410·5xx(재시도 후에도)·DNS/연결/타임아웃/SSL 오류(재시도 후에도). 실제로
  깨졌을 가능성이 높다.

네트워크 오류·5xx·429 는 소폭 지연을 두고 재시도해 일시적 깜빡임과 진짜 장애를 가른다.
표준 라이브러리만 쓴다. 이 스크립트는 저장소의 **공개 문서가 이미 가리키는** 참조 URL 에만
GET 을 보내 생존을 확인할 뿐, 어떤 대상도 스캔·탐침하지 않는다.

알려진 예외(allowlist)
`scripts/external-links-allowlist.txt` 에 적힌 URL 이 DOWN 으로 나오면 "ALLOWED" 로 따로
분류하고 strict 종료 코드에 넣지 않는다. 우리가 소유하지 않아 고칠 수 없는, 상류 원문 보존
파일(예: 상류 CHANGELOG.zh.md)이 물려받은 죽은 링크를 투명하게 기록해, 주기 strict 점검이
그 하나 때문에 영구히 빨갛게 되지 않고 **새로 깨진 링크가 생길 때만** 빨갛게 되도록 한다.

실행
- 기본(보고·종료 코드 0): `python3 -I scripts/check-external-links.py`
- 머지 게이트가 아닌 주기/릴리스 점검(새로 깨진 링크가 있으면 빨갛게): `--strict` (allowlist 에
  없는 DOWN 이 하나라도 있으면 종료 코드 1). RESTRICTED·ALLOWED 는 strict 에서도 실패로 치지 않는다.
- 네트워크 없이 추출 집합만 미리 보기: `--list` (호출 없이 점검 대상 URL 과 출처를 출력).
"""
import argparse
import http.client
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from urllib.parse import urlsplit

# [text](url) 본문 링크(이미지 아님)와 ![alt](url) 이미지. 경로는 공백·닫는 괄호 전까지.
MD_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)")
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)")
# <https://...> 자동 링크.
AUTOLINK = re.compile(r"<(https?://[^>\s]+)>")
# 산문 안의 맨 URL. 뒤따르는 구두점은 뒤에서 벗겨낸다.
BARE_URL = re.compile(r"https?://[^\s)>\]\"'`]+")
# 인라인 코드 스팬 `...` (단일 백틱). 추출 전에 공백으로 지운다.
INLINE_CODE = re.compile(r"`[^`]*`")
# 산문 URL 끝에 흔히 붙는 구두점.
TRAILING_PUNCT = ".,;:!?\"'»)]}>"

# IPv4 사설/루프백/링크로컬 대역(172.16~31. 은 별도 패턴).
PRIVATE_IPV4 = re.compile(r"^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0$)")
PRIVATE_IPV4_172 = re.compile(r"^172\.(1[6-9]|2\d|3[01])\.")

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
)

# 호스트는 살아 있으나 확인 방법이 서버 정책에 막힌 상태 코드(깨짐 아님).
RESTRICTED_CODES = {401, 403, 405, 429}

ALLOWLIST_PATH = os.path.join("scripts", "external-links-allowlist.txt")


def load_allowlist(root: str) -> set:
    """우리가 고칠 수 없는 알려진 DOWN URL 집합을 읽는다(없으면 빈 집합).

    한 줄에 URL 하나. `#` 뒤는 주석, 빈 줄·주석 전용 줄은 무시한다.
    """
    path = os.path.join(root, ALLOWLIST_PATH)
    allow = set()
    if not os.path.exists(path):
        return allow
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                allow.add(line)
    return allow


def strip_code(line: str) -> str:
    """fence 밖 한 줄에서 인라인 코드 스팬을 지운다(그 안의 URL 은 참조가 아니다)."""
    return INLINE_CODE.sub(" ", line)


def is_checkable(url: str) -> bool:
    """예약·플레이스홀더 호스트를 걸러, 실제 점검할 가치가 있는 외부 URL 만 남긴다."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = parts.hostname
    if not host:
        return False
    host = host.lower()
    if host == "localhost" or host.endswith(".localhost"):
        return False
    if host == "::1":
        return False
    if PRIVATE_IPV4.match(host) or PRIVATE_IPV4_172.match(host):
        return False
    if host in ("example.com", "example.org", "example.net", "example.edu"):
        return False
    if host.endswith((".example.com", ".example.org", ".example.net", ".example")):
        return False
    if host.endswith((".test", ".invalid", ".local", ".localdomain", ".tld")):
        return False
    if "." not in host:  # FQDN 이 아닌 맨 이름(예: target)
        return False
    return True


def extract(root: str, md_files: list) -> dict:
    """추적 .md 에서 점검할 외부 URL → [(파일, 줄번호), ...] 사전을 만든다."""
    found = defaultdict(list)
    for md in md_files:
        with open(os.path.join(root, md), encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        in_fence = False
        for lineno, raw in enumerate(lines, 1):
            stripped = raw.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            line = strip_code(raw)
            candidates = []
            for pattern in (MD_LINK, MD_IMAGE, AUTOLINK):
                candidates.extend(m.group(1) for m in pattern.finditer(line))
            for m in BARE_URL.finditer(line):
                candidates.append(m.group(0).rstrip(TRAILING_PUNCT))
            for url in candidates:
                url = url.strip().rstrip(TRAILING_PUNCT)
                if is_checkable(url):
                    where = (md, lineno)
                    if where not in found[url]:
                        found[url].append(where)
    return found


def probe(url: str, timeout: float, retries: int, delay: float):
    """URL 에 브라우저 UA 로 GET 을 보내 (분류, 상세) 를 돌려준다.

    분류는 "OK" · "RESTRICTED" · "DOWN". 네트워크 오류·5xx·429 는 재시도한다.
    """
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": BROWSER_UA,
            "Accept": "*/*",
            "Accept-Language": "ko,en;q=0.8",
        },
    )
    last = ""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = resp.getcode()
                if code in RESTRICTED_CODES:
                    return "RESTRICTED", f"HTTP {code}"
                return "OK", f"HTTP {code}"
        except urllib.error.HTTPError as exc:
            code = exc.code
            if code in RESTRICTED_CODES:
                return "RESTRICTED", f"HTTP {code}"
            if code >= 500 or code == 408:
                last = f"HTTP {code}"  # 일시적일 수 있어 재시도
            else:
                return "DOWN", f"HTTP {code}"  # 404·410 등은 확정, 재시도 불요
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            ssl.SSLError,
            socket.timeout,
            ConnectionError,
            TimeoutError,
            OSError,
        ) as exc:
            reason = getattr(exc, "reason", exc)
            last = f"{type(exc).__name__}: {reason}"
        if attempt < retries:
            time.sleep(delay * (attempt + 1))
    return "DOWN", last


def main() -> int:
    ap = argparse.ArgumentParser(description="추적 마크다운의 외부 링크 생존 점검")
    ap.add_argument("--strict", action="store_true",
                    help="DOWN 이 하나라도 있으면 종료 코드 1 (주기/릴리스 점검용)")
    ap.add_argument("--list", action="store_true",
                    help="네트워크 호출 없이 점검 대상 URL 과 출처만 출력")
    ap.add_argument("--timeout", type=float, default=15.0, help="요청 타임아웃(초)")
    ap.add_argument("--retries", type=int, default=2, help="네트워크 오류·5xx·429 재시도 횟수")
    ap.add_argument("--delay", type=float, default=0.5, help="호출 간·재시도 간 기본 지연(초)")
    args = ap.parse_args()

    root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True
    ).strip()
    tracked = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
    md_files = [f for f in tracked if f.endswith(".md")]

    allow = load_allowlist(root)
    found = extract(root, md_files)
    urls = sorted(found)
    print(f"추적 마크다운 {len(md_files)}개에서 점검 대상 외부 URL {len(urls)}개 수집")

    if args.list:
        for url in urls:
            where = ", ".join(f"{f}:{ln}" for f, ln in found[url])
            tag = " [allowlist]" if url in allow else ""
            print(f"  {url}{tag}  ({where})")
        return 0

    results = {"OK": [], "RESTRICTED": [], "ALLOWED": [], "DOWN": []}
    for i, url in enumerate(urls):
        if i:
            time.sleep(args.delay)  # 호출 간 소폭 지연(샌드박스 조절 회피)
        verdict, detail = probe(url, args.timeout, args.retries, args.delay)
        if verdict == "DOWN" and url in allow:
            verdict = "ALLOWED"  # 고칠 수 없는 알려진 상류 상속 DOWN
        results[verdict].append((url, detail))
        print(f"  [{verdict:10}] {url} — {detail}")

    print(
        f"\n요약: OK {len(results['OK'])} · RESTRICTED {len(results['RESTRICTED'])} · "
        f"ALLOWED {len(results['ALLOWED'])} · DOWN {len(results['DOWN'])}"
    )
    if results["RESTRICTED"]:
        print("RESTRICTED(호스트 생존·확인 방법이 막힘, 깨진 링크 아님):")
        for url, detail in results["RESTRICTED"]:
            print(f"  {url} — {detail}")
    if results["ALLOWED"]:
        print("ALLOWED(allowlist 에 적힌 알려진 DOWN — 우리가 고칠 수 없어 strict 제외):")
        for url, detail in results["ALLOWED"]:
            where = ", ".join(f"{f}:{ln}" for f, ln in found[url])
            print(f"  {url} — {detail}  (참조: {where})")
    if results["DOWN"]:
        print("DOWN(깨졌을 가능성 높음 — 확인 필요):")
        for url, detail in results["DOWN"]:
            where = ", ".join(f"{f}:{ln}" for f, ln in found[url])
            print(f"  {url} — {detail}  (참조: {where})")

    if args.strict and results["DOWN"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
