#!/usr/bin/env python3
"""저장소 안 마크다운 문서의 내부 링크·이미지·앵커 참조 무결성을 검사한다.

추적되는 모든 `.md` 문서를 훑어 두 가지를 확인한다.

1. 저장소 안 다른 파일을 가리키는 상대 경로 링크(`[text](path)`)와 이미지
   참조(`![alt](path)`·`<img src="path">`)가 실제로 존재하는 파일을 가리키는지.
2. 문서 앵커 링크(`[text](#heading)`·`[text](other.md#heading)`)가 대상 `.md`
   문서에 실제로 있는 헤딩을 가리키는지. 앵커 slug 는 GitHub 의 규칙
   (소문자화 → `\\p{Word}`·하이픈·공백만 남기고 제거 → 공백을 하이픈으로,
   같은 slug 가 겹치면 등장 순서대로 `-1`·`-2` 접미)을 표준 라이브러리로
   재현해 생성한다.

깨진 참조가 하나라도 있으면 종료 코드 1 로 끝나므로, CI 머지 게이트
(`.github/workflows/docs.yml`)와 기여자의 로컬 검증에 그대로 쓸 수 있다.

검사 대상이 아닌 것:
- 외부 URL(`http://`·`https://`·`mailto:`·`tel:`·`data:`): 네트워크에 의존해
  flaky 하므로 이 결정론적 게이트에서는 다루지 않는다. 외부 링크 상태는 별도로
  점검한다.
- `.md` 가 아닌 파일을 가리키는 링크의 `#` 뒤 조각(예: 소스 코드 줄 번호): 헤딩
  앵커가 아니므로 파일 실존만 확인하고 앵커는 검사하지 않는다.
- 이미지 참조의 `#` 조각: 이미지에는 헤딩 앵커가 의미가 없다.
- fenced code block(``` 또는 ~~~ 로 감싼 블록) 안의 예시 링크·헤딩 꼴 주석:
  실제 참조·헤딩이 아니라 코드 예시이므로 건너뛴다.

표준 라이브러리만 쓰고 네트워크에 접속하지 않는다. 실행: `python3 -I scripts/check-doc-links.py`
"""
import os
import re
import subprocess
import sys
import unicodedata
from collections import defaultdict

# [text](path) 중 이미지(`![...]`)가 아닌 링크. 경로는 공백 전까지(제목 "..." 제외).
MD_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)")
# ![alt](path) 이미지 링크.
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)")
# <img ... src="path" ...> HTML 이미지.
HTML_IMAGE = re.compile(r"<img[^>]*\bsrc=[\"']([^\"']+)[\"']", re.IGNORECASE)

# 네트워크·비파일 스킴. 앵커(`#`)는 같은 문서 참조이므로 여기 넣지 않는다.
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "tel:", "data:")

ATX_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
# 헤딩 텍스트 안의 인라인 마크다운을 걷어내 순수 텍스트만 남긴다.
MD_INLINE_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")


def is_external(target: str) -> bool:
    return target.startswith(EXTERNAL_PREFIXES)


def _is_word_char(ch: str) -> bool:
    """GitHub 의 앵커 slug 규칙이 남기는 `\\p{Word}` 문자인지 판정한다.

    Ruby 정규식 `\\p{Word}` = Letter(L*) + Mark(M*) + Decimal_Number(Nd)
    + Connector_Punctuation(Pc) + Join_Control(U+200C·U+200D). 한글·한자·
    언더스코어·이모지의 variation selector(Mn) 등이 그대로 유지된다.
    """
    if ch == "_":
        return True
    if ch in ("‌", "‍"):
        return True
    category = unicodedata.category(ch)
    if category[0] in ("L", "M"):
        return True
    return category in ("Nd", "Pc")


def slugify(text: str) -> str:
    """헤딩 텍스트를 GitHub 의 앵커 slug 로 변환한다(중복 접미 처리 제외)."""
    text = text.strip().lower()
    out = []
    for ch in text:
        if ch == " ":
            out.append("-")
        elif ch == "-" or _is_word_char(ch):
            out.append(ch)
    return "".join(out)


def heading_slugs(root: str, md: str) -> set:
    """파일의 모든 ATX 헤딩에서 GitHub 앵커 slug 집합을 만든다.

    같은 slug 가 겹치면 GitHub 처럼 등장 순서대로 `-1`·`-2` 접미를 붙인다.
    """
    slugs = set()
    counts = defaultdict(int)
    in_fence = False
    with open(os.path.join(root, md), encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            stripped = line.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            match = ATX_HEADING.match(line.rstrip("\n"))
            if not match:
                continue
            raw = match.group(2)
            raw = MD_INLINE_LINK.sub(r"\1", raw)
            raw = raw.replace("`", "").replace("*", "").replace("_", "")
            base = slugify(raw)
            seen = counts[base]
            counts[base] += 1
            slugs.add(base if seen == 0 else f"{base}-{seen}")
    return slugs


def main() -> int:
    root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True
    ).strip()
    tracked = subprocess.check_output(
        ["git", "ls-files"], cwd=root, text=True
    ).splitlines()
    md_files = [f for f in tracked if f.endswith(".md")]

    slug_cache: dict = {}

    def slugs_of(md_path: str) -> set:
        if md_path not in slug_cache:
            slug_cache[md_path] = heading_slugs(root, md_path)
        return slug_cache[md_path]

    checked_files = 0
    checked_anchors = 0
    broken_files = []
    broken_anchors = []
    for md in md_files:
        with open(os.path.join(root, md), encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        base_dir = os.path.dirname(md)
        in_fence = False
        for lineno, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for pattern in (MD_LINK, MD_IMAGE, HTML_IMAGE):
                for match in pattern.finditer(line):
                    target = match.group(1).strip()
                    if is_external(target):
                        continue

                    if target.startswith("#"):
                        file_part, anchor = "", target[1:]
                    elif "#" in target:
                        file_part, anchor = target.split("#", 1)
                    else:
                        file_part, anchor = target, ""
                    file_part = file_part.split("?", 1)[0]
                    anchor = anchor.strip()

                    # 가리키는 .md 문서(앵커 검사 대상). 다른 파일 링크면 그 파일,
                    # 파일 조각이 없는 `#앵커`면 자기 문서.
                    target_md = None
                    if file_part:
                        checked_files += 1
                        resolved = os.path.normpath(
                            os.path.join(root, base_dir, file_part)
                        )
                        if not os.path.exists(resolved):
                            broken_files.append((md, lineno, target))
                            continue
                        if file_part.endswith(".md"):
                            target_md = os.path.normpath(
                                os.path.join(base_dir, file_part)
                            )
                    else:
                        target_md = md

                    # 앵커는 본문 링크(MD_LINK)에만 의미가 있다. 이미지 참조의
                    # `#` 조각은 건너뛴다.
                    if anchor and target_md is not None and pattern is MD_LINK:
                        checked_anchors += 1
                        if anchor not in slugs_of(target_md):
                            broken_anchors.append((md, lineno, target, target_md))

    print(
        f"추적 마크다운 {len(md_files)}개 · 파일 참조 {checked_files}개 · "
        f"앵커 참조 {checked_anchors}개 검사"
    )
    if broken_files:
        print(f"깨진 파일 참조 {len(broken_files)}개 — 가리키는 파일이 저장소에 없습니다:")
        for md, lineno, target in broken_files:
            print(f"  {md}:{lineno} -> {target}")
    if broken_anchors:
        print(f"깨진 앵커 참조 {len(broken_anchors)}개 — 대상 문서에 그 헤딩이 없습니다:")
        for md, lineno, target, target_md in broken_anchors:
            print(f"  {md}:{lineno} -> {target}  (대상: {target_md})")
    if broken_files or broken_anchors:
        return 1
    print("깨진 참조 0 — 모든 내부 링크·이미지·앵커가 실존 대상을 가리킵니다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
