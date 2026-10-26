#!/usr/bin/env python3
"""Create a public source folder and ZIP from the current Git working tree.

Uses tracked and non-ignored untracked files, not Git history. Path exclusions
are enforced even for tracked files. This is not a content-based secret scanner;
scan and review the resulting folder before publishing it.
"""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile


MANIFEST = "SOURCE_MANIFEST.sha256"
GITHUB_README_TEMPLATE = "scripts/release-readme.md"
GITHUB_GUIDE = "docs/FINDING_DEFENSE_INVESTIGATION_KO.md"
GITHUB_DIAGNOSIS_GUIDE = "docs/OFFENSIVE_DIAGNOSIS_KO.md"
GITHUB_HUNTING_GUIDE = "docs/AUTONOMOUS_HUNTING_KO.md"
GITHUB_RELEASE_EVIDENCE = "docs/RELEASE_EVIDENCE_KO.md"
GITHUB_MARKDOWN = frozenset({
    "README.md", GITHUB_GUIDE, GITHUB_DIAGNOSIS_GUIDE, GITHUB_HUNTING_GUIDE,
    GITHUB_RELEASE_EVIDENCE, "docs/defense-ko.md", "docs/defense-en.md",
})
GITHUB_MARKDOWN_PREFIXES = ("skills/", "detections/")
GITHUB_EXCLUDED_PATH_PREFIXES = ("docs/evidence/", "docs/legacy-assessments/", "screenshots/")
MARKDOWN_FILE_LINK = re.compile(r"(?P<image>!?)\[(?P<label>[^\]]+)\]\((?P<target>[^)\s]+)\)")
EXCLUDED_DIRS = frozenset({
    ".git", ".aws", ".codex", ".agents", ".claude", ".local-runtime",
    ".playwright-mcp", ".playwright-cli", ".pnpm-store", ".idea", ".vscode", ".next",
    "__pycache__", "node_modules", "release-artifacts", "evidence-local",
    "work", "test-results", "scan-output", "demo-data", "transcripts",
    "presentation-output",
})
EXCLUDED_ROOTS = frozenset({"data", "dist", "bench"})
EXCLUDED_PATH_PREFIXES = ("web/out/", "server/webui/dist/")
EXCLUDED_NAMES = frozenset({
    "config.json", "scheduler_state.json", "jwt.key", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", "privatekey", "private_key", "private-key",
    "credentials", ".npmrc", ".netrc", ".pypirc",
    ".ds_store", "thumbs.db", "dump.sql", "backup.sql",
})
EXCLUDED_SUFFIXES = (
    ".env", ".har", ".har.json", ".db", ".db-wal", ".db-shm", ".dump",
    ".sqlite", ".sqlite3", ".sqlite-wal", ".sqlite-shm", ".sqlite3-wal",
    ".sqlite3-shm", ".sql.gz", ".sql.bz2", ".sql.xz", ".pem", ".key",
    ".p12", ".pfx", ".zip", ".pptx", ".tar", ".tar.gz", ".tgz", ".tar.bz2",
    ".tbz2", ".tar.xz", ".txz", ".7z", ".rar", ".pyc", ".pyo",
    ".tsbuildinfo", ".swp", ".swo",
)


class ReleaseError(Exception):
    """A release cannot be safely assembled."""


def git(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if result.returncode:
        raise ReleaseError(result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def exclusion_reason(relative, *, github=False):
    """Return a public-release exclusion reason, or None for source files."""
    if relative == "docker-compose.local-restored.yml":
        return "local-only database restore override"
    parts = PurePosixPath(relative).parts
    lowered = tuple(part.lower() for part in parts)
    name = lowered[-1]
    if any(part in EXCLUDED_DIRS for part in lowered[:-1]):
        return "local state, generated files, or dependencies"
    if lowered[0] in EXCLUDED_ROOTS or relative.lower().startswith(EXCLUDED_PATH_PREFIXES):
        return "runtime data or build output"
    if name in EXCLUDED_NAMES:
        return "runtime configuration or authentication file"
    if name != ".env.example" and (name == ".env" or name.startswith(".env.")):
        return "environment values"
    if name.endswith(EXCLUDED_SUFFIXES):
        return "environment, capture, database, private key, archive, or generated file"
    if len(parts) == 1 and name in {
        "artex", "artex.new", "artex.new.sha256", "artex.old", "artex.failed", "artex.upgrade.json",
    }:
        return "local executable or upgrade output"
    if name == MANIFEST.lower():
        return "release manifest is regenerated"
    if relative == GITHUB_README_TEMPLATE:
        return "release README template"
    if github:
        if relative.startswith(GITHUB_EXCLUDED_PATH_PREFIXES):
            return "development evidence or historical material"
        if relative.endswith(".md") and relative not in GITHUB_MARKDOWN \
                and not relative.startswith(GITHUB_MARKDOWN_PREFIXES):
            return "not needed in the GitHub distribution"
    return None


def checked_source(root, relative):
    """Reject unsafe paths, links (including parent links), and special files."""
    path = PurePosixPath(relative)
    if (not relative or path.is_absolute() or ".." in path.parts
            or "\\" in relative or any(ord(char) < 32 or ord(char) == 127 for char in relative)):
        raise ReleaseError(f"Unsafe source path: {relative!r}")
    current = root
    for index, part in enumerate(path.parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            # git ls-files --cached also lists files deleted in the working tree.
            return None
        if stat.S_ISLNK(mode):
            raise ReleaseError(f"Symbolic links are not allowed: {relative}")
        last = index == len(path.parts) - 1
        if not (stat.S_ISREG(mode) if last else stat.S_ISDIR(mode)):
            raise ReleaseError(f"Not a regular source file: {relative}")
    try:
        current.resolve().relative_to(root)
    except ValueError as error:
        raise ReleaseError(f"Source is outside repository: {relative}") from error
    return current


def inventory(root, *, github=False):
    candidates = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    included, excluded = [], []
    for relative in sorted({os.fsdecode(item) for item in candidates.split(b"\0") if item}):
        reason = exclusion_reason(relative, github=github)
        if reason:
            excluded.append((relative, reason))
        else:
            source = checked_source(root, relative)
            if source is None:
                excluded.append((relative, "deleted from working tree"))
            else:
                included.append(relative)
    if not included:
        raise ReleaseError("No public source files remain after exclusions.")
    return included, excluded


def copy_source(root, relative, destination):
    source = checked_source(root, relative)
    if source is None:
        raise ReleaseError(f"Source disappeared during packaging: {relative}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(source, flags), "rb") as reader:
        metadata = os.fstat(reader.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseError(f"Not a regular source file: {relative}")
        digest = hashlib.sha256()
        with destination.open("xb") as writer:
            while chunk := reader.read(1024 * 1024):
                writer.write(chunk)
                digest.update(chunk)
        # Retain ordinary permissions (especially executable scripts), not setuid.
        destination.chmod(stat.S_IMODE(metadata.st_mode) & 0o777)
        os.utime(destination, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    return digest.hexdigest()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as reader:
        while chunk := reader.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def remove_excluded_markdown_links(root, source_folder, relative):
    """Keep release docs readable when a link points to an omitted local file."""
    path = source_folder / relative
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    rewritten, fenced, removed = [], False, 0
    for line in lines:
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        if fenced:
            rewritten.append(line)
            continue

        def replace(match):
            nonlocal removed
            target = match.group("target")
            if target.startswith(("http://", "https://", "mailto:", "tel:", "data:", "#")):
                return match.group(0)
            file_part = target.split("#", 1)[0].split("?", 1)[0]
            resolved = (root / Path(relative).parent / file_part).resolve()
            try:
                target_relative = resolved.relative_to(root)
            except ValueError as error:
                raise ReleaseError(f"Markdown link escapes repository: {relative}: {target}") from error
            if target_relative == Path("README.md") and "#" in target:
                # The GitHub README replaces the development README and its headings.
                removed += 1
                return match.group("label")
            if (source_folder / target_relative).exists():
                return match.group(0)
            if not resolved.exists():
                raise ReleaseError(f"Broken Markdown link in source: {relative}: {target}")
            removed += 1
            return match.group("label")

        rewritten.append(MARKDOWN_FILE_LINK.sub(replace, line))
    if removed:
        path.write_text("".join(rewritten), encoding="utf-8")
    return removed


def build_release(root, output, name, *, github=False):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name):
        raise ReleaseError("Name must contain 1–100 ASCII letters, digits, dots, underscores, or hyphens.")
    root = Path(root).resolve()
    output = Path(output).absolute()
    if github:
        for required in ("README.md", GITHUB_README_TEMPLATE, GITHUB_GUIDE,
                         GITHUB_DIAGNOSIS_GUIDE, GITHUB_HUNTING_GUIDE):
            if checked_source(root, required) is None:
                raise ReleaseError(f"Required GitHub distribution file is missing: {required}")
    release = output / name
    archive = output / f"{name}.zip"
    checksum = output / f"{name}.zip.sha256"
    for path in (release, archive, checksum):
        if os.path.lexists(path):
            raise ReleaseError(f"Output already exists; choose a new name: {path}")
    included, excluded = inventory(root, github=github)
    output.mkdir(parents=True, exist_ok=True)
    published = []
    with tempfile.TemporaryDirectory(prefix=f".{name}-", dir=output) as temporary:
        staging = Path(temporary)
        source_folder = staging / name
        source_folder.mkdir()
        for relative in included:
            source = GITHUB_README_TEMPLATE if github and relative == "README.md" else relative
            copy_source(root, source, source_folder / relative)
        removed_links = 0
        if github:
            for relative in included:
                if relative.endswith(".md"):
                    removed_links += remove_excluded_markdown_links(root, source_folder, relative)
        records = [f"{sha256(source_folder / relative)}  {relative}\n" for relative in included]
        # The manifest covers every copied source file, excluding itself.
        (source_folder / MANIFEST).write_text("".join(records), encoding="utf-8")
        staged_zip = staging / archive.name
        with zipfile.ZipFile(staged_zip, "x", zipfile.ZIP_DEFLATED,
                             compresslevel=6, strict_timestamps=False) as bundle:
            for relative in sorted([*included, MANIFEST]):
                bundle.write(source_folder / relative, f"{name}/{relative}")
        staged_checksum = staging / checksum.name
        staged_checksum.write_text(f"{sha256(staged_zip)}  {archive.name}\n", encoding="utf-8")
        try:
            # Exclusive creation prevents replacing existing release artifacts.
            release.mkdir()
            published.append(release)
            for child in source_folder.iterdir():
                child.rename(release / child.name)
            os.link(staged_zip, archive)
            published.append(archive)
            os.link(staged_checksum, checksum)
            published.append(checksum)
        except Exception:
            for path in reversed(published):
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            raise
    return {
        "folder": release, "archive": archive, "checksum": checksum,
        "included": included, "excluded": excluded, "removed_links": removed_links,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Example: python3 scripts/package-release.py --name aegisloop-public-20261011-api-discovery",
    )
    parser.add_argument("--name", required=True, help="new folder and ZIP base name; never overwritten")
    parser.add_argument("--output", type=Path, default=Path.cwd() / "release-artifacts",
                        help="output directory (default: ./release-artifacts)")
    parser.add_argument("--dry-run", action="store_true", help="list included/excluded paths without writing files")
    parser.add_argument("--github", action="store_true", help="package only user-facing Markdown and use the GitHub README")
    args = parser.parse_args(argv)
    try:
        root = Path(os.fsdecode(git(Path.cwd(), "rev-parse", "--show-toplevel")).strip()).resolve()
        if args.dry_run:
            included, excluded = inventory(root, github=args.github)
            for relative in included:
                print(f"INCLUDE {relative}")
            for relative, reason in excluded:
                print(f"EXCLUDE {relative}: {reason}")
            print(f"Files: {len(included)} included, {len(excluded)} excluded")
        else:
            result = build_release(root, args.output, args.name, github=args.github)
            print(f"Files: {len(result['included'])} included, {len(result['excluded'])} excluded")
            for key in ("folder", "archive", "checksum"):
                print(f"{key.capitalize()}: {result[key]}")
            if args.github:
                print(f"Links to omitted local files converted to text: {result['removed_links']}")
            print("Review and secret-scan the release folder before publishing.")
        return 0
    except (ReleaseError, OSError, ValueError) as error:
        print(f"Release failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
