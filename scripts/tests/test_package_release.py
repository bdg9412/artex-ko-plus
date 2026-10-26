"""Public-release boundaries and integrity, using disposable Git repositories."""

import hashlib
import importlib.util
from pathlib import Path
import os
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "package_release", Path(__file__).resolve().parents[1] / "package-release.py")
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


class PackageReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        self.output = self.base / "releases"
        self.git("init", "-q")
        self.write("README.md", "Public source\n", tracked=True)

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def write(self, relative, contents="test\n", *, tracked=False):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        if tracked:
            self.git("add", "-f", "--", relative)
        return path

    def build(self, name="aegisloop-test", *, github=False):
        return packager.build_release(self.root, self.output, name, github=github)

    def test_tracked_sensitive_and_runtime_files_are_excluded(self):
        excluded = [
            ".env", ".env.local", "nested/.env.production", "lab/secrets.env",
            "config.json", "nested/config.json", "jwt.key", "nested/id_rsa",
            "nested/id_ed25519", "certificate.pem", "private.key", "credentials",
            "browser.har", "browser.har.json", "logs.sqlite3", "db.dump",
            "backup.sql", "database.sql.gz", "old-release.zip", "vendor.tar.gz",
            "data/result.json", ".local-runtime/third-party/source.go",
            "release-artifacts/old/source.go", "evidence-local/raw.txt",
            "work/note.txt", "test-results/result.json", "scan-output/results.json",
            "demo-data/database", "web/node_modules/pkg/index.js", "web/.next/app.js",
            "web/out/index.html", ".aws/config", ".codex/history.json", ".agents/state",
            "dist/artex", "server/webui/dist/index.html", "artex", "artex.new",
            ".pnpm-store/cache/metadata.json", "docker-compose.local-restored.yml",
        ]
        for relative in excluded:
            self.write(relative, tracked=True)
        included = [".env.example", ".gitignore", ".dockerignore", "LICENSE",
                    "config.example.json", "db/schema.sql", "Dockerfile.local",
                    "docs/evidence/images/example.jpg"]
        for relative in included:
            self.write(relative, tracked=True)
        result = self.build()
        copied = {str(path.relative_to(result["folder"]))
                  for path in result["folder"].rglob("*") if path.is_file()}
        self.assertTrue(set(included).issubset(copied))
        self.assertFalse(set(excluded).intersection(copied))
        self.assertEqual(set(excluded), {path for path, _ in result["excluded"]})
        self.assertFalse((result["folder"] / ".git").exists())

    def test_includes_new_untracked_sources_and_current_tracked_contents(self):
        self.write(".gitignore", "ignored/\n", tracked=True)
        self.write("README.md", "Edited after staging\n")
        self.write("new/module.py", "print('new source')\n")
        self.write("ignored/private.txt", "not public\n")
        self.write("removed.py", tracked=True).unlink()
        result = self.build()
        self.assertEqual((result["folder"] / "README.md").read_text(), "Edited after staging\n")
        self.assertTrue((result["folder"] / "new/module.py").is_file())
        self.assertFalse((result["folder"] / "ignored").exists())
        self.assertFalse((result["folder"] / "removed.py").exists())

    def test_github_distribution_uses_current_guide_without_history_markdown(self):
        self.write("scripts/release-readme.md", "[진단 가이드](docs/OFFENSIVE_DIAGNOSIS_KO.md)\n")
        self.write("docs/FINDING_DEFENSE_INVESTIGATION_KO.md", "Current guide\n")
        self.write("docs/OFFENSIVE_DIAGNOSIS_KO.md", "Current diagnosis guide\n")
        self.write("docs/AUTONOMOUS_HUNTING_KO.md", "Current hunting guide\n")
        self.write("docs/RELEASE_EVIDENCE_KO.md", "Sanitized release evidence\n")
        self.write("CHANGELOG.md", "Old changes\n", tracked=True)
        self.write("docs/evidence/old-run.md", "Historical run\n", tracked=True)
        self.write("docs/evidence/images/old-run.jpg", "image\n", tracked=True)
        self.write("docs/offensive-diagnostics.md", "Old feature\n", tracked=True)
        self.write("presentation-output/private.pptx", "Private presentation\n", tracked=True)
        self.write("skills/sample/SKILL.md", "Runtime instructions\n", tracked=True)
        self.write("detections/sigma/README.ko.md", "[Old changes](../../CHANGELOG.md)\n[Old section](../../README.md#old-section)\n", tracked=True)
        result = self.build(github=True)
        folder = result["folder"]
        self.assertEqual((folder / "README.md").read_text(),
                         "[진단 가이드](docs/OFFENSIVE_DIAGNOSIS_KO.md)\n")
        self.assertEqual((folder / "docs/FINDING_DEFENSE_INVESTIGATION_KO.md").read_text(), "Current guide\n")
        self.assertEqual((folder / "docs/OFFENSIVE_DIAGNOSIS_KO.md").read_text(),
                         "Current diagnosis guide\n")
        self.assertEqual((folder / "docs/AUTONOMOUS_HUNTING_KO.md").read_text(),
                         "Current hunting guide\n")
        self.assertEqual((folder / "docs/RELEASE_EVIDENCE_KO.md").read_text(),
                         "Sanitized release evidence\n")
        self.assertTrue((folder / "skills/sample/SKILL.md").is_file())
        self.assertEqual((folder / "detections/sigma/README.ko.md").read_text(), "Old changes\nOld section\n")
        self.assertEqual(result["removed_links"], 2)
        for relative in (
            "scripts/release-readme.md", "CHANGELOG.md", "docs/evidence/old-run.md",
            "docs/evidence/images/old-run.jpg", "docs/offensive-diagnostics.md",
            "presentation-output/private.pptx",
        ):
            self.assertFalse((folder / relative).exists(), relative)

    def test_github_distribution_requires_diagnosis_guide(self):
        self.write("scripts/release-readme.md", "Release README\n")
        self.write("docs/FINDING_DEFENSE_INVESTIGATION_KO.md", "Current guide\n")
        with self.assertRaisesRegex(packager.ReleaseError,
                                    "docs/OFFENSIVE_DIAGNOSIS_KO.md"):
            self.build(github=True)
        self.assertFalse(self.output.exists())

    def test_github_distribution_requires_hunting_guide(self):
        self.write("scripts/release-readme.md", "Release README\n")
        self.write("docs/FINDING_DEFENSE_INVESTIGATION_KO.md", "Current guide\n")
        self.write("docs/OFFENSIVE_DIAGNOSIS_KO.md", "Current diagnosis guide\n")
        with self.assertRaisesRegex(packager.ReleaseError,
                                    "docs/AUTONOMOUS_HUNTING_KO.md"):
            self.build(github=True)
        self.assertFalse(self.output.exists())

    def test_rejects_symbolic_links_without_creating_release(self):
        secret = self.base / "outside.txt"
        secret.write_text("private\n")
        (self.root / "link.txt").symlink_to(secret)
        with self.assertRaisesRegex(packager.ReleaseError, "Symbolic links"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_rejects_symlink_parent_and_traversal(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "source.py").write_text("private\n")
        (self.root / "linked").symlink_to(outside, target_is_directory=True)
        for candidate in ("linked/source.py", "../outside/source.py", "/etc/passwd"):
            with self.subTest(candidate=candidate):
                with patch.object(packager, "git", return_value=candidate.encode() + b"\0"):
                    with self.assertRaises(packager.ReleaseError):
                        self.build()
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_rejects_special_files_before_opening_them(self):
        os.mkfifo(self.root / "pipe")
        with patch.object(packager, "git", return_value=b"pipe\0"):
            with self.assertRaisesRegex(packager.ReleaseError, "regular source file"):
                self.build()
        self.assertFalse(self.output.exists())

    def test_manifest_zip_checksum_and_executable_permissions(self):
        self.write("scripts/start.sh", "#!/bin/sh\nexit 0\n", tracked=True).chmod(0o755)
        self.write("docs/한국어.md", "한국어 문서\n")
        result = self.build()
        folder = result["folder"]
        records = (folder / packager.MANIFEST).read_text().splitlines()
        manifest_paths = []
        for line in records:
            digest, relative = line.split("  ", 1)
            self.assertEqual(digest, hashlib.sha256((folder / relative).read_bytes()).hexdigest())
            manifest_paths.append(relative)
        self.assertEqual(manifest_paths, result["included"])
        self.assertNotIn(packager.MANIFEST, manifest_paths)
        self.assertEqual(stat.S_IMODE((folder / "scripts/start.sh").stat().st_mode), 0o755)
        with zipfile.ZipFile(result["archive"]) as archive:
            self.assertEqual(set(archive.namelist()),
                             {f"{folder.name}/{path}" for path in [*manifest_paths, packager.MANIFEST]})
            self.assertIsNone(archive.testzip())
            self.assertEqual((archive.getinfo(f"{folder.name}/scripts/start.sh").external_attr >> 16) & 0o777,
                             0o755)
            for relative in [*manifest_paths, packager.MANIFEST]:
                self.assertEqual(archive.read(f"{folder.name}/{relative}"), (folder / relative).read_bytes())
        self.assertEqual(result["checksum"].read_text(),
                         f"{hashlib.sha256(result['archive'].read_bytes()).hexdigest()}  {result['archive'].name}\n")

    def test_existing_artifacts_are_not_overwritten_or_deleted(self):
        self.output.mkdir()
        for kind in ("folder", "zip", "checksum"):
            with self.subTest(kind=kind):
                name = "existing-" + kind
                if kind == "folder":
                    existing = self.output / name
                    existing.mkdir()
                    sentinel = existing / "keep.txt"
                else:
                    existing = self.output / (name + (".zip" if kind == "zip" else ".zip.sha256"))
                    sentinel = existing
                sentinel.write_bytes(b"keep unchanged")
                with self.assertRaisesRegex(packager.ReleaseError, "already exists"):
                    self.build(name)
                self.assertEqual(sentinel.read_bytes(), b"keep unchanged")
                expected = {name if kind == "folder" else existing.name}
                self.assertEqual({path.name for path in self.output.glob(name + "*")}, expected)

    def test_invalid_name_cannot_escape_output_directory(self):
        for name in ("../escape", "/absolute", "", "a/b", "a\\b", "name\n"):
            with self.subTest(name=name):
                with self.assertRaises(packager.ReleaseError):
                    self.build(name)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
