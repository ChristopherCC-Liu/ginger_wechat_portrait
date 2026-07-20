import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_TRACKED_PARTS = {
    "personal_agent_state",
    "decrypted",
    "outputs",
    "runtime",
    "wechat_analysis_output",
}
FORBIDDEN_SUFFIXES = {
    ".db",
    ".db-shm",
    ".db-wal",
    ".key",
    ".pem",
    ".sqlite",
    ".sqlite3",
}


def _candidate_files():
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    return [Path(item.decode("utf-8")) for item in result.stdout.split(b"\0") if item]


class PublishPrivacyTests(unittest.TestCase):
    def test_tracked_tree_has_no_runtime_or_database_artifacts(self):
        violations = []
        for path in _candidate_files():
            absolute = ROOT / path
            if FORBIDDEN_TRACKED_PARTS.intersection(path.parts):
                violations.append(str(path))
            if path.name in {"all_keys.json", "wechat_keys.json", "config.toml"}:
                violations.append(str(path))
            if any(str(path).endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
                violations.append(str(path))
            if path.name.startswith("export_") and path.suffix in {".csv", ".json"}:
                violations.append(str(path))
            if absolute.is_symlink():
                violations.append(f"symlink:{path}")
            if absolute.is_file() and absolute.stat().st_size > 5 * 1024 * 1024:
                violations.append(f"large:{path}")
        self.assertEqual(violations, [])

    def test_candidate_release_tree_passes_path_and_content_allowlist(self):
        result = subprocess.run(
            ["python3", "scripts/check-release-tree.py", "--candidate-tree"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_example_config_contains_refs_not_credentials(self):
        text = (ROOT / "config.example.toml").read_text(encoding="utf-8")
        self.assertIn('mode = "shadow"', text)
        self.assertIn("api_key_ref", text)
        self.assertNotIn("api_key =", text)
        self.assertIn("real_send_enabled = false", text)
        self.assertIn("typing_only = true", text)
        self.assertIn("auto_activate_safe = true", text)

    def test_installer_is_checksum_locked_and_never_pulls_main(self):
        installer = (ROOT / "scripts/install-release.sh").read_text(encoding="utf-8")
        local_installer = (ROOT / "install-macos.sh").read_text(encoding="utf-8")
        builder = (ROOT / "scripts/build-release.sh").read_text(encoding="utf-8")
        self.assertIn("shasum -a 256 -c", installer)
        self.assertIn("release archive contains an unsafe path", installer)
        self.assertIn("release archive contains a link or special file", installer)
        self.assertIn("check-release-tree.py", builder)
        self.assertIn("--require-hashes", local_installer)
        self.assertIn('VENV_ROOT="$APP_ROOT/venvs"', local_installer)
        self.assertIn("refusing symbolic-link install path", local_installer)
        self.assertNotIn("git pull", installer + local_installer)

    def test_fixture_directory_contains_no_wechat_identifier(self):
        fixture_root = ROOT / "tests/fixtures"
        if not fixture_root.exists():
            return
        for path in fixture_root.rglob("*"):
            if path.is_file():
                self.assertNotIn("wxid_", path.read_text(encoding="utf-8"), str(path))


if __name__ == "__main__":
    unittest.main()
