"""TDD tests for scripts/qualify_q20_dynamic.py (PM-098 Q20 dynamic privacy sweep)."""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "qualify_q20_dynamic.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("qualify_q20_dynamic", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# Unique synthetic test secrets (never real keys/wallets; constructed dynamically in tests).
SYNTH_WORDS = [
    "q20alpha", "q20bravo", "q20charlie", "q20delta",
    "q20echo", "q20foxtrot", "q20golf", "q20hotel",
    "q20india", "q20juliet", "q20kilo", "q20lima",
]
SYNTH_PHRASE = " ".join(SYNTH_WORDS)
SYNTH_WINDOW_3 = " ".join(SYNTH_WORDS[3:6])
SYNTH_PASSWORD = "Synth-Q20-Wallet-Passphrase#9876"


def _encoded_variants(text: str) -> dict[str, bytes]:
    raw = text.encode("utf-8")
    return {
        "plain": raw,
        "utf16_le": text.encode("utf-16-le"),
        "utf16_be": text.encode("utf-16-be"),
        "base64": base64.b64encode(raw),
        "hex": raw.hex().encode("ascii"),
    }


def _assert_no_secrets_leaked(testcase: unittest.TestCase, blob: str) -> None:
    forbidden = [SYNTH_PHRASE, SYNTH_WINDOW_3, SYNTH_PASSWORD]
    for item in forbidden:
        for enc_name, enc_bytes in _encoded_variants(item).items():
            testcase.assertNotIn(
                enc_bytes.decode("latin-1"),
                blob,
                f"Secret leaked in {enc_name} form",
            )
            if enc_name in ("plain", "base64", "hex"):
                testcase.assertNotIn(
                    enc_bytes.decode("ascii"),
                    blob,
                    f"Secret leaked in {enc_name} form",
                )


class QualifyQ20DynamicTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="test-q20-dyn-")
        self.root = Path(self._tmp.name).resolve()
        self.needles_file = self.root / "needles.txt"
        self.needles_file.write_text(
            f"{SYNTH_PHRASE}\n{SYNTH_PASSWORD}\n",
            encoding="utf-8",
        )
        self.data_dir = self.root / "data_dir"
        self.logs_dir = self.root / "Library_Logs"
        self.app_support_dir = self.root / "Library_AppSupport"
        self.prefs_dir = self.root / "Library_Preferences"
        self.tmpdir = self.root / "tmpdir"
        for d in (
            self.data_dir,
            self.logs_dir / "DiagnosticReports",
            self.app_support_dir / "WAM Fusion REGTEST" / "wallet-leases",
            self.prefs_dir,
            self.tmpdir,
        ):
            d.mkdir(parents=True, exist_ok=True)
        self.output_json = self.root / "q20-dynamic-report.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _clean_fixture_files(self):
        chain = self.data_dir / "chain"
        (chain / "regtest").mkdir(parents=True, exist_ok=True)
        (chain / "regtest" / "debug.log").write_text("2026-11-20T01:00:00Z init message\n")
        (chain / "core-output.log").write_text("wamd started cleanly\n")
        (chain / "wallet-runtime.sqlite").write_bytes(b"SQLite format 3\x00clean-bytes")
        (self.data_dir / "supervisor.failure").write_text('{"stage":"NONE","code":"NONE"}\n')
        (self.logs_dir / "DiagnosticReports" / "WAM-2026-11-20.ips").write_text('{"bug_type":"309"}\n')
        (self.logs_dir / "WAM-console.log").write_text("ui ready\n")
        (self.prefs_dir / "org.wamcoin.privacywallet.regtest.plist").write_bytes(
            plistlib.dumps({"theme": "dark", "last_profile": "/tmp/clean"}, fmt=plistlib.FMT_BINARY)
        )
        (self.prefs_dir / "com.wam-privacy-wallet.REGTEST.plist").write_bytes(
            plistlib.dumps({"fusion_appearance": 0}, fmt=plistlib.FMT_XML)
        )
        (self.tmpdir / "wam-clean-temp.txt").write_text("benign temp file\n")

    def _run_sweep(self, mod, *, clipboard=b"", ps_lines=b"", ps_rc=0, pb_rc=0, since_epoch=None):
        def fake_run(cmd, **_kwargs):
            if cmd and cmd[0] == "pbpaste":
                return subprocess.CompletedProcess(cmd, pb_rc, stdout=clipboard, stderr=b"")
            if cmd and cmd[0] == "ps":
                return subprocess.CompletedProcess(cmd, ps_rc, stdout=ps_lines, stderr=b"")
            raise AssertionError(f"Unexpected subprocess command: {cmd}")

        with mock.patch.object(mod.subprocess, "run", side_effect=fake_run):
            return mod.run_sweep(
                needles_file=self.needles_file,
                data_dir=self.data_dir,
                output_path=self.output_json,
                logs_dir=self.logs_dir,
                app_support_dir=self.app_support_dir,
                prefs_dir=self.prefs_dir,
                tmpdir=self.tmpdir,
                window_minutes=120.0,
                since_epoch=since_epoch,
            )

    def test_clean_dirs_pass_and_shell_history_skipped(self):
        mod = _load_module()
        self._clean_fixture_files()
        report, stdout_lines = self._run_sweep(mod, clipboard=b"benign clipboard", ps_lines=b"")
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["overall_pass"])
        self.assertFalse(report["matched_content_recorded"])
        for name in ("logs_crash_reports", "data_dir", "preferences", "clipboard", "processes", "temp"):
            chk = report["checks"][name]
            self.assertEqual(chk["status"], "PASS", f"{name} failed: {chk}")
            self.assertEqual(chk["matches_count"], 0)
            self.assertEqual(chk["matched_paths"], [])
        self.assertGreater(report["checks"]["data_dir"]["checked_paths_count"], 0)
        self.assertGreater(report["checks"]["logs_crash_reports"]["checked_paths_count"], 0)
        self.assertGreater(report["checks"]["preferences"]["checked_paths_count"], 0)
        self.assertGreater(report["checks"]["temp"]["checked_paths_count"], 0)
        self.assertFalse(report["checks"]["clipboard"]["contains_needle"])
        self.assertFalse(report["checks"]["processes"]["contains_needle"])
        self.assertTrue(report["checks"]["shell_history"]["status"].startswith("SKIPPED("))

        raw_json = self.output_json.read_text(encoding="utf-8")
        _assert_no_secrets_leaked(self, raw_json)
        _assert_no_secrets_leaked(self, "\n".join(stdout_lines))

    def test_single_mnemonic_word_is_not_needle_but_three_word_window_fails(self):
        mod = _load_module()
        self._clean_fixture_files()
        # Individual word alone must NOT trigger a match.
        (self.data_dir / "chain" / "regtest" / "debug.log").write_text(
            f"word mention only: {SYNTH_WORDS[0]}\n"
        )
        report, _ = self._run_sweep(mod)
        self.assertEqual(report["status"], "PASS")

        # 3-word sliding window MUST trigger a FAIL.
        leak_path = self.data_dir / "chain" / "regtest" / "debug.log"
        leak_path.write_text(f"leaked window: {SYNTH_WINDOW_3}\n")
        report, stdout_lines = self._run_sweep(mod)
        self.assertEqual(report["status"], "FAIL")
        self.assertFalse(report["overall_pass"])
        chk = report["checks"]["data_dir"]
        self.assertEqual(chk["status"], "FAIL")
        self.assertEqual(chk["matches_count"], 1)
        self.assertEqual(chk["matched_paths"], [str(leak_path)])
        _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
        _assert_no_secrets_leaked(self, "\n".join(stdout_lines))

    def test_planted_needles_in_all_encodings_fail_across_file_checks(self):
        mod = _load_module()
        variants = _encoded_variants(SYNTH_PHRASE)
        pw_variants = _encoded_variants(SYNTH_PASSWORD)

        for enc_name, payload in variants.items():
            with self.subTest(target="data_dir", encoding=enc_name):
                self._clean_fixture_files()
                leak = self.data_dir / "chain" / f"leak-{enc_name}.sqlite"
                leak.write_bytes(b"\x00\x01header" + payload + b"trailer\x00")
                report, stdout_lines = self._run_sweep(mod)
                self.assertEqual(report["status"], "FAIL")
                self.assertIn(str(leak), report["checks"]["data_dir"]["matched_paths"])
                _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
                _assert_no_secrets_leaked(self, "\n".join(stdout_lines))
                leak.unlink()

        for enc_name, payload in pw_variants.items():
            with self.subTest(target="logs_crash_reports", encoding=enc_name):
                self._clean_fixture_files()
                leak = self.logs_dir / "DiagnosticReports" / f"WAM-crash-{enc_name}.ips"
                leak.write_bytes(b'{"app":"WAM"}\n' + payload)
                report, stdout_lines = self._run_sweep(mod)
                self.assertEqual(report["status"], "FAIL")
                self.assertIn(str(leak), report["checks"]["logs_crash_reports"]["matched_paths"])
                _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
                _assert_no_secrets_leaked(self, "\n".join(stdout_lines))
                leak.unlink()

            with self.subTest(target="temp", encoding=enc_name):
                self._clean_fixture_files()
                leak = self.tmpdir / f"wam-tmp-{enc_name}.tmp"
                leak.write_bytes(b"tmp=" + payload)
                report, stdout_lines = self._run_sweep(mod)
                self.assertEqual(report["status"], "FAIL")
                self.assertIn(str(leak), report["checks"]["temp"]["matched_paths"])
                _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
                _assert_no_secrets_leaked(self, "\n".join(stdout_lines))
                leak.unlink()

    def test_preferences_binary_and_xml_plist_needle_detection(self):
        mod = _load_module()
        self._clean_fixture_files()
        # Binary plist with planted UTF-16/UTF-8 secret in value
        bplist = self.prefs_dir / "org.wamcoin.privacywallet.regtest.plist"
        bplist.write_bytes(
            plistlib.dumps({"cached_secret": SYNTH_PASSWORD}, fmt=plistlib.FMT_BINARY)
        )
        report, stdout_lines = self._run_sweep(mod)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn(str(bplist), report["checks"]["preferences"]["matched_paths"])
        _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
        _assert_no_secrets_leaked(self, "\n".join(stdout_lines))

        # XML plist with <data> bytes containing phrase
        self._clean_fixture_files()
        xplist = self.prefs_dir / "com.wam-privacy-wallet.REGTEST.plist"
        xplist.write_bytes(
            plistlib.dumps({"blob": SYNTH_PHRASE.encode("utf-8")}, fmt=plistlib.FMT_XML)
        )
        report, stdout_lines = self._run_sweep(mod)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn(str(xplist), report["checks"]["preferences"]["matched_paths"])
        _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
        _assert_no_secrets_leaked(self, "\n".join(stdout_lines))

    def test_vault_ciphertext_excluded_but_unsealed_enc_scanned(self):
        mod = _load_module()
        self._clean_fixture_files()
        seed_dir = self.data_dir / "chain" / ("bip39-12-" + "a" * 32)
        scan_dir = self.data_dir / "chain" / ("bip39-12-scan-" + "a" * 32)
        ev_dir = self.data_dir / "chain" / "q06-payment-evidence"
        q05_vault = self.data_dir / "chain" / "wallet-vault"
        for d in (seed_dir, scan_dir, ev_dir, q05_vault):
            d.mkdir(parents=True, exist_ok=True)

        # Genuine WAMSP02\x00 >=52 byte ciphertext files are excluded even if bytes happen to match.
        sealed_header = b"WAMSP02\x00" + b"\x11" * 44
        (seed_dir / "seed-000000001.enc").write_bytes(sealed_header + SYNTH_PHRASE.encode("utf-8"))
        (scan_dir / "snapshot-000000001.enc").write_bytes(sealed_header + SYNTH_PASSWORD.encode("utf-8"))
        (ev_dir / "tok1-signed.enc").write_bytes(sealed_header + SYNTH_WINDOW_3.encode("utf-8"))
        (q05_vault / "snapshot-000000001.enc").write_bytes(sealed_header + SYNTH_PHRASE.encode("utf-8"))

        report, _ = self._run_sweep(mod)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["checks"]["data_dir"]["matches_count"], 0)

        # Unsealed .enc file WITHOUT WAMSP02\x00 header MUST NOT be excluded!
        unsealed = seed_dir / "unsealed-leak.enc"
        unsealed.write_text(f'{{"phrase":"{SYNTH_PHRASE}"}}', encoding="utf-8")
        report, _ = self._run_sweep(mod)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn(str(unsealed), report["checks"]["data_dir"]["matched_paths"])

    def test_clipboard_and_process_checks_true_false_only_and_skip_on_ps_denied(self):
        mod = _load_module()
        self._clean_fixture_files()

        # Clipboard leak (hex-encoded password)
        report, stdout_lines = self._run_sweep(
            mod,
            clipboard=SYNTH_PASSWORD.encode("utf-8").hex().encode("ascii"),
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(report["checks"]["clipboard"]["contains_needle"])
        self.assertEqual(report["checks"]["clipboard"]["matches_count"], 1)
        self.assertEqual(report["checks"]["clipboard"]["matched_paths"], [])
        _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
        _assert_no_secrets_leaked(self, "\n".join(stdout_lines))

        # Clean wamd process + unrelated process -> PASS, checked_paths_count=1
        clean_ps = (
            b"1001 /usr/bin/python3 unrelated.py\n"
            b"1002 /Applications/WAM Privacy Wallet REGTEST.app/Contents/MacOS/wamd -datadir=/tmp/x -daemon=0\n"
        )
        report, _ = self._run_sweep(mod, ps_lines=clean_ps)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["checks"]["processes"]["checked_paths_count"], 1)
        self.assertFalse(report["checks"]["processes"]["contains_needle"])

        # Process argv/env leak in wamd / app
        ps_out = (
            f"1001 /usr/bin/python3 unrelated.py\n"
            f"1002 /Applications/WAM Privacy Wallet REGTEST.app/Contents/MacOS/wamd -datadir=/tmp/x SECRET={SYNTH_PASSWORD}\n"
        ).encode("utf-8")
        report, stdout_lines = self._run_sweep(mod, ps_lines=ps_out)
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(report["checks"]["processes"]["contains_needle"])
        self.assertEqual(report["checks"]["processes"]["checked_paths_count"], 1)
        self.assertEqual(report["checks"]["processes"]["matches_count"], 1)
        self.assertEqual(report["checks"]["processes"]["matched_paths"], [])
        _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
        _assert_no_secrets_leaked(self, "\n".join(stdout_lines))

        # ps permission denied & pbpaste failure -> SKIPPED(reason), overall still PASS if others clean
        report, _ = self._run_sweep(mod, ps_lines=b"", ps_rc=1, pb_rc=1)
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["checks"]["processes"]["status"].startswith("SKIPPED("))
        self.assertTrue(report["checks"]["clipboard"]["status"].startswith("SKIPPED("))

    def test_app_support_lease_dir_chunk_boundary_and_symlink_safety(self):
        mod = _load_module()
        self._clean_fixture_files()

        # Symlink pointing outside data_dir must not be followed.
        outside = self.root / "outside-secret.txt"
        outside.write_text(SYNTH_PASSWORD, encoding="utf-8")
        symlink_in_data = self.data_dir / "chain" / "link.txt"
        symlink_in_data.symlink_to(outside)
        report, _ = self._run_sweep(mod)
        self.assertEqual(report["status"], "PASS")

        # Chunk-boundary straddle inside WAM Fusion REGTEST/wallet-leases
        lease_leak = self.app_support_dir / "WAM Fusion REGTEST" / "wallet-leases" / "lease.log"
        lease_leak.write_bytes(b"A" * 20 + SYNTH_PASSWORD.encode("utf-8") + b"B" * 20)
        with mock.patch.object(mod, "CHUNK_BYTES", 32):
            report, stdout_lines = self._run_sweep(mod)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn(str(lease_leak), report["checks"]["logs_crash_reports"]["matched_paths"])
        _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
        _assert_no_secrets_leaked(self, "\n".join(stdout_lines))

    def test_run_window_filters_old_logs_and_temp_files(self):
        mod = _load_module()
        self._clean_fixture_files()
        old_log = self.logs_dir / "DiagnosticReports" / "WAM-old.ips"
        old_tmp = self.tmpdir / "wam-old.tmp"
        old_log.write_text(SYNTH_PASSWORD)
        old_tmp.write_text(SYNTH_PHRASE)
        old_time = time.time() - (4 * 3600)
        os.utime(old_log, (old_time, old_time))
        os.utime(old_tmp, (old_time, old_time))

        report, _ = self._run_sweep(mod)
        self.assertEqual(report["status"], "PASS")

    def test_empty_needles_file_fails_closed(self):
        mod = _load_module()
        self.needles_file.write_text("\n   \n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self._run_sweep(mod)

    def test_cli_end_to_end_never_echoes_needles_and_writes_0600_json(self):
        self._clean_fixture_files()
        cmd_base = [
            sys.executable,
            str(SCRIPT_PATH),
            "--needles-file", str(self.needles_file),
            "--data-dir", str(self.data_dir),
            "--output", str(self.output_json),
            "--logs-dir", str(self.logs_dir),
            "--app-support-dir", str(self.app_support_dir),
            "--prefs-dir", str(self.prefs_dir),
            "--tmpdir", str(self.tmpdir),
        ]
        clean_res = subprocess.run(cmd_base, capture_output=True, text=True, check=False)
        self.assertEqual(clean_res.returncode, 0, clean_res.stdout + clean_res.stderr)
        self.assertIn("Q20_DYNAMIC_SWEEP_PASS", clean_res.stdout)
        _assert_no_secrets_leaked(self, clean_res.stdout)
        _assert_no_secrets_leaked(self, clean_res.stderr)
        _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(self.output_json.stat().st_mode), 0o600)

        # Now plant a needle in data-dir and verify CLI exits 1 without echoing any needle.
        (self.data_dir / "chain" / "core-output.log").write_text(
            f"oops {base64.b64encode(SYNTH_PHRASE.encode('utf-8')).decode('ascii')}\n"
        )
        dirty_res = subprocess.run(cmd_base, capture_output=True, text=True, check=False)
        self.assertEqual(dirty_res.returncode, 1, dirty_res.stdout + dirty_res.stderr)
        self.assertIn("Q20_DYNAMIC_SWEEP_FAIL", dirty_res.stdout)
        _assert_no_secrets_leaked(self, dirty_res.stdout)
        _assert_no_secrets_leaked(self, dirty_res.stderr)
        _assert_no_secrets_leaked(self, self.output_json.read_text(encoding="utf-8"))
        data = json.loads(self.output_json.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "FAIL")
        self.assertEqual(
            data["checks"]["data_dir"]["matched_paths"],
            [str(self.data_dir / "chain" / "core-output.log")],
        )


if __name__ == "__main__":
    unittest.main()
