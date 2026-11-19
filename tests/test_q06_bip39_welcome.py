"""Normal WAM Fusion V1 entry: one welcome, Q06 default, no legacy route.

This source test does NOT claim physical Core or end-to-end human acceptance.
The exact bundled executable must also exercise the native dialog and wallet.
"""
import importlib.util
import inspect
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest

if sys.platform == "linux" and not os.environ.get("DISPLAY"):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from wam_regtest.managed_onboarding import (
    selected_profile, wallet_route, launch,
)


_RETIRED_WELCOME_KEYS = (
    "welcome.legacy_wallet_compatibility",
    "welcome.show_legacy_q05_wallet_options",
    "welcome.legacy_notice",
    "welcome.open_legacy_wallet",
    "welcome.create_legacy_test_wallet",
)


class UnifiedWelcomeContracts(unittest.TestCase):
    def test_retired_welcome_copy_is_absent_from_every_catalog(self):
        from wam_regtest.presentation.strings import CATALOG
        self.assertGreaterEqual(len(CATALOG), 6)
        for language, entries in CATALOG.items():
            for key in _RETIRED_WELCOME_KEYS:
                self.assertNotIn(key, entries, language)

    def test_primary_actions_all_route_to_q06_owned_bip39(self):
        self.assertEqual(wallet_route("create"), (True, "create", True))
        self.assertEqual(wallet_route("open"), (True, "reopen", False))
        self.assertEqual(wallet_route("restore"), (True, "restore", True))
        for choice in ("legacy_open", "legacy_create"):
            with self.subTest(choice=choice):
                with self.assertRaises(ValueError) as caught:
                    wallet_route(choice)
                self.assertEqual(caught.exception.args, ("LEGACY_Q05_RETIRED",))
        for choice in (None, "", "q05", "q06", "import_seed", 7, True):
            with self.subTest(choice=choice):
                with self.assertRaisesRegex(
                        ValueError, "WAM_FUSION_WELCOME_CHOICE_DENIED"):
                    wallet_route(choice)

    def test_no_wallet_creation_or_implicit_migration_on_selection(self):
        with tempfile.TemporaryDirectory(prefix="wam-onboarding-contract-") as temp:
            parent = Path(temp).resolve()
            new = selected_profile(parent, True)
            self.assertRegex(new.name, r"^wam-fusion-core-[0-9a-f]{16}$")
            self.assertEqual(new.parent, parent)
            self.assertFalse(new.exists())
            with self.assertRaisesRegex(
                    ValueError, "MANAGED_PROFILE_SELECTION_DENIED"):
                selected_profile(parent, False)
            previous = parent / ("wam-fusion-core-" + "a"*16)
            previous.mkdir()
            with self.assertRaisesRegex(
                    ValueError, "MANAGED_PROFILE_SELECTION_DENIED"):
                selected_profile(previous, False)
            (previous / "supervisor.profile").write_text(
                "DISPOSABLE STRUCTURE TEST", encoding="utf-8")
            self.assertEqual(selected_profile(previous, False), previous)

    def test_normal_frozen_app_route_no_phase_picker(self):
        code = inspect.getsource(launch)
        self.assertIn("welcome_dialog()", code)
        self.assertIn("wallet_route(choice)", code)
        self.assertIn("launch_bip39_trial(", code)
        self.assertNotIn("launch_managed(", code)
        self.assertNotIn("QInputDialog.getItem(", code)
        self.assertNotIn("Choose wallet engine", code)

    @unittest.skipUnless(importlib.util.find_spec("PySide6") is not None,
                         "Live Qt widgets tested on native Qt-capable runners")
    def test_real_qt_buttons_default_bip39_and_hide_legacy(self):
        from PySide6.QtWidgets import QApplication, QWidget
        from wam_regtest.managed_onboarding import (
            assert_unified_welcome_qt, welcome_dialog)
        app = QApplication.instance() or QApplication([])
        assert_unified_welcome_qt()
        dialog = welcome_dialog()
        try:
            self.assertEqual(dialog.selection, None)
            self.assertFalse(hasattr(dialog, "legacy_toggle"))
            self.assertFalse(hasattr(dialog, "legacy_panel"))
            self.assertIsNone(dialog.findChild(QWidget, "FusionAdvanced"))
            self.assertEqual(tuple(dialog.buttons), ("create", "open", "restore"))
            chain = []
            widget = dialog.buttons["create"]
            seen = set()
            while widget is not None and widget not in seen and len(chain) < 40:
                seen.add(widget)
                chain.append(widget)
                widget = widget.nextInFocusChain()
            positions = [chain.index(dialog.buttons[key]) for key in ("create", "open", "restore")]
            self.assertEqual(positions, sorted(positions))
            self.assertIn("12 words", dialog.buttons["restore"].text())
            self.assertTrue(dialog.buttons["create"].isEnabled())
        finally:
            dialog.deleteLater()
            app.processEvents()


if __name__ == "__main__":
    unittest.main()
