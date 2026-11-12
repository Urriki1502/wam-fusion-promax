"""Test-runner isolation (W-TEST-01). Loaded automatically at interpreter start
because the standard test command puts tests/ on PYTHONPATH.

1. Points the wallet's UI preference store (wam_regtest.ui_settings) at a
   throwaway INI file, so no test can overwrite the owner's real preferences in
   ~/Library/Preferences/com.wam-privacy-wallet.REGTEST.plist.
2. Then runs the sitecustomize this file shadows (Homebrew's Python ships one
   that adjusts sys.path/sys.executable), so interpreter setup is unchanged.
test_ui_settings_isolation fails the suite if either step did not happen.
"""
import importlib.util
import os
import sys
import tempfile

if not os.environ.get("WAM_UI_SETTINGS_PATH"):
    os.environ["WAM_UI_SETTINGS_PATH"] = os.path.join(
        tempfile.mkdtemp(prefix="wam-test-ui-settings-"), "ui-settings.ini")

CHAINED = None
_here = os.path.dirname(os.path.abspath(__file__))
for _entry in list(sys.path):
    if not _entry or os.path.abspath(_entry) == _here:
        continue
    _candidate = os.path.join(_entry, "sitecustomize.py")
    if os.path.isfile(_candidate):
        _spec = importlib.util.spec_from_file_location("_wam_shadowed_sitecustomize", _candidate)
        _module = importlib.util.module_from_spec(_spec)
        sys.modules["_wam_shadowed_sitecustomize"] = _module
        _spec.loader.exec_module(_module)
        CHAINED = _candidate
        break
