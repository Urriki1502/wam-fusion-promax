"""Test-runner isolation (W-TEST-01). Loaded automatically at interpreter start
because the standard test command puts tests/ on PYTHONPATH.

Points the wallet's UI preference store (wam_regtest.ui_settings) at a
throwaway INI file, so no test can overwrite the owner's real preferences in
~/Library/Preferences/com.wam-privacy-wallet.REGTEST.plist.
test_ui_settings_isolation fails the suite if this did not happen.
"""
import os
import tempfile

if not os.environ.get("WAM_UI_SETTINGS_PATH"):
    os.environ["WAM_UI_SETTINGS_PATH"] = os.path.join(
        tempfile.mkdtemp(prefix="wam-test-ui-settings-"), "ui-settings.ini")
