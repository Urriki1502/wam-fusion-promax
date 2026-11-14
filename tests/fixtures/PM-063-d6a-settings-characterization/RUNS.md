# PM-063 D6-A Run Log

- **Branch / Base:** `promax/d6a-settings-characterization` at `promax/main` (`7255fe0a5f812979d043a08c7d3bbf0874159e76`)
- **Python:** `/Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python`
- **Isolation:** `QT_QPA_PLATFORM=offscreen`, `WAM_UI_SETTINGS_PATH` per-test temporary INI (`ui_settings.native_store_enabled() == False`), synthetic in-memory backend only (no Core, no owner profiles, no native store).
- **Governance:** Q06 `accepted=false`; G6/G7/V19 `BLOCKED`. Zero `src/` or locale changes; zero owner decisions made.

## Runs Recorded

1. `QT_QPA_PLATFORM=offscreen QT_REDUCE_MOTION=0 GITHUB_ACTIONS=false PYTHONPATH=src:tests /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python -m unittest tests/test_pm063_d6a_settings_state.py tests/test_pm063_d6a_settings_commands.py -v`
   - Result: `Ran 20 tests in 1.999s — OK (expected failures=6)` — exit `0`.
2. `QT_QPA_PLATFORM=offscreen QT_REDUCE_MOTION=1 GITHUB_ACTIONS=false PYTHONPATH=src:tests /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python -m unittest tests/test_pm063_d6a_settings_state.py tests/test_pm063_d6a_settings_commands.py -v`
   - Result: `Ran 20 tests in 1.981s — OK (expected failures=6)` — exit `0`.
3. `expectedFailure` assertion verification (unwrapping `__unittest_expecting_failure__` across all 6 `D6A-1..D6A-6` tests):
   - Result: `Ran 6 tests in 0.759s — FAILED (failures=6) / XFAIL_CHECK: 6 total, 6 failures, 0 errors` — exit `0`.
4. `QT_QPA_PLATFORM=offscreen QT_REDUCE_MOTION=0 GITHUB_ACTIONS=false PYTHONPATH=src:tests /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python -m unittest tests/test_ui_settings_isolation.py tests/test_gui_error_privacy.py tests/test_pm014_lazy_locale.py tests/test_pm015_languages.py tests/test_pm017_status_languages.py tests/test_pm017_main_path_languages.py tests/test_pm020_qual_locale.py tests/test_pm025_picker_isolated.py tests/test_fusion_design.py tests/test_fusion_v21_layout.py tests/test_fusion_v2_widgets.py tests/test_ui_text_layout.py tests/test_presentation_strings.py tests/test_pm045_backup_departure.py tests/test_pm018_legacy_windows.py tests/test_macos_wallet_gui_contracts.py tests/test_pm041_pending.py tests/test_pm043_backup_copy.py tests/test_pm063_d6a_settings_state.py tests/test_pm063_d6a_settings_commands.py -v`
   - Result: `Ran 166 tests in 15.062s — OK (expected failures=6)` — exit `0`.
5. Same 20-module suite with `QT_REDUCE_MOTION=1 GITHUB_ACTIONS=false`:
   - Result: `Ran 166 tests in 14.964s — OK (expected failures=6)` — exit `0`.
6. `tests.test_characterization_r0.MotionReduced` under both `QT_REDUCE_MOTION=0` and `QT_REDUCE_MOTION=1` (`GITHUB_ACTIONS=false`):
   - Result: `Ran 1 test` each (`0.147s`, `0.160s`), `OK` — exit `0` both.
