# PM-105 — shared probe keeps the failing action + raw public cause (FC-30 V1-NET diagnosis)

Branch: promax/shared-probe-diagnostics

## What FC-30 showed
REAL_REORG_FAIL_CLOSED_PASS passed, then the GUI reconciliation loop died with
SHARED_GUI_OPERATION_DENIED. Evidence (v1net-shared-public-evidence.json):
gui_denied [null, "WALLET_OPERATION_DENIED_STATE_RETAINED"] — node B (index 1)
went idle carrying the GENERIC public fallback while node A's Reconcile was
being approved. The raw cause was lost because only the generic public code was
kept.

## Change (Task 1 — diagnostics, fail-closed, public-only)
Whenever the Fusion window maps an operation failure to a public code it now
also keeps the failing action and a PUBLIC-only raw cause:
- `gui_errors.raw_cause(error)` (gui_errors.py:14) returns the exception's
  single code-shaped token when present, otherwise the exception TYPE name.
  Never str(error); message text, fake seed phrases, paths and RPC replies can
  never leak.
- ControlWorker.run (managed_gui.py:40) stamps `diagnostic_action` /
  `diagnostic_raw` on the worker before emitting the existing public code.
- The base Fusion/owner window (bip39_owner_gui.py `_command` / `_receive_denial`
  / `_finished` / `_on_denied`) persists `_last_error_action`,
  `_last_error_raw`, and the existing `_last_error_code`. Direct backup-flow
  mappings in bip39_fusion_gui.py (`backup_challenge`, `_challenge_cancel`,
  `_verify`, `_defer`) do the same.
- `shared_network_probe.record_gui_denial` (shared_network_probe.py:24) writes
  per node `{action, raw, public}` (aligned `gui_denied_nodes`) plus the active
  `wait` label (`gui_denied_wait`), on ANY GUI denial and on the
  SHARED_GUI_OPERATION_DENIED path (wait() :73 and the exception handler :295).
- q06_fix_scenarios wait_for also notes the raw cause (`gui_denied_raw`) and the
  public-whitelist keeps it when code- or token-shaped (q06_fix_scenarios.py).

## Task 2 — autonomous node-B ops during node A's reconcile, mapping analysis
The Fusion window used by the shared probe has NO auto snapshot/peer timer
(bip39_owner_gui.py:440 _poll only runs _check_quit; no _sync_timer). Node B's
window can only start work after a completed command, via _pending_action
chains (bip39_owner_gui.py:1005, bip39_fusion_gui.py:1524-1536). In the
reconcile window the realistic candidates and their public mapping:

| node-B window op (file:line) | exception/code it can raise | public code today |
|---|---|---|
| `snapshot` auto-chain (fusion:1534 owner:1005) | Q06_GUI_ANCHORED_SCANNER_REQUIRES_RECONCILIATION (backend bip39_owner_backend.py:557) | WALLET_NATIVE_CHECKPOINT_VERIFICATION_REQUIRED (gui_errors.py:41-44, specific) |
| `snapshot` | Q06_GUI_READ_ONLY_SYNC_DENIED catch-all (backend:651), Q06_GUI_CORE_TIP_CHANGED (:581), Q06_GUI_RUNTIME_PRESERVED (:678) | WALLET_OPERATION_DENIED_STATE_RETAINED (generic — no existing specific code) |
| `mine`/`prepare`/`prepare_auto` | SHARED_SINGLE_COORDINATOR_REQUIRED / SHARED_CONFIRMED_PEER_REQUIRED (SharedRegtestError, shared_regtest.py) | SHARED_* (gui_errors.py:40, specific, _MESSAGES) |
| `reconcile_reorg` (fusion:1133) | Q06_SHARED_RECONCILIATION_DENIED (backend:722), Q06_GUI_BACKUP_ACK_REQUIRED (:702) | Q06_SHARED_RECONCILIATION_DENIED specific; Q06_GUI_BACKUP_ACK_REQUIRED -> generic (no _MESSAGES entry) |
| `network_status` / `network_active` | SHARED_CONFIRMED_PEER_REQUIRED | SHARED_CONFIRMED_PEER_REQUIRED (specific) |
| `activate` (fusion:1121) | Q06_GUI_BACKUP_ACK_REQUIRED / Q06_GUI_SPEND_ACTIVATION_DENIED | generic (no specific _MESSAGES code for either) |

Conclusion: every code that already has a specific public _MESSAGES entry
(SHARED_*, WALLET_NATIVE_CHECKPOINT_VERIFICATION_REQUIRED,
Q06_SHARED_RECONCILIATION_DENIED, WALLET_CORE_UNVERIFIED) DOES map to that
specific code for these operations — none is wrongly swallowed into the generic
fallback. The generic fallback is only reached by codes that genuinely have NO
application-specific public code (READ_ONLY_SYNC_DENIED, CORE_TIP_CHANGED,
RUNTIME_PRESERVED, BACKUP_ACK_REQUIRED). Those are fail-closed verification /
consent boundaries and no existing specific code exists at all, so per the
brief ("at most map a transient that already has a specific _MESSAGES code to
that code; if you cannot prove a case is transient, leave it fatal") they stay
fatal. The probe is NOT changed to ignore errors.

## Task 3 — mapping fix
Not performed: Task 2 found no concrete mapping bug where an existing _MESSAGES
code was being masked by the generic fallback. The FC-30 generic code most
likely came from a code with no specific public entry; the correct durable fix
is the Task 1 diagnostics, so FC-31 will record the exact raw cause on a rerun
instead of losing it.

## Tests run (frozen-run targeted set; pure unit tests run directly)
PYTHONPATH=src:tests:wsp-upstream/src  env/py312/bin/python -m unittest
  tests.test_shared_regtest
  tests.test_gui_error_privacy
  tests.test_q06_fix_scenarios
  tests.test_q06_bip39_fusion_gui
  tests.test_presentation_strings
  tests.test_pm105_shared_probe_diagnostics   (new — secrets never leak)
=> 59 tests OK.
Plus touching suites: test_q02_contracts, test_q06_backend_authority_ui,
test_q06_bip39_reconciliation, test_pm090_rec_gui_truthful,
test_broadcast_rejection_state, test_pm072_dust_change, test_rec2_uncertain_resume,
test_legacy_lock_cleanup_failure (75 OK); test_q20_error_token_hardening,
test_q06_bip39_backup_ack, test_q06_bip39_backup_safety,
test_q06_bip39_native_checkpoint, test_q12_payment_controls (87 OK).
All PASS. Lead runs the full suite and repeated source-mode shared runs, then FC-31.
