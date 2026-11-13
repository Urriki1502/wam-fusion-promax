# PM-054 / D4-A run record

Writer: Codex, Lane A, PEER-167. 2026-11-13 UTC; final metadata read at
16:39:21Z. Starting source 8c61dabb0bf5e582008975b9a0baef5873f2ac1e;
only new tests and fixture Markdown added. Runner creates the commit after exit;
commit SHA is not available to this writer. Commit message supplied in the peer
job directory. No self-approval or push. Q06 accepted=false.

Environment: exact requested interpreter
`/Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python`,
CPython 3.12.15, PySide6 6.12.0, macOS 27.0.1 ARM64. Qt platform offscreen,
PYTHONPATH=src:tests, working directory the prepared PM-054 clone. No shared slot.
No full suite, native/Cocoa, gallery, frozen build, genuine Core or verify-batch.
The required PM-032 module runs its existing temporary offscreen interaction
probe; it is not a new gallery/native run. Native appearance, glyph fit,
physical acceptance and independent review remain unqualified.

External logs resolve under
`/Users/dinhdang/Documents/WAM-Fusion-Pro-Max/evidence/PM-054-d4a-history-characterization/`.
All historical logs retained.

## Run 1 — initial harness failure retained

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python -m unittest -v test_pm054_d4a_history_state test_pm054_d4a_history_commands > /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/evidence/PM-054-d4a-history-characterization/new-tests-1.log 2>&1
```

Unittest: 13 tests in 0.914s, FAILED (errors=2, expected failures=3).
Both errors were **teardown**: the synthetic backend continued reporting
core_alive=True after quit, so the real executor correctly refused closure with
WALLET_EXECUTOR_OWNER_STILL_LIVE. Its non-daemon test threads kept the test
process alive after the failure summary. No product defect inferred.

A read-only `ps -axo pid,ppid,command | rg ...` attempt was denied by the sandbox
(`operation not permitted: ps`, exit 1); no PID action followed. The original
exec session 73646 was interrupted via its own stdin Ctrl-C and returned exit 1.
No Core/foreign process was inspected, signalled or adopted. Fixed ONLY the new
synthetic backend to report core_alive=False on quit, matching PM-051's style.

## Run 2 — complete requested targeted batch

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python -m unittest -v test_pm054_d4a_history_state test_pm054_d4a_history_commands test_pm028_history_columns test_pm032_keyboard_trap test_pm041_pending test_q05_history_helpers test_q05_history_pagination test_q06_history_paging > /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/evidence/PM-054-d4a-history-characterization/targeted-2.log 2>&1
```

**Exit 0.** 75 tests in 14.552s; **72 PASS / 3 expected failures / 0 unexpected
FAIL or ERROR / 0 SKIP**. New D4-A: 13 tests, 10 PASS / 3 expected failures.
All six requested existing modules were present, 62 tests PASS.
Expected failures D4A-1 absent-TXID stale selection/Copy, D4A-2 confirmed-only
no-match copy despite pending inclusion, D4A-3 empty/unavailable copy collision.
They are retained defects, not technical acceptance PASS. The final test code
is exactly the code executed in run 2; later edits are evidence Markdown only.

Offscreen propagateSizeHints warnings are retained. The batch has no traceback
or callback error after the correction. Overview mouse-route probes observe
zero total real `_command` calls and zero synthetic backend executions from
selection/Copy, including all named payment/lifecycle commands in the matrix.
Constructor core_status and cleanup quit are outside the measured events.

## Read-only provenance and final inventory checks

- First handoff read: absent (`cat` exit 1). Initial source inventory clean;
  branch/HEAD as above. Runner lease marker present; clone lease/PIDs UNKNOWN.
- Specs were initially attempted at clone-relative evidence paths (absent),
  then read successfully from the canonical external evidence directory.
- Issue #45, exact owner protocol comment, GitHub main and Draft #141 read
  through GitHub fetch. Exact-tip check-runs supplied no usable structured
  result; CI UNKNOWN, not PASS. No Git fetch/rebase or remote mutation.
- Ledger read using py312: Q06 remains accepted=false, 0 PASS/0 FAIL/4 PENDING/
  15 STALE/5 BLOCKED. Initial parser incorrectly treated questions as a dict
  and raised TypeError (exit 1); corrected read uses its actual list shape.
  No ledger edit. Gates unchanged: G0 PENDING, G1–G5 STALE, G6/G7 BLOCKED.
- `git merge-base HEAD 8be05163550253d76110c010d1e89d1dd6933e6d`: exit 0,
  8be05163550253d76110c010d1e89d1dd6933e6d. No configured remotes.
- `git diff --check`: exit 0. Final source/existing-test inventory and syntax
  checks recorded in external `inventory.json`; no tracked file modified.
  New repository files: two test modules, HISTORY-STATE-MATRIX.md and RUNS.md.
- No Git add/commit attempted (.git read-only). Runner owns commit creation;
  message subject: `PM-054: D4-A history state and accounting characterization`.

ENGINEERING HANDOFF NO / FULL Q ACCEPTED NO. Reviewer owns independent
verify-batch. No source, locale, acceptance ledger, gallery or dependency change.
