# PM-051 execution receipt

Source HEAD `e0194a1383642ad0cee2a84848d0642c0a5d15b3`, branch
`promax/d3a-send-characterization`. New tests/fixtures remain untracked until
the runner creates the one requested commit. No Git add/commit/push performed.

Host: macOS 27.0.1 ARM64; Python 3.12.15; PySide6/Qt 6.12.0.
Every test command uses only:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests
/Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python
```

(The environment assignments are on the same command line as the executable.)
WSP import resolves to `/Users/dinhdang/Documents/WAM-Fusion-Pro-Max/source/wsp-upstream/src/wam_sp/`;
Git HEAD `ac55f13423620252bdbf848c7e8a280c3b84721e`, tracked source clean,
pre-existing untracked `.DS_Store` preserved. No Core binary invoked/qualified.
Native evidence-storage tests and all heavy/full runs use
`/Users/dinhdang/Documents/WAM-Peer-Tasks/bin/suite-slot` before the interpreter.

Raw logs and provenance reside in
`/Users/dinhdang/Documents/WAM-Fusion-Pro-Max/evidence/PM-051-d3a-send-characterization/`.

## Completed GUI runs

Common command: the environment and interpreter above, followed by
`-m unittest -v test_pm051_d3a_send_commands`.

| Log | Exit | Actual result |
|---|---|---|
| gui-first.log | 1 (own tool session interrupted after result) | Initial harness FAILED: 16 tests, 11 failures/16 errors. Wrong identity comparison against executor-copied immutable review, and synthetic quit incorrectly kept Core alive. Harness only corrected; product unchanged. This run is not a product defect receipt |
| gui-second.log | 0 | 16 tests; 13 ordinary PASS, 3 expected failures |
| gui-third.log | 0 | 18 tests; 14 ordinary PASS, 4 expected failures |
| gui-final.log | 0 | 22 tests; 18 ordinary PASS, 4 expected failures |
| gui-final-refined.log | 0 | Final candidate: 22 tests in 2.905s; 18 ordinary PASS, 4 expected failures. Modal probes assert visibly enabled approval, rather than assuming disconnect must close a sheet |

The final GUI inventory adds result navigation/close for pending, known-TXID
uncertain, missing-TXID uncertain, and rapid Sign activation.

Diagnostic: same environment/interpreter with an inline unittest runner removes
`__unittest_expecting_failure__` **in memory only** from all four marked tests
and runs only those tests. It requires exactly four assertion failures and zero
errors. `expected-failure-diagnostic.log` and final `expected-failure-diagnostic-refined.log`: wrapper exit 0, raw unittest result
**FAILED (failures=4)**, then `DIAGNOSTIC_EXPECTED_CONDITION: 4 contract assertion
failures, zero errors`. This checks expected-failure validity; it is not PASS of
the four contracts. The failures are the intended assertions, not setup errors.

## Pure targeted regression run

Same environment/interpreter, direct targeted pure offscreen tests (no native
custody/Core/full-suite):

```sh
-m unittest -v test_q06_bip39_fusion_gui test_presentation_action_state test_q06_pending_broadcast_recovery test_pm031_ui_interaction
```

`pure-regressions.log`: exit 0; 44 tests in 25.568s, all ordinary PASS.

## Shared-slot runs

Session command after suite-slot + interpreter:

```sh
-m unittest -v test_pm051_d3a_session_evidence
```

Focused command after suite-slot + interpreter:

```sh
-m unittest -v test_pm051_d3a_send_commands test_pm051_d3a_session_evidence test_q06_bip39_fusion_gui test_presentation_action_state test_q06_pending_broadcast_recovery test_tx03_signed_intent_recovery test_pm031_ui_interaction
```

Full offscreen command after suite-slot + interpreter:

```sh
-m unittest discover -s tests -p 'test*.py' -v
```

**VERIFICATION BLOCKED at handoff, 2026-11-13 13:41 UTC.** All three logs
still contain only `SUITE_SLOT_WAIT ...`; no test started, no command exit code
exists. No result is inferred from queueing a command. The six new session
cases and the required TX-03 regression are **NOT RUN as of handoff**. The
combined focused run and full offscreen suite are likewise **NOT RUN**. This
is shared-resource contention, not a sandbox-denial claim.

| Log | Exec session | Shared-slot process | State at handoff |
|---|---|---|---|
| session-first.log | 56545 | Python 81001 | WAIT; no exit code |
| focused-final.log | 90138 | Python 82333 | WAIT; no exit code |
| full-offscreen.log | 86587 | Python 82512 | WAIT; no exit code |

Read-only `lsof /private/tmp/wam-suite-slot.lock` also shows foreign Python
76568 (PM-049 workspace) and 80769 (PM-042 workspace). Open descriptors alone
do not prove which process owns the lock versus waits. No foreign process or
lock was changed; no slot bypass or cancellation. Original waiters remain
recorded, not replaced by duplicate attempts. Runner/reviewer must reconcile
these pending processes and collect their final exits/logs (or record their
actual termination) before restarting equivalent commands. Their lifetime
after peer exit is not promised.

Candidate inventory: **28 new tests: 18 ordinary PASS / 4 expected failures /
6 NOT RUN**. Four required pure regression modules: **44 ordinary PASS**.
No claim that the full required verification is complete. Runner commits only
after this peer exits; commit SHA is therefore **PENDING runner**, to be recorded
in the peer task's `06-commits.txt`. The requested commit message is staged as
`commit-message.txt` in that task directory, not in Git.

## Governance and scope

Read-only GitHub connector readback: canonical Issue #45, exact owner comment
6379544993, live `main` at `35553f674851282c6e107e02ba02ef2a7ac5ce64`, open Draft
#141 head `8be05163550253d76110c010d1e89d1dd6933e6d` / base `c61e3c5be4b8519dc6c4d9eb56d124fce84cf02d`.
Local merge-base with #141 head is that head. Remote main has 6 successful
check-runs; PR head has 26 successful / 2 skipped check-runs. Those historical
remote results qualify **neither this candidate nor PM-051**. Readback stored
in external `governance-readback.json`. No remote mutation/fetch/rebase.

Q06 active / accepted=false; ledger unchanged: 15 STALE / 4 PENDING / 5 BLOCKED
case records. G0 PENDING; G1–G5 STALE; G6–G7 BLOCKED. G6 physical, G7 independent,
V19 and required exact-source native/frozen/independent review remain separate.
macOS Cocoa ordering/focus/physical interaction: reviewer-owned NOT RUN.
Windows/Linux, genuine Core and final frozen packages: NOT RUN in PM-051.
ENGINEERING HANDOFF NO; FULL Q ACCEPTED NO; no push/merge/release/mainnet.
