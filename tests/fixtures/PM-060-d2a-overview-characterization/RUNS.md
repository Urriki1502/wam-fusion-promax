# PM-060 execution receipt

Source HEAD `6e2558a7b00581b0f4caaa0ae09fea9e4408d8b2`, branch
`promax/d2a-overview-characterization`. Tests and fixtures only; runner-owned
lease, no Git add/commit/push by Codex. Runner commit subject:
`PM-060: D2-A overview, balance and Receive characterization`.

Host macOS 27.0.1 ARM64; Python 3.12.15, PySide6/Qt 6.12.0; Qt **offscreen**,
DPR 1.0. Fresh per-process isolated INI settings, native store disabled;
provenance and actual temporary settings destination printed in each final log.
No production entrypoint, owner preferences, wallet profile or secret access.
No Core binary invoked; WSP public deterministic address fixture only.

Raw logs and executable selection/diagnostic runner are in
`/Users/dinhdang/Documents/WAM-Fusion-Pro-Max/evidence/PM-060-d2a-overview-characterization/`.
The runner is `run-targeted.py`; its SHA-256 is in `artifact-hashes.json`.
It loads ALL tests (including inherited NativeRowShape) from both new modules,
`test_presentation_action_state`, `test_pm041_pending`, `test_pm032_keyboard_trap`,
then AST-selects existing test method names containing `overview` or `receive`.
Exact resolved unittest IDs are printed in each log under `SELECTED_IDS`.
`selected-existing-tests.txt` is the initial AST inventory (45 explicit methods),
not the complete inherited-test inventory; final log IDs are authoritative.
Tests whose names mention frozen/platform qualification inspect source contracts
only; they do not launch a build or qualify another OS. PM-041 evidence-store
probe uses temporary synthetic encrypted evidence/SQLite, not native custody.
All these are targeted offscreen unit tests: **no slot**, per PM-060 brief.
No full suite, Cocoa/native, frozen or genuine-Core command was run.

## Exact final commands and outcomes

Executed from the task workspace. The sole interpreter is the required py312.

```sh
QT_QPA_PLATFORM=offscreen QT_REDUCE_MOTION=0 GITHUB_ACTIONS=false PYTHONPATH=src:tests /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/evidence/PM-060-d2a-overview-characterization/run-targeted.py
QT_QPA_PLATFORM=offscreen QT_REDUCE_MOTION=1 GITHUB_ACTIONS=false PYTHONPATH=src:tests /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/evidence/PM-060-d2a-overview-characterization/run-targeted.py
```

| Log | Exit | Exact outcome |
|---|---|---|
| motion-enabled-final2.log | 0 | 75 tests / 64 ordinary PASS / 11 expected failures / 0 errors / 0 skips / 0 unexpected successes; 12.853s |
| reduced-motion-final.log | 0 | 75 tests / 64 ordinary PASS / 11 expected failures / 0 errors / 0 skips / 0 unexpected successes; 12.209s |

Motion function explicitly asserted False/True respectively before tests;
GITHUB_ACTIONS=false avoids implicit reduced motion. Raw R-7 rectangles for
initial and bottom positions are printed as `PM060_R7` in both logs.
75 includes 22 new PM-060 tests and 53 existing regressions. Eleven expected
failures span seven **unfixed** D2A defect IDs in OVERVIEW-STATE-MATRIX.md.
No contract acceptance or independent approval follows from wrapper exit 0.

Diagnostic commands are the same two commands with `--diagnostic` appended:

| Log | Wrapper exit | Raw unittest result |
|---|---|---|
| diagnostic-motion.log | 0 | 11 tests; FAILED (failures=11), zero errors |
| diagnostic-reduced.log | 0 | 11 tests; FAILED (failures=11), zero errors |

Diagnostic removes expectedFailure flags in memory ONLY, executes the eleven
new defect tests, requires one assertion failure per test, zero errors and
`AssertionError` plus D2A ID in every traceback. Both print
`DIAGNOSTIC: 11 intended contract assertions; zero errors`. These are successful
defect reproduction checks, **not PASS of the eleven contracts**.

## Retained earlier attempts and errors

- `first.log`: direct `-m unittest -v test_pm060_d2a_overview_state test_pm060_d2a_overview_commands`
  with QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests and required py312.
  17 tests; 1 failure, 9 expected failures. Harness targeted hidden compatibility
  manual_sync instead of visible header sync. Backend emitted one snapshot,
  while six attempted GUI dispatcher calls violated the harness assertion.
  Product unchanged. Shell group ended in `tail`, exit 0; individual unittest
  exit was not captured, raw FAILED retained (not invented PASS).
- `second.log`: same direct command after targeting header sync; 17 tests,
  OK (expected failures=9). Subsequent shell capture used zsh read-only variable
  `status`, producing group exit **1** before tail. Individual unittest exit
  was not captured; the raw OK summary is retained, not used as final evidence.
- `motion-enabled.log`: first combined selection, 73 tests in 13.157s;
  exit 0, 10 expected failures. Additional final probes followed.
- `motion-enabled-final.log`: expanded classifier card integration incorrectly
  omitted positional snap for absent-snapshot cases; exit **1**, 75 tests,
  16 errors, 11 expected failures. Harness fixed by explicit default snap=None;
  product unchanged. Corrected final run is motion-enabled-final2.log above.
- Initial `cat ENGINEERING_HANDOFF.md` exit **1** (absent); guessed clone
  evidence glob absent; guessed bip39_trial_gui.py/bip39_gui.py and gallery
  locations absent. Actual paths located with rg and read. `lease-clone.txt`
  and pre-run `06-commits.txt` absent; no fabricated holder/commit SHA.
  Read groups ending with a later successful command do not make individual
  missing-path errors successes. No artifact or historical failure removed.

## Governance / qualification limits

Read-only GitHub connector: canonical Issue #45 and exact owner v2 comment
6379544993, live main, Draft #141, head check-runs. Main is
`35553f674851282c6e107e02ba02ef2a7ac5ce64`, distinct from local promax/main.
Draft #141 remains open/unmerged at `8be05163550253d76110c010d1e89d1dd6933e6d`,
base `c61e3c5be4b8519dc6c4d9eb56d124fce84cf02d`; local merge-base equals that
head. 28 retrieved head checks: 26 success, 2 skipped. These historical PR
checks are **not exact-6e2558a or merged-main qualification**. No remote mutation.
No new main-based PR or governance transition is part of PM-060.

ACTIVE ENGINEERING Q Q06 | canonical ledger unchanged: technical
0 PASS / 0 FAIL / 4 PENDING / 15 STALE, 5 external BLOCKED |
G0 PENDING; G1–G5 STALE; G6/G7 BLOCKED; V19 unresolved |
PR #141 unmerged; local source 6e2558a; live main 35553f6 |
new native/frozen Mac/Win/Linux NOT RUN |
physical operators MACOS_OWNER / WINDOWS_11_OWNER / LINUX_PHYSICAL_OPERATOR,
INDEPENDENT_SECURITY_REVIEWER and REPOSITORY_OWNER retain their named gates |
ENGINEERING HANDOFF NO | FULL Q ACCEPTED NO | Q06 accepted=false |
next: independent PM-060 characterization review, then separately authorized
D2 presentation/Receive work. No self-approval, release or mainnet permission.

Final verification (required py312 inline checker), **exit 0**: each of
`git diff --exit-code`, `git diff --cached --exit-code`, `git diff --check`,
`git rev-parse HEAD`, `git status --porcelain=v1 --untracked-files=all` exited 0.
Exactly four untracked intended files, no tracked/staged edits, HEAD unchanged.
Parsed both final RESULT records and both diagnostic sentinels, AST-parsed new
tests, verified evidence hashes and runner commit-message subject/trailer.
Runner commit remains pending; no commit hash is invented. This final receipt
addition is documentation only; hashes refreshed after it.
