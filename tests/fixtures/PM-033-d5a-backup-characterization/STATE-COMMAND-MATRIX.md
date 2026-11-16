# PM-033 / D5-A — backup and recovery characterization

Baseline: `promax/d5a-backup-characterization`, `e01b913136844afb1cdaf82ccd5c3fa42d793bd3`
(tree `f25b1200c7d7b835abddb8cda74364b65cbf2dc6`), matching local `promax/main`.
Tests only; no product, locale, layout, custody or acceptance changes. Prepared
by Codex for Cursor review, not independently accepted. This fallback location
keeps every repository change under `tests/`, as the PEER-100 runner requires;
no attempt to write the top-level evidence directory was needed.

## State → action → executor inventory

Counts are **per action**, excluding earlier setup commands. Commands are real
GUI-to-recording-stub dispatches, not real Core execution. `backup_verify`
receives challenge ID and three answers; `recovery_verify` receives 12 words.
The fixtures never derive a wallet or touch retained profiles. Do not log those
arguments. Production synchronous backup requests use timeout=30 seconds.

| State / action | Commands (count) | Visible/local behavior / coverage |
|---|---|---|
| Open result: required backup with folder | `acknowledge_create_pending` (1) | Grid shown, navigation disabled; confirm-count test |
| Words, checkbox unchecked / Confirm button or slot | none (0) | Disabled; slot also refuses; confirm-count test |
| Check checkbox | none (0) | Enables Confirm only |
| Checked / Confirm | `backup_challenge` (1), **no** `backup_verify` | Challenge page; confirm-count test |
| Challenge / Verify with empty answers | none (0) | Local error, no automatic retry; confirm-count test |
| Challenge / Verify with wrong answers | `backup_verify` (1), then `backup_challenge` (1) | Fresh ID, all old answers blank; wrong-word test |
| Challenge / executor verification refusal | `backup_verify` (1), then `backup_challenge` (1) | `verify_unavailable`, not `verify_error`; unavailable test |
| Words / challenge preparation refusal | `backup_challenge` (1) | Unavailable, phrase retained, no verification; challenge-unavailable test |
| Challenge / Back (Escape with phrase is the same path) | `backup_challenge_cancel` (1) | Clears inputs/ID, returns to held phrase; confirm-count + existing safety tests |
| Words / Later, Escape, close, request_quit / Stay | none (0); departure dialogs (1) each | All words retained; departure-count test |
| Words / Later or Escape / Leave | `backup_defer` (1) | Dialog (1); labels blank **before** dispatch for Later; existing safety covers Escape final state |
| Words / close or request_quit / Leave | `backup_defer` (1), owner `quit` (1) when idle | Dialog (1), words eventually blank; **clearing-before-command fails D5A-02** |
| Words / native Cmd+Q/menu | NOT EXECUTED | Native delivery skipped here; request_quit separately exercised. Cursor must supply native receipt |
| Words / mouse or keyboard sidebar navigation | none (0), dialogs (0) | Sidebar disabled: no departure; disabled-navigation test |
| Words / direct `_navigate` callback | none (0), dialogs (0), stack changes | **D5A-01**, callback lacks guard; not an enabled user route |
| Leave completed / repeated deferred signals/helper | none additional (0) | Original defer remains exactly one; departure-count test |
| Deferred reopen | `backup_challenge` (1) | Grid and held phrase cleared; no redisplay; deferred test |
| Deferred challenge / Back | `backup_challenge_cancel` (1) | Remains challenge page, no word redisplay; existing visible Back is not a phrase route |
| Deferred / Verify after cancellation | `backup_challenge` (1), no verify | Refresh only; deferred test |
| Challenge / correct Verify | `backup_verify` (1) | Clear words and answers; success, no snapshot until Continue |
| Verified / Continue | `snapshot` (1) | Existing ack test `test_successful_verification_unlocks_and_schedules_snapshot` |
| Verified / Escape, close, quit, late defer signal/helper | `backup_defer` (0) | Final acknowledgment retained; deferred/verified test + existing safety tests |
| Fusion About backup / reject consent | none (0) | Consent only; fusion-consent test |
| Fusion About backup / accept consent, cancel entry | none (0) | Opens existing owner recovery form; no automatic scan; fusion-consent test |
| Recovery / invalid submit | none (0) | Local checksum/count validation; recovery-count test |
| Recovery / Cancel | none (0) | Fields erased; recovery-count test + clipboard-ownership suite |
| Recovery / valid submit | `recovery_verify` (1) | Real ControlWorker → recording executor; clears fields; no signing/restore command |
| Recovery / same-chain result | none additional (0) | Existing owner handler renders returned count/atoms; no new recovery authority claimed |
| Welcome / restore words prompt | no recovery command from prompt | Real `getMultiLineText` reached with launch/owner boundaries stubbed; plaintext selection/copy observed, D5A-05 |

## New test inventory (method names, without `test_` prefix)

`tests/test_pm033_d5a_backup_contracts.py`:

| Method | Contract |
|---|---|
| `confirm_checkbox_challenge_verify_and_back_counts` | Pending acknowledgment, checkbox gating, no premature verification, exact challenge/cancel/verify counts |
| `wrong_word_refreshes_challenge_clears_answers_without_retry` | Wrong response => fresh ID, blank answers, one verify only |
| `challenge_unavailable_does_not_verify_or_judge_words` | Preparation refusal preserves phrase and maps to unavailable |
| `departure_stay_and_leave_dialog_and_command_counts` | Four Stay routes prompt once; Later Leave erases before one defer; late signals do not repeat |
| `disabled_navigation_cannot_depart_by_mouse_or_keyboard` | Disabled sidebar cannot dismiss phrase or dispatch |
| `navigation_callback_requires_departure_guard` | Expected failure D5A-01 |
| `window_close_clears_labels_before_defer` | Expected failure D5A-02 (close) |
| `request_quit_clears_labels_before_defer` | Expected failure D5A-02 (quit) |
| `native_cmd_q_departure` | Explicit skip: actual Cocoa/menu delivery left to Cursor native review |
| `deferred_reopen_never_redisplays_and_verified_cannot_defer` | Deferred challenge/cancel counts, no redisplay, verified completion rejects late deferral |
| `clearing_removes_words_from_widget_metadata_and_status` | No cleared word tokens in labels, titles, tooltips, accessible names/descriptions, status tips or What's This |
| `verify_unavailable_refreshes_without_reporting_wrong_answer` | Refused verification differs from wrong answer, refreshes once and clears answers |
| `fusion_backup_consent_and_recovery_cancel_send_no_command` | Real consent/entry dialogs, reject or accept+cancel issues zero commands |
| `recovery_invalid_cancel_and_valid_submit_command_counts` | Invalid/cancel zero; valid signal sends one recovery_verify via real worker and erases fields |

`tests/test_pm033_d5a_secret_export.py`:

| Method | Contract |
|---|---|
| `displayed_words_cannot_select_copy_cut_context_export_or_drag` | All 12 displayed labels resist double-click, drag, standard key export and context menu; clipboard unchanged |
| `masked_entered_words_do_not_export_by_copy_cut_or_context_menu` | All 3 challenge + 12 recovery inputs: Password mode; keys and disabled Copy/Cut menu actions do not export |
| `entered_words_have_drag_export_disabled` | All 15 fields have drag disabled; attempted mouse drag leaves clipboard unchanged |
| `challenge_words_cannot_be_selected` | Expected failure D5A-03 (challenge keyboard Select All) |
| `recovery_words_cannot_be_selected` | Expected failure D5A-03 (recovery keyboard Select All) |
| `challenge_context_menu_cannot_select_all` | Expected failure D5A-04 (challenge menu) |
| `recovery_context_menu_cannot_select_all` | Expected failure D5A-04 (recovery menu) |
| `challenge_keyboard_cut_is_blocked` | Expected failure D5A-06 (challenge Cut still deletes input) |
| `recovery_keyboard_cut_is_blocked` | Expected failure D5A-06 (recovery Cut still deletes input) |
| `primary_unchanged_after_export_attempts` | Linux PRIMARY: displayed+entered export attempts; skip on non-Linux or Qt without selection support |
| `cleared_inputs_leave_no_words_in_metadata_or_status` | Cleared fields and labels/metadata contain no fixture word tokens |
| `welcome_restore_probe_reaches_real_multiline_entry` | Passing control proves real multiline editor selected text and exported it; avoids a vacuous expected failure |
| `welcome_restore_route_uses_protected_entry` | Expected failure D5A-05 / D5-E; real restore input lacks protected entry |

## Findings retained, no repairs

| ID | Observed contract gap | Representation |
|---|---|---|
| D5A-01 | Direct `_navigate(1)` changes stack without a departure dialog. Normal sidebar is disabled; this is callback hardening, not a demonstrated enabled UI escape | 1 expectedFailure |
| D5A-02 | Close/request_quit invoke owner `_defer_active_backup` while **12 live word labels** still hold text; labels clear only after executor returns. Later-button order is correct | 2 expectedFailure |
| D5A-03 | Password `QLineEdit` accepts standard keyboard Select All; masking is not no-selection | 2 expectedFailure |
| D5A-04 | Password standard context menu permits Select All | 2 expectedFailure |
| D5A-05 | Welcome restore real `QInputDialog.getMultiLineText` uses selectable plaintext multiline entry; Copy changes clipboard. Known spec gap D5-E | 1 expectedFailure + passing observation control |
| D5A-06 | Password keyboard Cut deletes selected input even though it does not export to clipboard; strict “no Cut” contract fails | 2 expectedFailure |

No source fixes. Expected failures are visible defects, not acceptance PASS.
Copy/Cut export prevention for password fields passed; this does not imply
selection/Cut editing is blocked. Native VoiceOver/accessibility actions, OS
clipboard history, actual outbound drag MIME on native platforms and physical
behavior remain unqualified by offscreen widget probes.

## Reproduction / limits

From this clone:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests QT_QPA_PLATFORM=offscreen /Users/dinhdang/Documents/WAM-Fusion-Pro-Max/env/py312/bin/python -m unittest -v test_pm033_d5a_backup_contracts test_pm033_d5a_secret_export test_q06_bip39_backup_safety test_q06_bip39_backup_ack test_backup_words_not_selectable test_recovery_clipboard_ownership
```

Final focused result: exit 0; 92 tests in 7.057s; 80 ordinary PASS,
10 expected failures, 2 skips. Of 27 new tests: 15 ordinary PASS,
10 expected failures and 2 skips. Exact output/exit status is recorded in the PEER-100 task directory's
`focused-tests-complete.log` and `TEST-RECEIPT.md`. Earlier runs retained separately.
A diagnostic run removes expected-failure flags in memory and checks that all
10 failures are assertion failures at the intended contracts, with zero errors;
its raw output honestly says FAILED, and its wrapper exits 0 only when that
specific diagnostic condition holds. It is not a product PASS.

Full suite, genuine Core, native Cocoa .app/.dmg, Windows/Linux, PRIMARY and
physical/independent security checks NOT EXECUTED here. Cursor owns independent
full-suite/native review. No push, merge or release. No automatic Q transition.

ACTIVE Q06 | no acceptance-case changes | G0–G7 unchanged; G6/G7/V19 BLOCKED |
local source e01b913; remote main 35553f6 and open Draft #141 head 8be0516 are
different source states | native/frozen NOT EXECUTED | ENGINEERING HANDOFF NO |
FULL Q ACCEPTED NO | next: runner commit, Cursor review, Codex corrections.
