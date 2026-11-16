# PM-054 / D4-A — History state and accounting characterization

2026-11-13; Lane A; Codex single writer. Prepared branch
`promax/d4a-history-characterization`, starting HEAD and local promax/main
`8c61dabb0bf5e582008975b9a0baef5873f2ac1e`. Initial tracked/staged/untracked
inventory empty. Tests and evidence only; no product, locale, existing-test or
image changes. Q06 accepted=false. Not implementation approval, independent
review, engineering handoff or native/frozen qualification.

`ENGINEERING_HANDOFF.md` was attempted first and is absent. Runner
`PEER-167-codex-implement-pm054-d4a/lease.txt` says ENGINEERING_LEASE_HELD;
`lease-clone.txt` is absent. Exact holder PIDs / clone lease detail are UNKNOWN;
no lease acquisition, release, Git metadata writes or process adoption attempted.
Runner retains lease ownership and creates the requested commit after exit.

Source citations below are relative to `src/wam_regtest/` at the starting HEAD.
External evidence citations are relative to
`/Users/dinhdang/Documents/WAM-Fusion-Pro-Max/evidence/`. Design inputs read:
`PM-053-d4-history-spec/D4-history-spec.md` §§2–4, 6.1, 7 D4-A and
`CLAUDE-SPEC-REVIEW.md`; harness style read-only from PM-051 clone
`tests/fixtures/PM-051-d3a-send-characterization/STATE-COMMAND-MATRIX.md` and
`tests/test_pm051_d3a_send_commands.py`. No imported acceptance credit.

## Truth and row mapping today

The same verified WalletReadSnapshot is passed to Fusion, rather than a second
scanner (`application/snapshot_projection.py:19–29,41–43`;
`bip39_fusion_gui.py:975–1005`). Confirmed fields are TXID, block height,
confirmations, owned-output credit and owned-input debit
(`wallet_read.py:29–43`). The reader builds confirmed rows from the bounded
SQLite observation (`wallet_read.py:134–165`); height/order/confirmation
consistency is checked by `history_pages.py:60–70`. This UI accepts the supplied
snapshot; synthetic display tests do not authenticate a chain.

All fixture numbers are integer atoms, 100,000,000 atoms/WAM; formatting uses
integer divmod and eight decimal places (`wallet_read.py:22–26`).

| Row / synthetic fixture | Source / available state | Credit / debit / net atoms | Rendered today |
|---|---|---|---|
| Confirmed incoming `ab` ×32 | HistoryRow; block 112, confirmations 1 | 5000 / 0 / +5000 | Received; raw 0.00005000 / 0.00000000; overview +0.00005000 WAM |
| Confirmed outgoing with owned change `cd` ×32 | HistoryRow; block 108, confirmations 5 | 6900 / 10000 / -3100 | Sent; raw 0.00006900 / 0.00010000; overview -0.00003100 WAM. Credit includes change, not income |
| Confirmed zero-net `ef` ×32 | HistoryRow; block 107, confirmations 6 | 10000 / 10000 / 0 | Activity, numeric 0.00000000 WAM in overview; no invented self-transfer classification |
| Recorded pending outgoing `12` ×32, fee 100, change None | PendingHistoryRow, state=pending; height/count 0 | 0 / 3100 / -3100 | Sent + localized pending state; block em dash, confirmation column pending text; fee 0.00000100 WAM, change localized unknown |
| Pending outgoing optional fee/change both None | Same synthetic row shape; authentic producer normally supplies a positive fee | 0 / 3100 / -3100 | Two unitless unknown values in selected detail; not two zero amounts |
| Pending incoming | Only current WSP mempool coins without spends/confirmed history, `history_pages.py:188–200` | verified unspent owned credit / 0 / positive | Pending Received if supplied. Current Fusion live incoming availability is blocked by PM-041b; this is no live detection receipt |

History direction is derived from **net = credit - debit**, not credit alone
(`fusion_pages.py:122–134`). Overview derives the identical integer net and
sign (`fusion_ui.py:1618–1649`). An outgoing 3000 payment with 100 fee has
pending debit 3100; on ordinary confirmation, owned inputs 10000 and change
6900 still net -3100. **Never subtract fee again** (-3200 would be wrong).
Pending change is separate, never credit on that outgoing pending row
(`wallet_read.py:40–43`; `history_pages.py:178–183`). The existing PM-041
producer tests in the scoped run verify the authenticated-evidence projection,
including stale mempool → unknown change and all-history confirmation suppression.

Pending source is bounded supplemental authenticated broadcast evidence selected
by broadcast reservations, matched to PSBT identity/inputs/amount/fee; confirmed
TXIDs are checked against ALL history, not just this page
(`history_pages.py:132–187`). Invalid evidence is omitted without changing
reservations. Source bounds the pending result at GUI_HISTORY_LIMIT=250
(`history_pages.py:201`). No complete pending-count claim is justified.

Confirmed fee/change decomposition is UNKNOWN and absent from HistoryRow; today's
confirmed detail shows block, confirmations, credit and debit only
(`fusion_pages.py:164`). Pending optional fields are known only as supplied.
`pending_amount_text` accepts exactly a nonnegative int, with units; None,
negative, bool, string and float become localized unitless unknown
(`fusion_ui.py:1351–1355`). Known zero is numeric `0.00000000 WAM`.

No row timestamps, recipient, uncertainty, replacement/conflict/failure timeline,
current per-row mempool-membership flag, ETA or self-transfer provenance is
established by this model. UNKNOWN is not failed, zero or released authority.
No actual lifecycle, native custody or genuine Core proof is generated here.

## Paging, search, filtering and exact identity

| Event | Current behavior / source | Characterization |
|---|---|---|
| Snapshot render | Pending rows precede confirmed rows; confirmed offset/count and shown count use only snap.history (`fusion_pages.py:100–120`) | Pending absent/present at offsets 0/250/500 produces identical confirmed scope and page requests |
| Older / Newer | Offset ± GUI_HISTORY_LIMIT, newer clamped to 0; button availability uses confirmed count (`:102–106,173–178`) | For 503 confirmed records, 3 displayed, offsets 0/250 permit older; offset 500 does not. Pending never shifts offsets |
| Search | Trim/lower substring of loaded TXID or block height only; hides rows, no global query (`:143–149`) | Uppercase pending TXID matches; absent ID triggers no page request/lookup |
| Credit / debit filters | Positive raw credit / debit predicates (`:146`) | Outgoing-with-change matches BOTH; credit filter is not an income filter |
| Overview activity | First four of pending+confirmed; exact identity in `_txids`; mouse cellClicked → `_select_tx` → transaction_selected (`fusion_ui.py:1473–1474,1534–1536,1618–1619`) | Actual mouse clicks on pending and incoming route exact IDs |
| Overview → History | Signal connected at `bip39_fusion_gui.py:498`; `_select_transaction` selects navigation index 2 and History TXID (`:668–670`) | Search cleared and filter reset to All (`fusion_pages.py:166–169`); matching loaded row selected; no RPC/page scan |
| Absent requested TXID | Clears query/filter then silently falls through; previous row/detail/Copy can remain (`:166–169`) | D4A-1 expectedFailure; absence establishes no transaction outcome |
| Row/arrow selection | itemSelectionChanged → show_details; current unhidden row selects exact data (`:74,150–165`) | Arrow Down changes incoming to outgoing detail; hiding selected row clears detail/Copy |
| Copy | Enabled selected row → clipboard exact full row.txid (`:170–172`) | All four fixtures copy exactly 64 ASCII characters; no label, spaces, ellipsis or newline. Disabled Copy leaves sentinel unchanged |
| Refresh/clear | New snapshot resets displayed detail/Copy (`:101`); None clears rows | Hidden-selection and lock-clear probes retain no actionable stale Copy |

Route command counts are **event increments**, not constructor/cleanup traffic.
The real window `_command` is wrapped, with real WalletExecutor and synthetic
recording backend, following PM-051's two-boundary harness. Both confirmed and
pending click → selection → Copy sequences yield **GUI dispatch total 0,
backend execution total 0**. Each named count is 0: prepare_auto, prepare,
mark_signed, sign, broadcast, sendrawtransaction, cancel, release_draft,
resume_intent, activate, fund, confirm, lock, unlock, quit, snapshot.
All-command totals also prevent an unnamed command escaping the list.
Backend methods not reached are not cryptographic/durable-state evidence;
setup core_status and teardown quit are excluded and explicitly separate.

## Rendering and keyboard today

| State | Actual display / limits | Source / proof |
|---|---|---|
| Fresh page before snapshot | Initial history-empty text, Copy disabled, paging disabled; no explicit History loading state | `fusion_pages.py:66–74`; initial locale text `presentation/locales/en.py:172` |
| Snapshot in progress | No History-specific busy/loading parameter or spinner. Existing rows are not cleared by command startup; History remains the previous rendered display until result/clear | `bip39_owner_gui.py:405–425`; Fusion `_set_actions` `bip39_fusion_gui.py:709–759` and History `render_snapshot` `fusion_pages.py:100`. Source characterization only; exact native paint timing UNKNOWN |
| Locked / explicit clear | `_clear_visuals` renders None into History; no rows, detail blank, Copy disabled, scope blank, paging disabled | `bip39_fusion_gui.py:1010–1021`; executable clear-boundary probe. Merely changing an executor flag is not this signal path |
| Unavailable (None) | “No verified transactions · unlock and sync the wallet”, no special History unavailable heading | `fusion_pages.py:107–108,148,152`; `presentation/locales/en.py:218` |
| Verified empty snapshot | Same message as unavailable, despite verified read; confirmed-record scope still available, pending-unverified note possible | `fusion_pages.py:100–120,148`; D4A-3 expectedFailure |
| Loaded display, no match | “No matching confirmed transactions” even with only pending rows loaded | `fusion_pages.py:148`; `presentation/locales/en.py:217`; D4A-2 expectedFailure |
| Table width 900 | Direction, TXID, credit, debit never hidden; only block/confirmation optional. Full width measured with all columns visible, then cached | `fusion_pages.py:75–98`; six-locale offscreen test at 900×630. This checks visibility, not native glyph fit, all themes or maximum-amount clipping |
| Keyboard | Tab cell cycling disabled; table/scroll accessible names; arrow selection updates detail; focus follower reveals focused descendants, guards teardown | `fusion_ui.py:637–677,685`; `fusion_pages.py:69,74`; PM-032 scoped regression module |
| Overview keyboard activation | Only cellClicked hookup is present at `fusion_ui.py:1473`; Enter/Space route behavior is not established by these probes (UNKNOWN). Future D4-D must characterize/implement the proposed contract | No keyboard activation PASS inferred from mouse test |

History rows remain fixed 48px (`fusion_pages.py:134`). The PM-053 review says
PM041-WRAP was fixed by PM-048 at under-review `68f8947`; that is an external
review lead, not proof of integration here. This checkout's
`WrappedActivityDelegate` has only sizeHint (`fusion_ui.py:1337–1348`), no
explicit WrapText paint override. D4-C must inspect PM-048 integration rather
than claim this task repaired/requalified wrapping. No new wrap/gallery evidence.

## Preservation of earlier findings

| Finding | Historical disposition, exact evidence | Preservation here |
|---|---|---|
| R-5 hidden amounts | CLOSED in reconciled FC-12/FC-13 evidence, `V0-visual-baseline/V0-RECONCILED.md:81–84`. PM-028 commits 418d0cb/1322b34; `PM-028-history-columns/INTEGRATION.md:2–17` | Four columns visible in six locales at 900; replay PM-028 measurement/resize/keyboard-detail tests. Existing `tests/test_pm028_history_columns.py:76–95` covers old D-PM028-1 confirmations/arrow debt |
| R-10 table Tab trap | CLOSED with PM-032 / FC-13; `PM-032-keyboard-trap/INTEGRATION.md:3–8,18–23`, reconciled `:83–84` | PM-032 tests retain tabKeyNavigation=false and full interaction cycle detector |
| R-11 unnamed focus | CLOSED, same PM-032 record `:9,18–23`, reconciled `:83–84` | Existing table/scroll names tested; no new locale changes |
| R-12 focus outside viewport | CLOSED, same record `:10–17,18–23`, reconciled `:82–84` | Existing focus reveal/teardown regressions and detector replayed; original REQUEST CHANGES and blocked Codex Cocoa exit 134 remain historical |

These closures are historical exact-source receipts, not new native/frozen PASS
on 8c61dab. PM-032 test invokes the existing offscreen interaction detector in a
temporary directory; no gallery image or native/Cocoa run is requested here.

## Defects retained, not repaired

| ID | Contract violation | Executable expectedFailure |
|---|---|---|
| D4A-1 | Absent exact TXID retains previous detail and enabled Copy instead of clearing selection and showing not-in-display state | `test_D4A_1_absent_txid_clears_previous_detail_and_copy` |
| D4A-2 | Pending-inclusive no-match result incorrectly says confirmed | `test_D4A_2_no_match_copy_does_not_claim_confirmed_only` |
| D4A-3 | Verified empty and unavailable collapse into identical unlock/sync copy | `test_D4A_3_verified_empty_distinguished_from_unavailable` |

Each is `@unittest.expectedFailure` in the new state module. They are known
contract FAILs, never technical acceptance PASS. The matrix also records source
limitations not promoted into speculative tests or invented failure states.

## Runs and governance boundary

Exact commands, exits, retained harness failure and environment are in RUNS.md
and the external PM-054 evidence folder. Final scoped run: 75 tests, 72 PASS,
3 expected failures, 0 unexpected FAIL/ERROR, 0 SKIP, exit 0. Of these 13 are
new D4-A tests (10 PASS, 3 expected failures); 62 existing scoped tests PASS.
Independent verify-batch is reviewer-owned and NOT RUN by this writer.
No full suite, shared slot, native/Cocoa, gallery, frozen build or genuine Core.

Read-only live governance checked: Issue #45 and exact owner comment 6379544993;
GitHub main 35553f674851282c6e107e02ba02ef2a7ac5ce64; open/unmerged Draft #141
head 8be05163550253d76110c010d1e89d1dd6933e6d, base c61e3c5be4b8519dc6c4d9eb56d124fce84cf02d.
Local merge-base with that head is 8be0516. PR body links historical candidate
b187cde CI/receipts and retains prior failures; none is exact-8c61dab proof.
Exact-tip check-runs retrieval did not return usable structured content; current
exact-tip CI is UNKNOWN. No fetch/rebase, push, dispatch or remote mutation.

Canonical `tests/acceptance/issue45.json` was read and remains unchanged:
ACTIVE ENGINEERING Q06 | 0 case-ledger PASS / 0 FAIL / 4 PENDING / 15 STALE /
5 BLOCKED | G0 PENDING; G1–G5 STALE; G6/G7 BLOCKED; V19 BLOCKED |
no new native/frozen macOS/Windows/Linux evidence | exact-main, physical,
independent security and native-language gates outstanding |
ENGINEERING HANDOFF NO | FULL Q ACCEPTED NO | Q06 accepted=false.
Next: non-writer review/verify-batch, then separately authorized D4-B work.
