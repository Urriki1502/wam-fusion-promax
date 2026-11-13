# PM-051 / D3-A — actual Send state and command characterization

Source: `promax/d3a-send-characterization`, clean starting HEAD
`e0194a1383642ad0cee2a84848d0642c0a5d15b3` = local `promax/main`.
Date: 2026-11-13. Lane A, Codex single writer. Tests/evidence only;
no product, locale, existing-test or image changes. This is characterization,
not D3-B..F implementation or independent approval. Q06 accepted=false.

The design's line numbers describe older e01b913; **all source citations below
refer to this checkout**, relative to `src/wam_regtest/` unless specified.
There is no `ENGINEERING_HANDOFF.md` in this prepared clone. Runner reports
`ENGINEERING_LEASE_HELD` in the peer job's `lease.txt`; no second lease acquired
and no Git metadata writes attempted. The prompt names `lease-clone.txt`, but
that file is absent: its PID/clone lease detail is UNKNOWN, not independently
attested here. Initial tracked/staged/untracked inventory was empty.

## Counting rules and control definitions

Each tuple is the **increment caused by the event in that row**, in order:
`(prepare, mark_signed, sign, sendrawtransaction, release_draft, resume_intent)`.
`prepare` means one **backend prepare_auto command**, not the internal fee
proposal loop or the explicit-fee test helper. `sign` counts one session Signer
invocation, not one signature per input. Cancel dispatch is named separately
because the required tuple counts its resulting release, not its GUI command.
A tuple for modal cancellation is additional to the earlier prepare tuple;
do not sum the preparation a second time. Source describes success paths;
negative/fault cases below explicitly qualify those counts.

The normal form has **recipient and amount only, no fee field**
(`bip39_fusion_gui.py:259–268`, `wallet_session.py:439–450`). Fee is automatic.
The design §2's old explicit-fee description is historical. Enabled input
editors do not grant spending authority. The editors are not disabled by
`_set_actions` (`bip39_fusion_gui.py:699–755`); a modal blocks ordinary interaction.
No main-window default button is explicitly installed by this Send flow;
native focus/default routing outside dialogs is UNKNOWN. Both decision sheets
explicitly set **Cancel default**, approve auto-default false
(`fusion_pages.py:312–319`); offscreen Return/Escape/close probes below test it.
Native Cocoa focus/button order remains reviewer-owned, NOT RUN here.

Enabled control sets below assume ready, sending enabled, healthy unlocked
executor, verified live Core, no reauthentication, idle, isolated REGTEST,
funding already done, no recovered unsigned draft or resumable intent:

- **E**: Sync, Review payment (`send`), recovery, inspect, signed-intent inspection
  (`intents`), Lock, Quit. Broadcast/Cancel/Confirm/Resume/Activate/Fund/Unlock off.
- **R**: Sync, Cancel unsigned draft, recovery, inspect, Lock, Quit. Review payment,
  Broadcast, Confirm, intents, Resume, Activate/Fund/Unlock off.
- **S**: Sync, Broadcast, recovery, inspect, Lock, Quit. Review payment, Cancel,
  Confirm, intents, Resume, Activate/Fund/Unlock off.
- **P**: Sync, Review payment, Confirm, inspect, Lock, Quit. Broadcast, Cancel,
  recovery, intents, Resume, Activate/Fund/Unlock off. **Today's Review predicate
  does not exclude pending_confirm**; this is recorded, not a new permission.
- **BUSY**: all `BASE_CONTROLS` off (with a healthy running, nonclosed executor).
- **LOCKED** after lock result: Unlock, Quit; payment/recovery/inspect/intent
  controls off; form editors still enabled, stale modal approval may remain enabled.

These sets are directly derived from `presentation/action_state.py:48–101` and
`bip39_owner_gui.py:376–425`. For any different state use those exact predicates:
`spend = !faulted && !locked && !reauth && core_alive is True && spend_enabled &&
!busy && !quit_requested`. Shared disconnected masks Fund/Confirm/Review/Broadcast
only (`action_state.py:75–85`), not Cancel/recovery/inspect/intent controls.
Resume requires idle payment and an explicitly selected resumable intent; it
is an Advanced consent route, never implicit (`bip39_owner_gui.py:550–563`).
Navigation is ordinarily enabled; modal/window shutdown still obey owner rules.

## State / event matrix

| Actual state / event | Enabled controls / default | Command increment, exact source | Durable evidence / limits |
|---|---|---|---|
| Input empty; click Review | E, editors enabled; no installed Send default | `(0,0,0,0,0,0)`; parse fails before dispatch `bip39_fusion_gui.py:921–935` | None; input retained. Review stays enabled: D3A-3 |
| Input partial (recipient only or amount only); click Review | E; same default | `(0,0,0,0,0,0)`; same lines | None, invalid-payment status |
| Input invalid amount or wrong-prefix address; click Review | E; same default | `(0,0,0,0,0,0)`; same lines | None. Prefix/length is not full address validation; backend must validate |
| Input valid; click Review | E → BUSY; editors still enabled | `(1,0,0,0,UNKNOWN,0)`; GUI `:921–935`, session `wallet_session.py:489–617` | One accepted draft checkpoint before review; auto-quote can release intermediate **unsaved/unreviewed** drafts. Exact internal release count is quote/coin-dependent, UNKNOWN for arbitrary valid input; not cancellation of an approved/signed payment |
| Prepare busy; rapid repeated Review | BUSY; editors enabled | Additional `(0,0,0,0,0,0)`; `_command` guard `bip39_owner_gui.py:402–425` | No extra draft command; existing operation keeps ownership |
| Review / Sign sheet open; no decision | R underneath, sheet Cancel + Approve Sign; Cancel default | `(0,0,0,0,0,0)` after the one prepare; `bip39_fusion_gui.py:1040–1078` | Prepared draft already saved. Opening nonblocking sheet `:907–919` adds no signature |
| Sign declined: Cancel | R → E; Cancel default | `(0,0,0,0,1,0)` on healthy active-draft cancellation; **one cancel command** `bip39_fusion_gui.py:1054–1074`, `wallet_session.py:765–773` | Draft rows deleted and checkpoint saved; no signed evidence |
| Sign declined: default Return | Same as Cancel | Same `(0,0,0,0,1,0)` | Same; Return emits zero Sign/submission |
| Sign declined: Escape | Same as Cancel | Same `(0,0,0,0,1,0)` | Same |
| Sign declined: title-bar close | Same as Cancel | Same `(0,0,0,0,1,0)` | Same |
| Sign approved, exact commitment | R → BUSY → S | `(0,1,1,0,0,0)` on success; `wallet_session.py:661–694`, Q06 wrapper `bip39_spend_session.py:161–164` | `mark_signed` then anchored save **before crypto**; create-only encrypted `signed` evidence after crypto. Crypto failure still retains signed locks |
| Signed pending Broadcast; wait / navigate | S; editors still enabled; no Send default | `(0,0,0,0,0,0)`; `action_state.py:60–64`, navigation has no payment command | Signed checkpoint + evidence retained; navigation never unsigns/releases |
| Broadcast decision open | S underneath; Cancel + Approve Broadcast; Cancel default | `(0,0,0,0,0,0)`; `bip39_fusion_gui.py:937–953` | No new evidence merely from opening |
| Broadcast declined: Cancel / default Return / Escape / close | S remains; Cancel default | `(0,0,0,0,0,0)` for **each** path; `:947–953` only accepted code queues broadcast | Signed bytes, commitment and reservation remain; no cancel/release |
| Explicit Broadcast approved, success | BUSY → P after result; no Send default | `(0,0,0,1,0,0)`; GUI `:947–953`; session `wallet_session.py:700–733`; WSP `wallet.py:253–283` | Preflight read-only → encrypted `uncertain` evidence → uncertain reservations/checkpoint → one sendrawtransaction → broadcast checkpoint/evidence + exact pending TXID. Q06 `bip39_spend_session.py:166–176,375–379` |
| Rapid repeated explicit approval | BUSY; same modal default | First approval as above; duplicate additional `(0,0,0,0,0,0)` `bip39_owner_gui.py:402–425` | One submission; no automatic resubmission |
| Submitted, TXID known | P (not Confirmed); no Send default | Result delivery `(0,0,0,0,0,0)`; queues read-only snapshot `bip39_owner_gui.py:680–687` | Broadcast evidence remains. TXID alone is submitted/pending copy, not proof of confirmation `fusion_pages.py:323–340` |
| Uncertain with TXID, mempool absent / not in verified history | Controls depend on owner fault/custody; formatter alone cannot determine them: UNKNOWN absent owner inputs | Inspection/result `(0,0,0,0,0,0)` `fusion_pages.py:323–340`, GUI `:1099–1109` | No result write; original uncertain/signed reservation preserved. Unknown ≠ failed; no automatic retry/release |
| Uncertain without TXID | Same owner-dependent controls, UNKNOWN from missing TXID alone | Formatter `(0,0,0,0,0,0)`; same source. If caused by submission exception, preceding submission count may be 0 or 1; **network acceptance UNKNOWN** | No invented TXID or success. Actual interrupted submission keeps uncertain checkpoint; no automatic RPC retry `wallet_session.py:716–729` |
| Verified mempool pending exact TXID | P for normal submitted owner state; no Send default | Inspect/result `(0,0,0,0,0,0)` `bip39_fusion_gui.py:1099–1109` | Read-only result, pending not confirmed; no new payment evidence |
| Confirmed exact TXID in verified history | E after exact pending clears; no Send default | Result display `(0,0,0,0,0,0)` `bip39_owner_gui.py:687–695`, `bip39_fusion_gui.py:1091–1109` | History is authoritative. Explicit developer `confirm` mines separately; result/navigation never mines. Mismatched TXID cannot clear pending |
| Stale Sign commitment | Approval opens on original review; no new default | `(0,0,0,0,0,0)`; session `wallet_session.py:665–666` refuses before mark/sign | Existing draft unchanged; never silently prepares or re-signs |
| Stale Broadcast dialog / mismatched signed result | Broadcast off after mismatched result; Cancel stays dialog default | `(0,0,0,0,0,0)`; GUI `:943–952`; owner `:672–679`; session `wallet_session.py:703–705` | Signed reservation unchanged; no submission |
| Lock while modal; late **accept** | LOCKED; stale sheet still interactive (D3A-1), Cancel default | Lock result clears commitment; late accept `(0,0,0,0,0,0)` `bip39_owner_gui.py:726–744`, GUI `:1054–1074,:947–953` | Lock/custody cleanup is separate; late accept enqueues no Sign/Broadcast |
| Lock while Sign modal; late **decline** | LOCKED, stale Cancel actionable | **one cancel command queued** (D3A-2); durable release UNKNOWN from GUI alone; production `_rpc` refuses locked state `wallet_session.py:304–312` | Synthetic dispatch probe does not establish a production release. No claim that locked custody is bypassed |
| Shared disconnect while modal | Shared masks Review/Broadcast/Confirm/Fund; modal approval stays enabled (D3A-4), Cancel default | Modal acceptance can enqueue a command; real backend rechecks `peer_status(require_connected=True)` before prepare/sign/broadcast `bip39_owner_backend.py:561–565`. Resulting tuple `(0,0,0,0,0,0)` when disconnected check refuses | No session method reached on failed peer guard; no actual Shared Core run here |
| Reopen signed intent / authenticated snapshot of active signed review | S if live review+signed restored; E + optional Advanced Resume if only durable signed intent is available | Reopen/status/navigation `(0,0,0,0,0,0)`; `bip39_owner_gui.py:621–637`, Q06 `bip39_spend_session.py:180–253` | Anchored signed rows + encrypted exact PSBT inspected read-only. No automatic resume/re-sign |
| Reopen pending broadcast | P after authenticated exact pending TXID recovery | `(0,0,0,0,0,0)`; Q06 `:330–372`, GUI `bip39_fusion_gui.py:1113–1127` | Recover exact TXID from anchored rows/evidence plus mempool; no auto-inspect merely to fill reopened UI |
| Reopen uncertain | E/Advanced intent route if newly authenticated and healthy; spend controls off if faulted/uncertain latch; UNKNOWN without those inputs | `(0,0,0,0,0,0)` for reopen/status; Q06 `:180–253` | Uncertain rows and evidence survive; read-only classification does not itself authorize resume |
| Signed/pending/uncertain window close | Quit/lock owner shutdown; no Send default | No prepare/mark/sign/send/release/resume from close `(0,0,0,0,0,0)`; `bip39_owner_gui.py:910–924`, `wallet_session.py:820–866` | Native lock/checkpoint/cleanup may write custody state, never undo irreversible reservation. GUI probe sees quit only; TX-03 proves retained rows across restart |

WSP reference above is pinned external source
`/Users/dinhdang/Documents/WAM-Fusion-Pro-Max/source/wsp-upstream/src/wam_sp/wallet.py`;
`release_draft:222`, `mark_signed:232`, `sendrawtransaction:277`.
Read-only snapshot/status inspection can perform RPC reads and schedule bounded
read-only inspection (`bip39_fusion_gui.py:1113–1121`); zero tuple does **not**
mean zero read traffic or no custody shutdown writes.

## Defects retained, not repaired

| ID | Contract violated / observed boundary | Probe |
|---|---|---|
| D3A-1 | §7 close/invalidate presentation gap: commitment invalidates, but Sign sheet remains visibly interactive after lock. No late accept write observed; this is not an authority bypass | `test_lock_invalidates_open_decision_sheet` expectedFailure |
| D3A-2 | §7/§8 late signals must not enqueue writes. Late rejection of locked Sign sheet still dispatches cancel. This is a GUI command gap, **not demonstrated durable release** | `test_late_decline_after_lock_enqueues_no_write_command` expectedFailure |
| D3A-3 | §3/§7 invalid form should disable Review until actionable. Empty form still enables Review; clicking it is correctly refused before prepare | `test_invalid_form_disables_review` expectedFailure + passing validation probe |
| D3A-4 | §2/§7 disconnected control gap: underlying Broadcast disables, but modal Approve Broadcast remains enabled. Backend independently refuses disconnected spend commands; not a demonstrated write bypass | `test_disconnect_disables_open_broadcast_approval` expectedFailure + passing real backend peer guard |

Expected failures are defects, never technical acceptance PASS. No authority,
locale, layout, format, fee policy or persistence repair in PM-051.

## Executable evidence boundaries

`test_pm051_d3a_send_commands.py` wraps the **real window `_command`** and uses
real ControlWorker/WalletExecutor with a synthetic recording backend, following
`test_q06_bip39_fusion_gui`. It tests no-approval, all four Sign declines, all
four Broadcast declines, prepare busy/rapid clicks, duplicate explicit approval,
stale commitments, lock and late accept/decline, disconnect peer guard,
reopen/navigation/close, uncertain/mempool/confirmed result facts.

`test_pm051_d3a_session_evidence.py` reuses only TX-03's existing disposable
fixture boundaries: real WalletSession/Q06 session, WSP scanner/PSBT/signer,
SQLite reservations and encrypted evidence; synthetic RPC, anchored-vault and
owner-binding doubles. It wraps actual prepare/mark_signed/Signer.sign/release/
resume methods, observes uncertain evidence **inside the RPC submission call**,
and asserts row states/checkpoints/exact PSBT/TXID/one submission and read-only
signed+uncertain restart. It does not call a new synthetic RPC method or real
Core, use a retained profile, or read a secret. Its inherited TX-03 tests are
excluded by load_tests; required TX-03 regression module runs separately.

A prepare_auto backend command is not proof of exactly one internal proposal:
fee quoting can deliberately prepare/release several never-reviewed drafts.
The session probes use TX-03's explicit-fee fixture, not a fake auto-fee RPC.
Native-Cocoa ordering, full built-app interaction, frozen packages, genuine Core,
Windows/Linux host proof, physical G6 and independent G7/V19 are NOT RUN here.
No G0–G7 or acceptance ledger change. ENGINEERING HANDOFF NO; FULL Q ACCEPTED NO.

Run commands, exit codes, environment and retained initial harness failures
are recorded in `RUNS.md` beside this matrix and in the external PM-051 evidence
folder. No failed log is deleted. Runner alone will create the single requested
commit; its SHA is unavailable before runner completion. Never push.
