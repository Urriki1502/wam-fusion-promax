# PM-060 / D2-A — Overview and states characterization

2026-11-14 · Lane A · Codex single writer. Tests/evidence ONLY.
Branch `promax/d2a-overview-characterization`; initial HEAD and local promax/main
`6e2558a7b00581b0f4caaa0ae09fea9e4408d8b2`; initial tracked/staged/untracked
inventory empty. No fetch/rebase, source/locale/ledger change, push or Git
metadata write. Runner creates the commit after exit. Independent review remains
required. Q06 accepted=false; no engineering handoff or full acceptance.

`ENGINEERING_HANDOFF.md` was attempted first and is absent. Runner-owned
`PEER-196-codex-implement-pm060-d2a/lease.txt` contains
`ENGINEERING_LEASE_HELD`. The promised `lease-clone.txt` is absent; exact lease
holder PIDs/clone detail are UNKNOWN. Per explicit runner instruction, no lease
acquisition/release, process adoption, duplicate checkout or source transfer.
No application/Core owners remain running from these synthetic tests.

Inputs: external `PM-055-d2-overview-spec/D2-overview-spec.md` §§2–4,8.1,9;
its `CLAUDE-SPEC-REVIEW.md`; `PM-059-d6-settings-spec/D6-settings-advanced-spec.md`
§2.1; PM-051/PM-054 fixtures and recording-backend style; product charter
`source/docs/WAM_FUSION_PRO_MAX_PRODUCT_NORTH_STAR_2026.md`.
All source citations below are relative to `src/wam_regtest/` at the initial HEAD.
All fixture data are public synthetic values; **design-fixture / PM-041b live
incoming unavailable**. No genuine chain, custody or frozen qualification.

## Classifier and rendering: exhaustive current leaves

`fusion_status.py:7–75` returns tone/title/detail; invalid kind raises at :14–15.
Titles/details below name **existing `status.*` catalog keys**, resolved at call
time, not proposed D2 copy. Braced fields are exact supplied values, not progress.
`fusion_ui.py:1559–1569` classifies four cards; StatusCard.apply at :1014–1017
sets glyph state and both labels. `_set_actions` refreshes the security card
(`bip39_fusion_gui.py:733–741`). Header pill uses only snapshot **title** at
:993–997 / :1012–1015; detail/tone are not bound there as an independent score.

| Kind and condition, in precedence order | Tone | Title / detail key | Source |
|---|---|---|---|
| core, fault | error | core_fault / core_fault_reservations | fusion_status.py:22–23 |
| core, snapshot + alive False | warning | identity_pinned / pinned_disconnected | fusion_status.py:25–28 |
| core, snapshot + alive True | verified | identity_pinned / pinned_snapshot | fusion_status.py:29–31 |
| core, snapshot + alive None | warning | identity_pinned / pinned_process_unconfirmed | fusion_status.py:32–33 |
| core, no snapshot + busy | pending | verifying / checking_identity | fusion_status.py:34–35 |
| core, no snapshot, idle, alive False | unknown | not_connected / core_not_running | fusion_status.py:36–37 |
| core, no snapshot, idle, alive True | pending | core_running / process_alive_unverified | fusion_status.py:38–39 |
| core, no snapshot, idle, alive None | unknown | not_verified / identity_after_snapshot | fusion_status.py:40 |
| chain, snapshot (even fault/busy) | verified | height {height} / verified_height | fusion_status.py:41–44 |
| chain, no snapshot + busy | pending | syncing / waiting_snapshot | fusion_status.py:45–46 |
| chain, no snapshot, idle | unknown | not_verified / height_after_snapshot | fusion_status.py:47 |
| security, fault | error | faulted / reservations_preserved | fusion_status.py:17–19 |
| security, locked OR no snapshot OR !operational | unknown | locked / password_required | fusion_status.py:48–51 |
| security, otherwise | warning | unlocked / keys_open | fusion_status.py:52–53 |
| network, integer count + connected False | error | disconnected / peers_disconnected {peer_count} | fusion_status.py:56–59 |
| network, integer count + connected True | verified | connected / peers_verified {peer_count} | fusion_status.py:60–62 |
| network, integer count + connected unspecified | warning | peer_check / peers_unconfirmed {peer_count} | fusion_status.py:63–64 |
| network, count absent/invalid + shared + busy | pending | awaiting_peer_check / peer_state_after_check | fusion_status.py:65–67 |
| network, count absent/invalid + shared + idle | unknown | awaiting_peer_check / peer_state_after_check | fusion_status.py:65–67 |
| network, count absent/invalid + isolated | unknown | isolated / zero_peer | fusion_status.py:68 |
| snapshot, fault | error | core_error / owned_core_fault | fusion_status.py:20–21 |
| snapshot, snapshot present (locked ignored) | verified | snapshot_verified / wallet_verified_snapshot | fusion_status.py:69–70 |
| snapshot, absent + busy | pending | verifying / refreshing_state | fusion_status.py:71–72 |
| snapshot, absent + idle + alive True | pending | core_running / core_alive_unverified | fusion_status.py:73–74 |
| snapshot, absent + idle + alive False/None | unknown | snapshot_not_verified / header_snapshot_state | fusion_status.py:75 |

Bool peer count is invalid (`type(...) is int`); connected uses identity tests.
Fault overrides core/security/snapshot only, not chain/network. Overview masks
snap on lock before classify (:1563), but a direct faulted+snap render does not
itself clear financial values; window invalidation owns that boundary. Isolated
zero-peer text is configuration, not an observed count. Tests pin each leaf,
all three security OR operands, fault fallthrough, bool count, invalid kind and
actual card rendering. Existing PM-017 adds six-locale coverage. No universal
Connected/security/acceptance score is implied by verified snapshot.

## Actions and command boundary

`bip39_owner_gui.py:375–396` defines busy as worker present OR executor.busy OR
result delivery. `presentation/action_state.py:49–75,95–110` is the pure action
source; Fusion binds it at `bip39_fusion_gui.py:709–744`.

| Action | Exact current predicate / route |
|---|---|
| Visible header Refresh (`sync`) | ready && !faulted && !busy && !quit_requested. Snapshot only; owner_gui.py:346 and fusion_gui.py:210–214 |
| Overview Send | ready && !faulted && !locked && !busy && spend_enabled && core_alive is True && !reauthentication_required && (isolated OR shared.connected). Navigation row 3 only (:490–491), not prepare/sign/broadcast |
| Security compatibility navigation | !quit_requested; row 4 (:494–495). Security is navigation, no custody action |
| Base Lock | ready && !busy && !quit_requested |
| Base Unlock | unlock_allowed && !ready && !busy && !quit_requested |
| Custody switch | !busy && !quit_requested && (base lock OR base unlock); `_switch_custody` :779–785 uses existing lock/unlock route |
| Receive | go_receive enabled only on rendered snapshot; lock/clear disables (:1588,:1612); row 1 (:488–489) |
| History / selected TXID | row 2 or exact existing route; :492–498,:668–670. No lookup/payment command |
| Copy / QR | validated public address only; fusion_pages.py:14–22,47–60. Copy calls clipboard, QR locally encodes |

Nuances retained: go_send itself does **not** consult quit_requested (unlike
base Send/Refresh); it is presentation navigation, not spend authority. Hidden
compatibility `overview.manual_sync` directly calls `_command('snapshot')`
(:496–497), remains hidden and is not the action-state-controlled header Refresh.
It is excluded from the visible Refresh claim. First harness run mistakenly
clicked this compatibility button, causing six dispatcher attempts but still
one backend snapshot; corrected test targets visible `window.sync`.
`_command` rejects overlapping workers/closed owner/delivery before enqueue
(owner_gui.py:404–410). Six rapid visible Refresh clicks produce exactly one
GUI dispatch and one backend snapshot; after lock, disabled Refresh produces
zero. Navigation, rendering QR and Copy produce **zero commands of ANY name**,
not merely an allowlisted subset. Real ControlWorker/WalletExecutor plus a
recording synthetic backend counts both dispatch and execution; cleanup quit is
outside measured intervals. No backend process/mining/payment implementation.

## Four balance facts, producers and currentness

Same WalletReadSnapshot, no second scanner: `application/snapshot_projection.py:19–29,41`.
`bip39_owner_backend.py:328–349` holds session lock/transaction, supplements pending
facts and projects available; read-only branch verifies scanner/Core tip at
:416–434 and builds snapshot at :455–465. `wallet_session.py:367–395` syncs and
asserts current tip before transactional balance/history. `wallet_read.py:47–76`
defines fields; `history_pages.py:132–146` gates pending totals by mempool_ready.

| Fact | Producer/basis | Rendering today / unknown versus zero |
|---|---|---|
| Confirmed | Wallet balance confirmed_atoms at verified height/tip | Sole hero, grouped integer atoms, eight decimals; :1526–1538,:1597–1598. None/locked -> unitless em dash. Invalid confirmed is refused by format_wam (:22–26), caught by window :1001–1004, not fabricated as zero |
| Available (confirmed) | backend balance available_atoms, snapshot projection independent of confirmed | fund_details prose, not primary card. Explicit argument None falls back to snap.available_atoms (:1602–1604). Not derived from history/count/pending |
| Confirmed inputs pending spend | balance pending_spent_atoms only with current mempool | fund_details pending.spent_value (:1606); whole owned input value, not payment+fee; None means unknown |
| Unconfirmed incoming/change | balance unconfirmed_atoms -> pending_atoms only with current mempool | fund_details pending.total_value (:1605); combined incoming/change, no income split; live incoming remains unavailable/blocked on PM-041b |

`pending_amount_text` (:1357–1361) accepts exact nonnegative int; None, negative,
bool, float, NaN or string becomes localized unitless unknown. Known zero is
numeric `0.00000000 WAM`; optional labels do not add a unit to unknown.
Fixture confirmed=100000, available=7000, pending-spent=90000,
unconfirmed=8000 pins all four independently, plus a reservation **count** 2.
No sum/subtraction or synthetic total. Existing PM-041 pins outgoing amount+fee,
change separation, stale mempool and all-history confirmation suppression.

Confirmed chart uses complete verified history and consistency with confirmed
amount (`fusion_ui.py:853–887`); it is secondary, not a balance producer.
Snapshot height is visible in UTXO prose (:1599–1601) and chain card, but there
is no current ordinary “Verified at block” band. Hidden live_badge initially
hidden at :1388–1389, updated on snapshot (:1611) and denial
(`bip39_fusion_gui.py:1172–1173`) but never shown there. Thus a **stale signal
exists** (`wallet.refresh_required`), with no visible stale-state presentation.
Busy `_set_actions` disables actions but keeps prior verified balance/chain/pill;
no visible Last verified marker. No wall-clock verification time, ETA, IBD,
target height or age producer is established: **UNKNOWN**. D2A-2 retains both
busy and ordinary-refresh-denial defects; this is not permission to change
freshness/spend policy.

## Receive / R-7 and exact public identity

`fusion_pages.py:34–46`: QR/address/Copy card precedes info panel containing
`pages.silent_payments_note` (anonymity limit + technical explanation) and
`pages.disposable_funds`. Both warnings belong to the **same scroll body**;
there is no persistent warning band. Sizes reuse
`qualification/ui_gallery.py:28` (client dimensions, not desktop size).

Measured real Bip39FusionWindow, English/default dark, offscreen, DPR 1;
positions below are y,height relative to actual Receive scroll viewport.
Raw logs include x,y,width,height for warning/address/QR/Copy at both positions.
This is bounded characterization, **not** 36-variant gallery/native a11y proof.

| Client / viewport | Initial anonymity / funds warning | Bottom anonymity / funds warning | Address / QR / Copy |
|---|---|---|---|
| 900×630 / 597×479 | (777,32) / (821,34): both not visible | scroll 454: (323,32) / (367,34), both fully visible | Initial QR visible; address/Copy below fold. Bottom address/Copy visible; QR above viewport |
| 1100×720 / 797×569 | (542,32) partial / (586,17) below fold: neither fully visible | scroll 129: (413,32) / (457,17), both fully visible | Address/QR/Copy fully visible at both positions |
| 1440×900 / 1144×749 | (542,16) / (570,17), both fully visible | maximum=0: unchanged, no actual scrolling available | Address/QR/Copy fully visible |

R-7 remains open at 900/1100 (D2A-1); 1440 fitting does not make a scrolling
warning persistent. Both positions are recorded **before** the defect assertion,
so an expected failure does not skip the bottom measurement. No clipping or
anonymity claim follows from offscreen rectangles alone.

PaymentQR.set_code requires wamrtsp1 and decode_address before QR data
(:14–22), then encodes the raw string with no URI/amount/label. Test captures
actual QRCode.add_data payload and compares actual rendered QR matrix to an
independent QRCode of that same full string. Payload == visible address ==
clipboard text byte-for-byte. This proves logical matrix/payload equality;
optical camera decoding/physical legibility is **UNKNOWN**, not claimed.
Invalid address is refused/QR cleared by existing Receive regression; lock
clears code/QR/Copy immediately. Existing copy feedback timer remains armed on
clear, but its late timeout uses current `self.code` and shows address_locked,
not old success. Public clipboard is intentionally retained, not auto-cleared.

## Lifetime and late delivery

Window `_render_verified` checks exact snapshot type, regtest, synthetic/mainnet
flags, receive/confirmed/signer/broadcast equality and fault (:973–984).
`_clear_visuals` (:1010–1024) clears accepted snapshot, Overview, Receive,
History and review summary, but not all cached/hidden text. Public open-result
injection models a profile-boundary delivery only: no profile is opened, no
folder supplied or remembered (`owner_gui.py:445`), and checkpoint_present=True
prevents automatic snapshot. Actual switching/owner reachability is UNKNOWN.

| Field | Lock delivery | Fault/Core-loss denial | Profile open delivery | Late results |
|---|---|---|---|---|
| `_last_verified` | None; lock path :1142–1144 | None; :1156–1165 | None; :1132–1138 | Direct snapshot after lock/open can repaint; faulted state rejects. No profile generation comparison in renderer |
| Financial/address/activity widgets | Em dash, unit hidden, empty rows/QR/Copy; no synthetic zero | Same | Same | Injected old snapshot repaints if snapshot guards pass; real serialized race reachability UNKNOWN |
| Hidden fund_details | Hidden but old amounts retained | Same | Same | Last accepted render replaces text; stale hidden buffer D2A-7 |
| `_last_network` | Retained | Retained | Retained | network_status/network_active sets cache unconditionally (:1038–1050); old generation cannot be distinguished in this handler |
| `_last_error_code` | Direct result delivery retains old code; actual `_command('lock')` clears it first | Replaced by sanitized public denial code | Direct result delivery retains old code; actual dispatched command clears it first | Any `_on_denied` sets current code; no profile attribution token |
| Advanced session account/balance/tip | Explicit locked/unverified labels | Old account/balance/tip remain | New public account + balance-unsynced / chain-unchecked | Snapshot updates balance/tip; no account update in snapshot branch |

Sources: inherited `_last_error_code` starts None at `bip39_owner_gui.py:371`,
resets on successful command start at :415; sanitized denial updates at :842–844.
Session labels reset on open at :580–606 and lock at :744–746; snapshot replaces
balance/tip at :635–636; denial :842–866 does not reset them. Snapshot assignment
:1005 is after rendering; network cache initialized :503, updated :1038–1042
and read :672–707. `_shared_connected` also survives clear, impacting existing
presentation predicate; no cross-profile peer truth is established.

Worker result staging/finish (`owner_gui.py:868–905`) serializes one operation,
then delivers with `_delivering_result`; `_command` refuses overlap. Tests
inject stale public results intentionally to establish the **handler's missing
guard**, not a proven concurrent/backend custody exploit or permission to add
new concurrency architecture. Late result actual feasibility is UNKNOWN.
Late network delivery has no invalidation token in this handler; future D6
must not describe mixed-age network/snapshot as one current observation.

## D2-A defects retained, not repaired

Each expected failure is tagged in a test docstring/assertion. Diagnostic run
removes decorators only in memory and requires intended D2A assertion failures,
zero errors. Expected failures are not contract PASS.

| ID | Current deviation / tests |
|---|---|
| D2A-1 | R-7 safety warnings not fully visible at scroll=0 at 900/1100; 2 expected failures |
| D2A-2 | Refresh denial signal hidden; busy retained snapshot lacks visible Last verified; 2 expected failures |
| D2A-3 | Lock and profile open retain previous network peer truth; 2 expected failures |
| D2A-4 | Delivered profile open retains old public error code; dispatched commands clear first, so live cross-profile attribution is UNKNOWN; 1 expected failure |
| D2A-5 | Fault clears ordinary pages but not Advanced session labels; 1 expected failure |
| D2A-6 | Direct late snapshot delivery repaints after lock/profile boundary; actual serialized race UNKNOWN; 2 expected failures |
| D2A-7 | Hidden fund_details retains wallet-linked amount text after lock; 1 expected failure |

No product fixes, new RPC, native settings, Core/WSP/dependency upgrade or
wallet/profile access. PM-048 WrapText is integrated in this checkout
(`fusion_ui.py:1337–1354`); existing PM-041 narrow-row wrapping regression and
PM-054 exact History route are rerun, rather than reimplemented.

See RUNS.md for exact commands, exits, retained harness failures and limits.
