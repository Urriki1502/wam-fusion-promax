# WAM Fusion — Independent Remediation Design Review (v1.0)

**Date:** 2026-11-06 (Asia/Ho_Chi_Minh)  
**Purpose:** clarify engineering options *before* implementing fixes; minimize the scope of changes, CI reruns and custody risks.  
**Repository:** https://github.com/Urriki1502/wam-privacy-wallet-regtest  
**Immutable audit baseline:** PR #141, commit `b187cde17b12ae5f7c11f0611d5f4b1661bfc90b`; base `c61e3c5be4b8519dc6c4d9eb56d124fce84cf02d`; Core v0.1.13; WSP `ac55f13423620252bdbf848c7e8a280c3b84721e`.  
**Findings source:** `WAM_Fusion_Phase_A_Security_Audit_Report_2026-11-06.md` (2 High, 9 Medium, 1 Low; 6 NOT VERIFIED groups).  
**Evidence level:** source modules and GitHub evidence inspected at the exact SHA; GitHub, Apple, Qt, Microsoft, SQLite and OWASP documentation compared. **No payloads or fuzzing were run, no exploit was demonstrated, and no access to the original Mac took place.** This is a *security design review*, not independent G7 approval or authorization for mainnet.

## Decision rules

- **FACT:** confirmed by the inspected source/configuration; **DESIGN:** selected implementation option; **HYPOTHESIS:** requires reproduction; **OPEN:** requires a design decision or evidence before any fix.
- **READY TO IMPLEMENT:** limited custody impact, known files and tests. **DESIGN GATE:** establish invariants, race and crash behavior. **RESEARCH GATE:** data or infrastructure is missing.
- High/Medium severity expresses **anticipated risk when real funds are involved**, not an assertion that an exploit succeeded or that a CVE exists.
- **Prohibited:** enabling mainnet without authorization; modifying WSP or Core consensus; deleting/resetting native anchors, signed/uncertain reservations or historical failures; changing the ledger to force PASS; testing on real mainnet wallets or nodes; force-pushing, merging or releasing.
- **Local first:** source, macOS native, then frozen app/DMG on local machines before pushing and running same-commit Windows/Linux/macOS CI. Three-platform CI must not be presented as G6/G7/V19 evidence.

## Prioritized execution matrix

| ID | Finding | Readiness | Recommended next action | Completion criterion |
|---|---|---|---|---|
| H-01 | Fusion publisher trust not established | RESEARCH / RELEASE ADMIN | Specify signing; test disposable lab copy without production trust keys | Independent verification procedure and responsible signer established |
| H-02 | `main` unprotected; zero rulesets | ADMIN READY | Configure `main` ruleset through GitHub UI | Direct/force-push prevention confirmed by actual settings |
| M-01 | Incomplete clean-device/disaster-recovery proof | DESIGN GATE | ADR, threat model, fixtures; do not alter vault | Proof irreversible state is retained before spending is enabled |
| M-02 | Unencrypted SQLite runtime while unlocked | RESEARCH GATE | Data inventory, retention and forensic tests | Documented exposure threat model and tested mitigations |
| M-03 | Best-effort RAM secret clearing | RESEARCH GATE | Audit secret lifetime/copies; no zeroization claim | Runtime-specific mitigations and limitations demonstrated |
| M-04 | Fixed KDF and feasible weak passwords | DESIGN GATE | Benchmark, password policy and separately versioned format upgrade | Authenticated migration and cross-platform fixtures PASS |
| M-05 | 4096 / Linux 10000 generation limits | DESIGN GATE | Stress fixtures near limits only | Crash-safe rotation/compaction with preserved reservations |
| M-06 | Missing idle/OS-session auto-lock | DESIGN GATE | State machine and race tests before implementation | No stale approval; correct locking under in-flight work |
| M-07 | Mutable GitHub Actions tags | READY TO IMPLEMENT | Pin independently verified full SHAs across 11 workflows | Only `uses`/permissions diff; CI remains valid |
| M-08 | Suspected slow-trickle/hanging RPC | REPRODUCE FIRST | Bounded lab transport fixture | Before/after evidence, no write retries |
| M-09 | Manual peer lacks cryptographic identity binding | RESEARCH / NETWORK | Threat model, V19/partition lab; do not claim added authentication | Explicit P2P trust model and test results |
| L-01 | Backup verifier accepts fewer than three GUI-selected positions | READY AFTER MINI DESIGN | Backend-controlled single-use challenge | One/two/replay/substitution FAIL; exactly three correct PASS |

## H-01 — Fusion package publisher integrity

**FACT:** `scripts/build_macos_bundle.sh` executes `codesign --force --sign - --timestamp=none "$APP"`, producing an ad-hoc signed app/DMG without notarization. Core v0.1.13 members have separately pinned hashes; those hashes **do not** authenticate the Fusion wrapper or its publisher. `docs/SBOM_PREP_HOST.md` inventories host dependencies, not the frozen SBOM. [Source](https://github.com/Urriki1502/wam-privacy-wallet-regtest/blob/b187cde17b12ae5f7c11f0611d5f4b1661bfc90b/scripts/build_macos_bundle.sh#L90-L104).

**SELECTED DESIGN:** separate **builds without release secrets** from **controlled signing and distribution**. Produce source/WSP/Core pin manifests and hashes of *final signed artifacts*. Sign metadata with a release-key-management-controlled key; users verify through a public trust root distributed independently. For macOS: Developer ID, hardened runtime and notarization/stapling *when a valid certificate is available*. For Windows: Authenticode, signer chain and timestamp verification. For Linux: detached package/manifest signature, with its verification key distributed separately. Never alter verified upstream Core member bytes while signing. Explicitly test interactions between outer-app signing and nested `wamd`/`wam-cli` hashes.

**REJECT:** a standalone `SHA256SUMS.txt` placed alongside a ZIP; a CI-runner-generated signing key falsely presented as a publisher identity; replacing upstream Core merely to simplify signing; or treating the upstream Core signature as a Fusion signature.

**INITIAL ACTION:** draft `docs/security-audit/H01_RELEASE_TRUST_ADR.md`, test signing on a **disposable copy** without production keys, and compare Core member hashes before/after. **Do not independently enable notarization or release.** **Definition of done:** independent trust-root distribution, key custody/rotation/revocation, offline verification, separation of CI builds from authorized releases, final SHA256/SBOM/signer reports. **Mainnet release remains blocked.**  
**Reference:** https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution

## H-02 — GitHub `main` ruleset

**FACT:** on 2026-11-06, GitHub returned `main.protected=false` and `/rulesets=[]`. This is a **repository governance/supply-chain risk**, not a wallet-signing defect and not a reason to halt local REGTEST auditing.

**SELECTED DESIGN (repository administrator):** apply a ruleset to `main` only; require pull requests; prohibit force pushes and branch deletion; provide no bypass to automated identities. Add required checks only after verifying their actual names and whether they run on `main` (workflows differ by manual/PR/path filters). Prefer GitHub Actions as the expected app where possible. For a mostly single-maintainer repository, do not require mandatory human approval before a qualified reviewer can provide it, or merging may become impossible. Verify effective settings through the UI rather than destructive test pushes.

**REJECT:** enabling 20 required checks immediately; protecting every feature branch and blocking normal work; granting a Full Access token to modify rules and exempt itself. **Definition of done:** screenshots or configuration records, bypass actors and verified enforcement. No source change required; do not disrupt PR #141.

**Reference:** https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets

## M-01 — Clean-device recovery, missing anchors and missing journals (highest difficulty)

**FACT:** `bip39_recovery_proof.py` deliberately reports `same_chain_only=true`, `clean_device_recovery=false`, `signed_reservations_restored=false`, `signer_allowed=false`, and `broadcast_allowed=false`. `wallet_recovery.py` preserves the native anchor floor and rejects divergent future state; `Core migratewallet` does not migrate Fusion's Core identity. [Recovery proof](https://github.com/Urriki1502/wam-privacy-wallet-regtest/blob/b187cde17b12ae5f7c11f0611d5f4b1661bfc90b/src/wam_regtest/bip39_recovery_proof.py#L80-L97).

**Three separate rights:** (R1) **key identity** from 12 words; (R2) **chain-visible wallet state** from a full scan of the correct chain/genesis and its history/UTXO; (R3) **off-chain irreversible state** including signed and uncertain transactions, reservations, and Core/native process identity and provenance. R1+R2 **do not prove** R3: a signed but unbroadcast transaction may be invisible on-chain.

**RESEARCH DESIGN (DO NOT IMPLEMENT SIGNING):**
1. `RECOVERED_READ_ONLY`: create a new disposable profile from a test mnemonic; attest genesis/Core, perform a full correct-chain rescan; permit address/balance/history reading only. Never overwrite old profiles or anchors.
2. `STATE_CONTINUITY_VERIFIED`: require an authenticated journal backup, matching wallet identity, complete signed/uncertain records and native-authorized migration proof; use create-only crash-safe checkpoints and compare-and-swap into a new anchor. Any mismatch -> READ_ONLY/BLOCKED.
3. If **all journals are lost but keys survive**, there is no demonstrated universal method to restore signing authority safely. A separate reviewed policy must address risky UTXOs, reconciliation windows/procedures and warnings about invisible signed transactions. Never select an arbitrary timeout to release them.

**Mandatory vectors:** one missing anchor; both anchor+ciphertext missing; old/new backup; signed-before-crash; broadcast-uncertain; chain partition; same-chain restore; wrong genesis; wrong OS; wrong Core hash; concurrent process claimant; crash at each new-write step; duplicate transaction; reorg. **Do not reset retained native anchors or existing user data.**

**Before implementation:** `M01_RECOVERY_THREAT_MODEL.md`, `M01_RECOVERY_ADR.md`, state/invariant table, proposed migration format, fixture-only two-computer scenarios and refusal proofs. **DESIGN GATE:** independently review these artifacts before changing any wallet writer. A simple BIP39 rescan must not be called a complete M-01 fix.

## M-02 — Plaintext runtime SQLite and privacy data

**FACT:** pinned WSP `store.py` stores coins, tweaks, contacts, labels, history and reservations in unencrypted SQLite, with `PRAGMA journal_mode=DELETE` and `synchronous=FULL`. The inspected schema did not contain plaintext passwords or seeds. `bip39_spend_session.lock()` intentionally **retains** runtime data on signed/uncertain/faulted sessions for forensic recovery; unconditional deletion would be unsafe.

**TWO-STAGE DESIGN:**
- **Measure first:** populate synthetic history/contacts/labels; inventory database, `-journal`, swap/crash dumps, OS backups and snapshots within observable limits on macOS APFS, Windows and Linux. Measure file lifetimes after clean lock, uncertain lock, crash and restart. Never scan real seed data.
- **Minimal mitigation:** limit time spent unlocked, enforce private file permissions, exclude inappropriate backup targets, minimize PII/retention and redact logs; exclude runtime profiles from distributables and evidence. If privacy requires encryption at rest even while unlocked, write a separate ADR for SQLCipher/encrypted VFS or in-memory storage with encrypted snapshots **and consistency proof**. Do not change the SQLite storage engine in this phase.

**REJECT:** unlinking uncertain runtime state; promising secure SSD erasure via `PRAGMA secure_delete`; enabling WAL/SQLCipher without WSP/schema/rollback compatibility checks; or replacing all storage solely to pass audit. **Definition of done:** verified exposure inventory, mitigations and regression tests for normal cleanup vs. fault retention. Encryption rollout, if pursued, needs format migration and crash testing.

## M-03 — Secret lifetime in RAM

**FACT:** `bip39_12.py` constructs an immutable `seed: bytes` before copying into a `bytearray`; close only overwrites the mutable buffer. GUI mnemonic `str` values, Python scalars and `_password` may have additional uncontrolled copies. Complete RAM zeroization cannot be demonstrated in Python.

**SELECTED DESIGN:** trace seed/passphrase flow through `bip39_12.py`, `bip39_seed_vault.py`, `bip39_owner_backend.py`, `wallet_session.py` and WSP. Reduce unnecessary `bytes(...).decode()` operations and plaintext lifetime. Clear seed text from UI as soon as confirmation completes. Do not log secrets; avoid release core dumps when a supported mechanism exists; reduce sensitive data in errors. A separate signer process or native lockable-memory buffer is a later research milestone because IPC/process isolation introduces another trust boundary. The current application must not be described as resistant to same-UID malware or root access.

**REJECT:** unsupported overwriting of immutable CPython `str`, modifying cryptographic primitives, claiming `mlock` protects every native copy, or removing recovery to improve RAM metrics. **Definition of done:** explicit secret-flow diagram; tests showing no secrets in diagnostics/artifacts/UI after lock; and a documented assessment of mitigation limits. Destructive testing of real RAM or profiles is not required.

## M-04 — Password and KDF resistance to offline guessing

**FACT:** WSP `keystore.py` uses AES-GCM and scrypt `N=2^15, r=8, p=1` with a random salt, purpose/network AAD and envelope `WAMSP02`. The 12-byte minimum checks **length**, not entropy. OWASP 2026 recommends stronger scrypt settings (for example `2^17,r=8,p=1` or cost-equivalent combinations); this guidance does **not** prove the old format has been cracked.

**DESIGN:** (1) investigate a usable passphrase-quality policy, common/weak/repeated passwords and NFKD/Unicode; (2) benchmark wallet creation/open/recovery KDF latency on the least powerful supported Mac/Windows/Linux targets; (3) choose parameters using password entropy, memory limits and UX latency; (4) if increasing scrypt costs or moving to Argon2id, define a **new versioned envelope and purpose** with authenticated transactional migration in reviewed WSP source, conditional dual-read and new-format single-write. Do not silently modify pinned WSP or change the runtime MAGIC value.

**TESTS:** old-envelope read; wrong password; modified salt/nonce; downgrade; Unicode; short password; costly input exhaustion; mid-migration crash; checksum/Core independence. **REJECT:** replacing `N` without migration; silently re-encrypting old profiles; permitting arbitrarily weak passwords in a mainnet design. **Definition of done:** measured benchmarks, ADR for versioned envelopes, accepted CPU/memory bounds and safe fallback denial.  
**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## M-05 — Checkpoint and journal generation limits

**FACT:** the Q06 scanner checkpoint uses `MAX_CHECKPOINT_GENERATIONS=4096`; the Linux root-witness reader limits reads to 10,000 `.anchor` files and requires continuous generations. These are substantiated long-term availability limits, not evidence of immediate key loss.

**DESIGN:** Phase 1: read-only metrics/early warnings (for example at 80/90% of the limit) and fixture-only stress tests near the caps. Quantify file sizes, latency and daily write rates. Phase 2: an ADR for **CAS-controlled epochs/compaction**, with a new authenticated summary proving full state, preservation of signed/uncertain reservations, journaling of the transition *before* any deletion, and attestation by the native witness. Each crash cut before/after fsync or anchor advance must either recover a verifiable state or refuse. Review crash logic before implementation.

**REJECT:** arbitrarily increasing 4096/10000, resetting the counter to one, deleting anchors/snapshots or removing gap checks. **Definition of done:** fixtures at/above capacity, long-running steady-state tests, cross-platform failure injection and proof of no irreversible-state loss. Until then, preserve fail-closed behavior and document the limit.

## M-06 — Auto-lock and OS session lock: establish the architecture before GUI changes

**FACT:** Q06 GUI provides manual Lock only. The executor serializes in-flight operations; a `wallet_executor.request()` timeout **does not cancel** the operation. `PaymentApproval.open()` is asynchronous and can leave a modal awaiting action. There is no idle or OS-session lock path here. The lock methods in `wallet_session` and `bip39_spend_session` preserve uncertain state. A timer-triggered `lock` while the worker is busy may be refused.

**PROPOSED DESIGN:** an **authorization-epoch state machine** with two lock layers.
- `UNLOCKED(epoch=N)` → idle/OS lock → synchronously set `LOCK_REQUESTED(epoch=N+1)` at the GUI/security gate. Immediately invalidate modal approvals, hide/clear sensitive UI and deny new approvals. Clearing UI is not proof of a backend lock.
- Backend sign/broadcast receives the *current epoch and commitment*, validated within the serialized execution boundary just before the **irreversible point**. A lock request before authorization linearization must refuse. If an approved native Sign/Broadcast **already began**, do not kill, cancel or retry it; let it finish or retain uncertainty and then lock the session through the executor.
- When idle/OS events arrive with a busy worker, persist a synchronized lock intent outside the operation queue (do not rely only on `executor.submit('lock')`, which may refuse); queue the final lock operation safely after the worker. Keep denying UI actions until `LOCKED`/`FAULTED`. Never reuse an approval from an earlier epoch for signing or broadcast.
- Unlock requires a password and attestation of the original Core/native anchor. OS unlock must not automatically unlock the wallet or release signed/uncertain reservations. Application restart begins locked.
- **Illustrative UX defaults, not approved:** idle timeout of 5 minutes with 1/5/15-minute options; immediate lock on OS session lock/suspend. Only genuine interaction in the app counts as activity—not timer, sync or network background events. If native OS signals are unreliable on a platform, state the limitation instead of claiming PASS.

**Event sources:** Qt `QApplication.installEventFilter()` for keyboard/mouse; macOS `NSWorkspace` session/sleep notifications; Windows `WM_WTSSESSION_CHANGE` and notification registration; Linux systemd-logind `LockedHint` or a verified desktop-specific signal. A Qt event filter alone is **not** equivalent to observing OS screen lock.

**PRE-PR TESTS:** idle countdown; keyboard/mouse; open modal; approve/show race; timer at completion of Prepare; sign in flight; uncertain broadcast; worker timeout; OS lock/wake; hidden GUI; lost lock event; unresponsive GUI; disconnected Core; two windows; quit/restart; platform-specific native/frozen checks. Synthetic OS events alone do not qualify native OS-event observation.

**REQUIRED DESIGN OUTPUT:** `M06_AUTOLOCK_ADR.md`, state-transition table, OS event-adapter design and negative-test skeleton. Review them before implementation. **REJECT:** timer-only `_command('lock')`, killing the executor, canceling signed transactions or auto-unlocking with the OS.  
**References:** https://doc.qt.io/qt-6/eventsandfilters.html ; https://developer.apple.com/documentation/appkit/nsworkspace/sessiondidresignactivenotification ; https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change

## M-07 — Pin GitHub Actions with minimal changes

**FACT (inspected across 11 workflows under `.github/workflows/`):** external `uses:` references belonged to **four Actions**: `actions/checkout@v4`, `actions/setup-python@v5`, `actions/upload-artifact@v4` and `actions/download-artifact@v4`. Most jobs specified `permissions: contents: read`; some need `actions: read`.

**READY DESIGN:** obtain immutable full commit SHAs from the Actions' own publishing repositories, check tags/releases and hashes against maintainers; update corresponding `uses` in all 11 YAML files while retaining version comments. Ensure no external `uses:` is missed; grant minimal per-job token permissions and prevent fork PRs from receiving release secrets. Validate YAML and run existing workflows. A GitHub Actions dependency lockfile may be stronger if supported, but is not necessary for this limited hardening.

**REJECT:** pasting SHAs from arbitrary websites; switching back to mutable latest tags; granting broad write tokens to work around failures; rewriting CI and losing evidence. **Definition of done:** no mutable `uses:`, provenance for each selected SHA, valid workflow parsing, unaffected tests and compared artifacts.  
**Reference:** https://docs.github.com/en/actions/reference/security/secure-use

## M-08 — Transport liveness: reproduce before implementing a fix

**FACT:** `json_rpc.py` limits HTTP response size and uses `response.read(cap+1)` plus a socket timeout, but has no **absolute wall-clock deadline** across the entire stream. `wallet_executor.py` keeps operations pending after caller timeout in accordance with the financial-write no-retry policy. **HYPOTHESIS:** a peer or Core endpoint sending very slow chunks might indefinitely delay the executor and locking.

**REPRODUCTION DESIGN:** build a loopback fixture returning chunks just before each socket timeout while total elapsed time exceeds the intended limit. Measure wall-clock duration, resources, state, GUI refusal and binding to the original Core. The fake transport is **for reproduction only**; qualification still requires genuine Core. If confirmed, use an absolute monotonic deadline and bounded read worker *only for response reading*, never to cancel or retry the financial write path. Preserve the pending original operation where its outcome is uncertain. Whether genuine Core can exhibit the behavior is a separate question.

**REJECT:** inflating timeouts to 240/600/900 seconds; automatically canceling/killing the worker; automatically resubmitting write RPCs. **Definition of done:** deterministic before/after slow-trickle regression, unaffected native Core, and eventual safe UI lock with truthful state reporting.

## M-09 — Peer trust, P2P and mainnet

**FACT:** `shared_regtest.py` validates IP address/port, handshake version/subversion and peer limits, but has no cryptographic channel binding for remote peer identity. This is deliberate manual REGTEST behavior, **not** proof a peer can control RPC or sign wallet transactions. BIP352 does not conceal IP addresses.

**REGTEST DESIGN:** preserve manual P2P for V19; test two real hosts with wrong genesis, fake peer, partition, stale chain, fork/reorg, unexpected peers, self-connection, inbound/outbound peers, and loopback-only RPC. Validate retention of signed/uncertain state. The operator selects which remote peer to trust; version strings do not prove identity.

**FUTURE MAINNET DESIGN (out of scope):** rely on native Core v0.1.13 peer discovery/chain validation; investigate eclipse resistance, peer diversity, and transport privacy/Tor only if supported and reviewed. Do not invent a Fusion UI peer-authentication layer and claim underlying TCP is protected without real cryptographic binding. **Definition of done:** physical two-host V19 evidence, explicit network threat model and privacy limitations; do not enable automatic peer discovery in current REGTEST.

## L-01 — Three-word backup challenge: implementation-ready contract

**FACT:** `bip39_backup_page.py` (GUI) calls `random.sample(range(1,13),3)`, sending both **positions and answers** to `backup_verify`. `bip39_owner_backend.py:665-700` accepts any nonempty set of distinct positions (1–12), so even one correct word can create an acknowledged HMAC. The backend already MAC-protects acknowledgements; the weakness is **who controls challenge creation and verification**, not the BIP39 checksum.

**SELECTED DESIGN:** move challenge creation into `Bip39ReadOnlyBackend`. Generate exactly **three distinct positions** with `secrets.SystemRandom().sample(...)`; retain an opaque `challenge_id`, profile/seed identity, session epoch, proposed expiry (120 seconds), and used/invalidated state in the **in-memory session**. GUI requests and displays the three positions; the submission contains **no caller-selected positions**, only `challenge_id + 3 answers`. The backend verifies that the challenge is current, has exactly three slots, was not used or expired, matches the profile/epoch, and that answers match the expected words. **Consume once** before creating the acknowledgement. Cancel, lock, restart, seed change, wrong answer and timeout invalidate it; a new challenge may be requested, but the UI must not reveal the correct words. Do not persist challenges or mnemonics. Preserve the existing acknowledgement HMAC/sidecar envelope unless independent tests reveal a defect.

**TESTS:** exactly three correct answers PASS; one/two positions FAIL; altered positions FAIL; replay FAIL; old ID FAIL; wrong wallet FAIL; expired FAIL; lock/reopen FAIL; wrong word FAIL; concurrent submissions on the same challenge allow at most one success; deferred backup obtains a fresh challenge; error/log outputs contain no seeds/passwords; genuine frozen Qt flow PASS. **Important:** if the GUI still shows the mnemonic word grid during the challenge, this is only user acknowledgement—not proof that an offline backup was written down.

**FILES:** `src/wam_regtest/bip39_backup_page.py`, `bip39_fusion_gui.py`, `bip39_owner_backend.py`, the command allowlist in `wallet_executor.py` if a new internal command is needed, `tests/test_q06_bip39_backup_ack.py`, `tests/test_q06_bip39_owner_backend.py`, `tests/test_q06_bip39_fusion_gui.py`. **Definition of done:** backend independently denies GUI bypass, existing acknowledgement HMAC remains valid, old profiles remain readable, and Core/WSP pins do not change. **READY TO IMPLEMENT** only after the `challenge_id`/expiry contract is finalized.

## Six NOT VERIFIED areas — evidence to collect, not six confirmed vulnerabilities

| Area | Research or test | Required output | Implementation status |
|---|---|---|---|
| NV-01 Crypto/BIP352/nonce | BIP39 128→512-bit vectors; WSP BIP352/PSBTv2 differential testing against an independent library; malformed point/PSBT parser fuzzing; native secp256k1 hash and nonce review | Vector diffs, redacted seed corpus and crash-free parser statistics | Research; do not replace crypto in this phase |
| NV-02 Dependencies/loader | CycloneDX/SPDX SBOM from *final frozen artifacts* on all three OSs; review native wheels, Qt plugins, OpenSSL, SQLite, DLL/dylib/ELF loader/RPATH and audit-time CVEs with reachability | Per-artifact SBOM, dated software composition analysis and exception ledger | Research; may run separately |
| NV-03 Power-cut/dual rollback | Disposable wallet with fault injection around fsync/CAS/anchors/SQLite; separate physical power-cut lab; rollback both stores while retaining evidence | Crash-state transition map and recovery/refusal proof | High-risk lab; never on a personal machine containing real profiles |
| NV-04 GUI/clipboard | Long/Unicode recipient, clipboard substitution, DPI 100/125/150, accessibility/screen reader, stale modal, amount/fee normalization across OSs | Physical screenshots/test receipts without seed material | Research followed by scoped UX fixes |
| NV-05 Network/privacy | Two-host V19, compromised peer, authorized packet capture, scan of logs/crashes/artifacts for secrets, privacy disclosures | Redacted PCAP metadata and two-host proof | Distinct G6/V19/network review |
| NV-06 Chain/fee/migration | Reorgs at depths 1/12/100; exact-intent fee/dust rules; full-history same-chain restore; separate v0.1.11→v0.1.13 identity migration test | Funds-correctness matrix and approved migration ADR | Research; silent migration forbidden |

## Non-negotiable invariants

1. REGTEST only, `mainnet_allowed=false`, Core RPC restricted to localhost, and manual P2P unchanged; no live mainnet seeds/funds.
2. Preserve original signed Core v0.1.13 member hashes and pinned WSP source; do not silently migrate earlier Core-version wallet profiles or native anchors.
3. `prepare` validates recipient, amount and fee and creates durable reservations; `sign` validates exact commitment plus UTXO/tip; `broadcast` needs separate approval and persists uncertainty **before** network calls.
4. Signing/broadcast timeout or exception must not auto-retry, release signed/uncertain reservations, or adopt an external Core merely based on PID.
5. Retain historic FAIL receipts and `tests/acceptance/issue45.json` until separately supported reconciliation; G6/G7/V19 remain BLOCKED, Q06 `accepted=false`.
6. Preserve the liveness fix using Qt `PaymentApproval.open()`; do not regress to blocking `exec()` in this flow.

## Implementation sequence

**T0 — Repository administration:** consider configuring the `main` H-02 ruleset; review UI changes and do not self-grant bypass.

**T1 — Focused PR A (L-01):** implement the backend challenge contract and tests, limited to 5–7 principal files. Run focused tests → full unit suite → macOS native/frozen → push → three-platform CI. **Do not combine with auto-lock.**

**T2 — Focused PR B (M-07):** update 11 workflows/four Actions; verify SHAs, YAML and three-platform CI. A read-only review of the M-06 design may proceed separately, but there must not be concurrent writers in one workspace.

**T3 — DESIGN ONLY, M-06:** state machine, epoch model, OS event adapters, security review and test matrix before any implementation PR. T1/T2 are not blocked by M-06 design.

**T4 — RESEARCH ONLY, M-01/M-05:** recovery continuity and snapshot compaction, without changing runtime before the design gate PASS. M-02/M-03/M-04 use disposable labs before any implementation roadmap.

**T5 — Independent review NV-01 through NV-06 plus M-08 reproduction:** allocate suitable reviewers/runners, separate defect discovery from repair and retain exact-SHA evidence.

**T6 — H-01 release trust architecture/credentials:** after source hardening stabilizes; final artifacts require a separately controlled publisher trust root. Production signing is not required to continue REGTEST work.

**T7 — Full requalification and G6/G7/V19:** native/frozen at exact commit; physical Mac/Windows/Linux workflows; two actual Core hosts; independent security review; case-by-case Q06 ledger reconciliation. Mainnet promotion is a separate project and decision.

## Scope-control rules

- Use one security finding per focused PR when runtime is affected. Touch only the specified modules instead of rereading or changing the entire repository without a dependency reason.
- Every task scope must include: `exact SHA`, `finding ID`, `allowed files`, `must-preserve invariants`, `focused tests`, `LOCAL-FIRST`, `stop conditions` and `output report`.
- Before editing: inspect Git status, clean working tree, engineering lease, branch and relevant files. Expand file scope only with a documented dependency.
- Fix issues proven by tests; avoid unrelated refactors, arbitrary timeout increases or using CI to debug a reproducible local Mac failure.
- Do not push between local defects. Push only after local gates; macOS unit tests cannot replace Windows/Linux CI.
- For each result, map `finding→code diff→test→source SHA→artifact hash→residual risk` in the engineering handoff. Do not mark complete without evidence.
- Internal self-review is **not independent G7 review**; that requires a qualified separate reviewer and evidence.

## References consulted

- Baseline PR #141: https://github.com/Urriki1502/wam-privacy-wallet-regtest/pull/141
- WAM Fusion audit: `docs/security-audit/WAM_Fusion_Phase_A_Security_Audit_Report_2026-11-06.md`
- Pinned WSP keystore/store: https://github.com/Urriki1502/wam-silent-payments/tree/ac55f13423620252bdbf848c7e8a280c3b84721e/src/wam_sp
- GitHub Rulesets: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
- GitHub Actions secure use: https://docs.github.com/en/actions/reference/security/secure-use
- Apple notarization: https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
- Qt event filters: https://doc.qt.io/qt-6/eventsandfilters.html
- Apple session notifications: https://developer.apple.com/documentation/appkit/nsworkspace/sessiondidresignactivenotification
- Microsoft WTS lock: https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change
- OWASP KDF: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- SQLite WAL and consistency: https://www.sqlite.org/wal.html

**Assessment scope:** viable engineering design decisions, not implemented fixes or a security certification. For DESIGN/RESEARCH GATE findings, the first step is an ADR and evidence rather than changing wallet writers. Never promise absolute security.

