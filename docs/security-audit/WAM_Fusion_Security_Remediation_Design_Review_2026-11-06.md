# WAM Fusion — Independent Remediation Design Review (v1.0)

**Date:** 2026-11-06 (Asia/Ho_Chi_Minh)  
**Objective:** Clarify technical remediation designs prior to implementation; minimize change scope, CI reruns, and custody risk.  
**Repository:** https://github.com/Urriki1502/wam-privacy-wallet-regtest  
**Immutable audit baseline:** PR #141, commit `b187cde17b12ae5f7c11f0611d5f4b1661bfc90b`; base `c61e3c5be4b8519dc6c4d9eb56d124fce84cf02d`; Core v0.1.13; WSP `ac55f13423620252bdbf848c7e8a280c3b84721e`.  
**Findings source:** `WAM_Fusion_Phase_A_Security_Audit_Report_2026-11-06.md` (2 High, 9 Medium, 1 Low; 6 `NOT VERIFIED` groups).  
**Verification level of this document:** Direct source and GitHub configuration inspection at the exact SHA, cross-checked against GitHub, Apple, Qt, Microsoft, SQLite, and OWASP documentation. **No exploit payloads or fuzzers were executed, no exploit was proven, and no owner production host was accessed.** This is a *security design review*, not an independent G7 sign-off or mainnet authorization.

## Decision rules

- **FACT:** Directly observed in inspected source or configuration; **DESIGN:** Selected technical approach; **HYPOTHESIS:** Requires reproduction first; **OPEN:** Requires design decision or additional evidence before code changes.
- **READY TO IMPLEMENT:** Low custody impact with bounded file scope and clear tests. **DESIGN GATE:** Must prove invariants, concurrency, and crash behavior before implementation. **RESEARCH GATE:** Missing empirical data or lab infrastructure.
- Audit High/Medium classifications reflect **projected risk under real-funds use**, not proof of an active exploit or CVE.
- **Prohibited actions:** Enabling mainnet, modifying WSP or Core consensus, deleting or resetting native anchors, removing signed/uncertain reservations, editing the ledger to force PASS, erasing historical failures, running against real wallets or mainnet nodes, force-pushing, merging, or publishing releases.
- **Local-first qualification:** Run source, native macOS, and frozen `.app`/`.dmg` verification locally before pushing and qualifying Windows/Linux/macOS on the exact commit. Three-OS CI does not replace G6/G7/V19.

## Remediation execution matrix

| ID | Summary | Readiness | Optimal immediate action | Definition of Done |
|---|---|---|---|---|
| H-01 | Publisher trust does not cover the Fusion wrapper | RESEARCH/OWNER | Specify signing architecture and lab-test on disposable copies; **do not** self-mint production trust | Independent verification flow and owner-controlled signer/release separation |
| H-02 | `main` unprotected; `rulesets=0` | ADMIN READY | Owner enables `main` branch protection in GitHub UI | Direct/force-push prevention verified via effective rules |
| M-01 | Clean-device/disaster recovery lacks proof | DESIGN GATE | Write ADR, threat model, and fixture tests; do not alter vault writer yet | Proof preserving irreversible state before spend unlock |
| M-02 | Plaintext runtime SQLite while unlocked | RESEARCH GATE | Inventory runtime data, retention, and forensic behavior | Documented leakage threat model and tested mitigations |
| M-03 | RAM secret clearing is best-effort only | RESEARCH GATE | Audit secret lifetimes/copies; do not claim full zeroization | Runtime-bounded mitigations verified by negative tests |
| M-04 | Fixed KDF parameters and weak password acceptance | DESIGN GATE | Benchmark KDF and design password policy; separate versioned format upgrade | Versioned migration and cross-platform fixture PASS |
| M-05 | Checkpoint generation cap (4096 / Linux 10000) | DESIGN GATE | Near-limit stress tests with fixtures only | Crash-safe rotation/compaction preserving reservations |
| M-06 | Missing idle/OS session auto-lock | DESIGN GATE | Complete state-machine and race tests before implementation | No stale approvals; safe locking while worker is in-flight |
| M-07 | GitHub Actions reference mutable tags | READY TO IMPLEMENT | Pin verified full commit SHAs across all 11 workflows | Diff limited to `uses`/permissions; CI unaffected |
| M-08 | Potential RPC slow-trickle hang | REPRODUCE FIRST | Build bounded loopback lab transport fixture | Before/after evidence; never retry financial writes |
| M-09 | Manual P2P peer lacks cryptographic authentication | RESEARCH/NETWORK | Threat model and V19/partition lab; no superficial security claims | P2P test evidence and explicit trust boundary documentation |
| L-01 | Backup verifier accepts <3 positions from GUI | READY AFTER MINI DESIGN | Backend-owned single-use 3-position challenge | 1/2-word, replay, and substitution FAIL; exact 3 PASS |

## H-01 — Publisher integrity of Fusion packages

**FACT:** `scripts/build_macos_bundle.sh` runs `codesign --force --sign - --timestamp=none "$APP"` and documents the app/DMG as ad-hoc and unnotarized. Core v0.1.13 member hashes are verified separately, which **does not** certify that the Fusion wrapper was authorized by a publisher. `docs/SBOM_PREP_HOST.md` lists host dependencies rather than a frozen-artifact SBOM. [Source](https://github.com/Urriki1502/wam-privacy-wallet-regtest/blob/b187cde17b12ae5f7c11f0611d5f4b1661bfc90b/scripts/build_macos_bundle.sh#L90-L104).

**Selected DESIGN:** Separate **secret-free builds** from **owner-controlled signing and release publication**. Generate a manifest covering source SHA, WSP/Core member pins, and post-signing artifact hashes; sign release metadata with an owner-managed key verified against an independently distributed public trust root. macOS: Developer ID + hardened runtime + notarization/stapling *when appropriate certificates are provisioned*. Windows: Authenticode + signer chain and timestamp verification. Linux: detached signature over package/manifest with out-of-band public verification key. The signing workflow must never alter upstream verified Core bytes; explicitly test whether outer app signing interacts with nested `wamd`/`wam-cli` hashes before freezing packaging design.

**Rejected approaches:** Bundling `SHA256SUMS.txt` inside the same ZIP alone; minting keys on a CI runner and calling them publisher keys; rebuilding Core from source solely to simplify signing; inferring Fusion wrapper trust from upstream Core signatures alone.

**Immediate engineering scope:** Author `docs/security-audit/H01_RELEASE_TRUST_ADR.md`, test signing mechanics **on disposable copies** without production keys, and measure Core member hashes before/after. **Do not enable production notarization or releases.** **DoD:** Trust-key distribution procedure, key custody/rotation/revocation policy, offline verification steps, CI-build vs owner-release separation, and SHA256/SBOM/signer output format. **Blocks mainnet release** until completed.  
**Reference:** https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution

## H-02 — GitHub `main` branch ruleset

**FACT:** GitHub API returned `main.protected=false` and `/rulesets=[]` on 2026-11-06. This is a **governance and supply-chain risk**, not a wallet signing bug, and does not block local REGTEST auditing.

**Selected DESIGN (owner action):** Apply a ruleset targeting `main` only; require pull requests; block force-pushes; block branch deletion; grant no bypass to automation tokens. Add required status checks only after reconciling exact check names that actually execute on `main` (workflows vary across manual, PR, and path triggers), selecting GitHub Actions as the expected app where applicable. For a primarily single-maintainer repository, defer mandatory external approval **until an eligible reviewer is assigned**, avoiding self-lockout. Verify via UI and effective rules rather than attempting prohibited pushes.

**Rejected approaches:** Enabling 20 required checks blindly; locking all feature branches; granting broad admin tokens to automation to modify or bypass rulesets. **DoD:** Configuration record, documented bypass actors, and verified rule enforcement. No source changes required; does not disrupt PR #141.  
**Reference:** https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets

## M-01 — Clean-device recovery, lost anchor, and lost journal (highest complexity)

**FACT:** `bip39_recovery_proof.py` intentionally reports `same_chain_only=true`, `clean_device_recovery=false`, `signed_reservations_restored=false`, `signer_allowed=false`, and `broadcast_allowed=false`. `wallet_recovery.py` preserves the native anchor floor and refuses divergent futures; Core `migratewallet` does not transfer Fusion Core identity. [Recovery proof](https://github.com/Urriki1502/wam-privacy-wallet-regtest/blob/b187cde17b12ae5f7c11f0611d5f4b1661bfc90b/src/wam_regtest/bip39_recovery_proof.py#L80-L97).

**Separate three distinct authorities:** (R1) **key identity** derived from 12 words; (R2) **chain-visible wallet state** obtained by scanning the exact chain, genesis, and full UTXO history; (R3) **off-chain irreversible state**, including signed/uncertain transactions, input reservations, and Core/native owner provenance. R1+R2 **do not prove** R3; a signed transaction not yet broadcast may not appear on-chain.

**Research DESIGN (do NOT implement signer unlock yet):**
1. `RECOVERED_READ_ONLY` mode: initialize a **clean new profile** from a test mnemonic, attest genesis and Core identity, and rescan the full chain; allow read-only address/balance/history inspection only; never write to older anchors or profiles.
2. `STATE_CONTINUITY_VERIFIED` mode: require an authenticated backup journal, matching wallet identity, complete signed/uncertain reservation records, and native-authorized migration proof; perform create-only checkpoint publication and crash-safe CAS onto a new anchor; any mismatch falls back to `READ_ONLY`/`BLOCKED`.
3. Total journal loss with keys retained: no automatic mechanism guarantees safe signing recovery in every scenario. Requires an owner- and reviewer-approved policy defining at-risk UTXOs, reconciliation windows/procedures, and warnings regarding unbroadcast signed transactions. Engineering automation must not invent arbitrary timeouts to auto-release locks.

**Mandatory test vectors:** Single lost anchor; lost anchor + ciphertext; stale backup; newer backup; signed-before-crash; broadcast-uncertain; chain partition; same-chain restore; wrong genesis; wrong OS; wrong Core hash; concurrent owner; crash at every write boundary; duplicate transaction; reorg. **Never reset native anchors or retained owner data.**

**Pre-code deliverables:** `M01_RECOVERY_THREAT_MODEL.md`, `M01_RECOVERY_ADR.md`, state/invariant table, migration format proposal, fixture-only two-machine scenarios, and refusal proofs. **DESIGN GATE:** Must pass independent review before modifying any wallet writer. **Never declare M-01 fixed via plain BIP39 rescan alone.**

## M-02 — Plaintext runtime SQLite / privacy surface

**FACT:** Pinned WSP `store.py` stores coins, tweaks, contacts, labels, history, and reservations in unencrypted SQLite with `PRAGMA journal_mode=DELETE` and `synchronous=FULL`; passwords and seeds are not stored in the inspected schema. `bip39_spend_session.lock()` intentionally **retains** the runtime database when signed, uncertain, or faulted state exists for forensic preservation, so unconditional `unlink` is incorrect.

**Two-stage DESIGN:**
- **Empirical lab measurement first:** Populate synthetic history, contacts, and labels; inventory `.db`, `-journal`, swap/crash dump, and OS backup/snapshot exposure (within observable bounds) across macOS APFS, Windows, and Linux. Measure file lifecycle across clean lock, uncertain lock, crash, and restart. Never inspect real seeds.
- **Minimal mitigations:** Minimize unlocked window duration, enforce owner-only permissions, exclude runtime paths from OS backups where supported, minimize PII/retention, redact logs, and exclude runtime files from artifacts/evidence. If threat model requires encryption-at-rest while unlocked, author a separate ADR evaluating SQLCipher/encrypted VFS or in-memory + encrypted snapshot models **with formal consistency proofs**; do not swap the SQLite engine in initial remediation batches.

**Rejected approaches:** Unconditionally unlinking uncertain runtimes; treating `PRAGMA secure_delete` as SSD secure-erase proof; enabling WAL or SQLCipher without verifying WSP schema and rollback compatibility; rewriting all state storage solely to satisfy an audit checklist. **DoD:** Verifiable data-exposure inventory, tested mitigations, and cleanup/fault-retention regressions; any future encryption rollout requires versioned migration and crash tests.

## M-03 — Secret lifetime / RAM exposure

**FACT:** `bip39_12.py` produces immutable `seed: bytes` before copying into a `bytearray`; closing overwrites only the `bytearray`. GUI mnemonic strings, Python scalars, and `_password` create unmanaged copies in interpreter and toolkit memory. "Absolute RAM zeroization in Python" is not provable.

**Selected DESIGN:** Trace every seed and passphrase path through `bip39_12.py`, `bip39_seed_vault.py`, `bip39_owner_backend.py`, `wallet_session.py`, and WSP; eliminate unnecessary `bytes(...).decode()` conversions and shorten plaintext lifetimes; clear GUI seed displays immediately after acknowledgement; prohibit secret logging; disable core dumps in release builds via supported OS mechanisms; minimize diagnostic error detail. Defer dedicated isolated signer processes / locked native memory buffers to a separate milestone because introducing IPC adds a new trust boundary. Current builds must not claim defense against same-UID malware or root compromise.

**Rejected approaches:** Unsafe CPython `str` mutation hacks; patching cryptographic primitives; claiming `mlock` covers all native allocations; removing recovery functionality to shrink memory footprint. **DoD:** Explicit secret-flow diagram, regression tests confirming zero secrets in diagnostics/artifacts/UI post-lock, and documented runtime mitigation boundaries.

## M-04 — Password quality and offline KDF hardening

**FACT:** Pinned WSP `keystore.py` uses AES-GCM with `scrypt(N=2^15, r=8, p=1)`, random salt, purpose/network AAD, and envelope `WAMSP02`; the 12-byte minimum enforces **length**, not entropy. OWASP 2026 guidelines recommend stronger scrypt parameters (e.g., `N=2^17, r=8, p=1` or equivalent cost); guideline updates alone do **not** prove existing envelopes are broken.

**Selected DESIGN:** (1) Evaluate passphrase-friendly password quality checks, common/repetitive password rejection, and NFKD/Unicode normalization; (2) benchmark KDF latency on the lowest-supported macOS, Windows, and Linux hardware for create/unlock/restore; (3) select parameters balancing brute-force cost and UX latency; (4) if raising KDF parameters or adopting Argon2id, introduce a **new versioned envelope/purpose with verified transactional migration** inside reviewed upstream WSP source, supporting conditional dual-read and single-format writes. Never silently patch pinned WSP checkouts or alter `MAGIC` values at runtime.

**Tests:** Legacy envelope read; wrong password; tampered salt/nonce; downgrade attempt; Unicode inputs; short/weak password; excessive-cost input DoS; mid-migration crash; independent Core checksum check. **Rejected approaches:** Search-and-replace bumping of `N`; silent re-encryption of existing profiles; allowing weak passwords without bounds for future mainnet use. **DoD:** Measured benchmarks, versioned envelope ADR, accepted CPU/memory bounds, and fail-closed fallback denial.  
**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## M-05 — Checkpoint and journal generation limits

**FACT:** Q06 scanner checkpoints cap at `MAX_CHECKPOINT_GENERATIONS=4096`; Linux root-witness reads cap at 10,000 `.anchor` files and verify contiguous generations. This is a documented long-term availability ceiling, not direct key loss.

**Selected DESIGN:** Phase 1: add read-only metrics/early warnings (e.g., 80%/90% thresholds) and near-limit fixture stress tests to measure size, latency, and daily write rates. Phase 2: write an ADR for **CAS-protected epoch compaction** featuring an authenticated summary proving complete state, preserving signed/uncertain reservations, journaling transitions before any deletion, and requiring native witness/owner attestation; power-cut injection before/after every `fsync` and anchor advance must yield either verified state or fail-closed refusal. Crash logic must pass review before implementation.

**Rejected approaches:** Arbitrarily raising 4096/10000 limits; resetting generation counters to 1; deleting `.anchor`/snapshot files; weakening contiguity checks. **DoD:** Near-cap and over-cap fixtures, steady-state endurance tests, and cross-platform fault injection with zero irreversible state loss. Until verified, retain fail-closed limits and document them explicitly.

## M-06 — Idle and OS session auto-lock architecture

**FACT:** Q06 GUI supports manual Lock only; the executor runs one operation in-flight; `wallet_executor.request()` timeout **does not cancel** an active operation; `PaymentApproval.open()` is asynchronous and may remain pending; no idle timer or OS session-lock hook currently feeds this path. `wallet_session.lock()` and `bip39_spend_session.lock()` preserve uncertain state; naive timer-driven `lock` calls can be rejected while the worker is busy.

**Proposed DESIGN: Authorization-epoch state machine with two lock layers.**
- `UNLOCKED(epoch=N)` receiving an idle or OS-lock trigger transitions **synchronously** to `LOCK_REQUESTED(epoch=N+1)` at the GUI/security gate, immediately invalidating open modal approvals, clearing/masking displayed UI state, and blocking new consent. UI clearing alone is never treated as proof of backend lock completion.
- Backend `sign`/`broadcast` receives *current epoch + commitment* and validates under the serialized owner boundary immediately before the **irreversible point**. If `LOCK_REQUESTED` linearizes before authorization, refuse. If user approval and native Sign/Broadcast **already started**, never kill, cancel, or retry; allow completion or preserve uncertain state, then finalize session lock under the owner executor.
- When idle/OS lock fires while the worker is busy, record the lock request in an independent synchronized flag/state (rather than relying solely on `executor.submit('lock')`, which may be denied), queue controlled closure behind the active worker, and keep UI in deny state until `LOCKED`/`FAULTED`. **Never allow Sign/Broadcast to consume an approval created in a prior epoch.**
- Unlock requires password + original Core/native anchor attestation; OS unlock never auto-unlocks the wallet; signed/uncertain reservations are never cleared. Application restarts in the locked state.
- **Proposed UX defaults (pending sign-off):** 5-minute default idle timeout with 1/5/15-minute options; immediate lock on OS session lock/suspend. Activity resets only on genuine user interaction within the application, not timers, sync loops, or network events. If an OS lacks reliable native lock notifications, document the limitation rather than faking PASS.

**Event sources:** Qt `QApplication.installEventFilter()` for keyboard/mouse; macOS `NSWorkspace` active-session/sleep notifications; Windows `WM_WTSSESSION_CHANGE` session registration; Linux `systemd-logind` `LockedHint` / desktop-specific signals verified per environment. A Qt event filter alone is **not** equivalent to OS screen lock.

**Pre-PR tests:** Idle countdown, keyboard/mouse activity, open modal invalidation, approve-during-show race, timer firing right as Prepare completes, sign-in-flight, broadcast-uncertain, worker timeout, OS lock/wake, hidden window, missed lock event, unresponsive GUI, Core disconnect, multi-window, quit/restart, and cross-platform native/frozen runs. **Never mark CI PASS via synthetic OS events without separate native observation.**

**Mandatory pre-implementation deliverable:** `M06_AUTOLOCK_ADR.md`, state-transition table, OS lock adapters, and negative test skeleton — **must pass review before implementation**. **Rejected approaches:** Timer calling `_command('lock')` alone; killing the executor; canceling signed transactions; auto-unlocking on OS wake.  
**References:** https://doc.qt.io/qt-6/eventsandfilters.html ; https://developer.apple.com/documentation/appkit/nsworkspace/sessiondidresignactivenotification ; https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change

## M-07 — Pin GitHub Actions to immutable SHAs

**FACT (verified across all 11 `.github/workflows/` files):** External `uses:` entries reference **4 Actions**: `actions/checkout@v4`, `actions/setup-python@v5`, `actions/upload-artifact@v4`, and `actions/download-artifact@v4`. Most jobs declare `permissions: contents: read`; some require `actions: read`.

**READY DESIGN:** Resolve full immutable commit SHAs **from each official upstream Action repository**, verifying the corresponding release tag and repository owner; replace mutable tags across all 11 workflow YAML files while keeping human-readable version comments; verify zero mutable `uses:` entries remain; enforce least-privilege job permissions; ensure fork PRs receive no release secrets; validate YAML syntax and execute existing workflows.

**Rejected approaches:** Copying SHAs from unverified third-party sources; switching to unpinned `latest` tags; broadening token write permissions to bypass failures; rewriting CI pipelines in a way that invalidates historical evidence. **DoD:** Zero mutable `uses:` entries remaining, documented SHA provenance, YAML parse PASS, tests unaffected, and consistent artifacts.  
**Reference:** https://docs.github.com/en/actions/reference/security/secure-use

## M-08 — Transport liveness (reproduce before patching)

**FACT:** `json_rpc.py` enforces an HTTP response size cap, `response.read(cap+1)`, and socket timeout, but lacks an **overall wall-clock deadline** across an entire response stream; `wallet_executor.py` preserves pending operations on caller timeout, matching the no-retry policy for financial writes. **HYPOTHESIS:** A slow-trickle peer or Core process sending bytes just inside each socket timeout could stall the executor or lock path.

**Reproduction design:** Create a bounded loopback lab fixture emitting chunks just before each socket timeout until total elapsed time exceeds the budget; measure wall-clock duration, resource consumption, state transitions, GUI refusal behavior, and original-Core binding. The simulated transport is **strictly for reproduction**; qualification still requires genuine Core. If reproduced, add an absolute monotonic deadline and bounded stream read *at the transport read layer only*, without interrupting or retrying write paths, while keeping operations pending whenever uncertainty exists. Whether genuine Core can trigger this condition remains a separate question.

**Rejected approaches:** Raising timeouts to 240/600/900s to mask stalls; killing or canceling workers on timeout; retrying RPC write calls. **DoD:** Deterministic before/after slow-trickle regression test, genuine Core unaffected, safe eventual UI lock, and accurate state reporting.

## M-09 — Peer trust, P2P, and future mainnet discovery

**FACT:** `shared_regtest.py` checks IP/port, handshake version/subversion, and peer limits; it does not bind remote peers to cryptographic channel identities. This is an intentional manual REGTEST policy, **not** evidence that a remote peer can control Core RPC or sign wallet transactions. BIP352 does not provide IP-level anonymity.

**REGTEST DESIGN:** Preserve manual P2P for V19; run actual two-host tests covering wrong genesis, spoofed peer, network partition, stale chain, fork/reorg, unexpected peers, self-peering, inbound/outbound connectivity, localhost-only RPC enforcement, and preservation of signed/uncertain state. Peer host trust is operator-selected; version strings are not identity proofs.

**Future MAINNET DESIGN (out of scope for current PR):** Rely on Core v0.1.13 native peer discovery and chain validation, evaluating eclipse resistance, peer diversity, and transport privacy (e.g., Tor) under a separate security review. Never invent a Fusion UI peer-trust layer claiming to protect Core TCP without genuine cryptographic channel binding. **DoD:** Physical V19 two-host evidence, documented network threat model, and explicit privacy boundaries; never enable automatic peer discovery in REGTEST.

## L-01 — Backup 3-word challenge enforcement

**FACT:** `bip39_backup_page.py` (GUI) calls `random.sample(range(1, 13), 3)` and submits both **positions and answers** to `backup_verify`. `bip39_owner_backend.py:665-700` accepts any non-empty subset of 1–12 distinct positions, allowing a single correct word to write an acknowledged HMAC. Backend MAC authentication already exists; the gap is **challenge generation and binding**, not BIP39 checksum validation.

**Selected DESIGN:** Move challenge generation into `Bip39ReadOnlyBackend`, selecting exactly **3 distinct positions** using CSPRNG `secrets.SystemRandom().sample(...)` and storing them inside the *in-memory owner session* with an opaque `challenge_id`, profile/seed identifier, session epoch, expiry (proposed 120 seconds), and single-use consumed/invalidated flag. The GUI only requests a challenge and displays the 3 positions; submission sends **only `challenge_id` + 3 answers** (never caller-chosen positions). The backend verifies active challenge, exact count of 3, unused/unexpired status, matching profile/epoch, and expected words, **consuming** the challenge once before writing the acknowledgement. Cancel, lock, restart, seed change, wrong answer, or timeout invalidates the challenge; the UI may request a fresh challenge without revealing correct words. Never persist challenges or mnemonics. Retain the existing HMAC/sidecar envelope unless tests uncover an independent defect.

**Tests:** Exact 3 correct PASS; 1 or 2 positions FAIL; altered positions FAIL; answer replay FAIL; stale `challenge_id` FAIL; wrong wallet FAIL; expired challenge FAIL; lock/reopen FAIL; wrong word FAIL; concurrent submissions for the same challenge allow at most one success; deferred backup obtains a fresh challenge; zero seed/password leakage in errors/logs; genuine frozen Qt flow PASS. **Note:** While the mnemonic remains visible in the UI during the challenge flow, this remains a UX acknowledgement rather than cryptographic proof of offline paper backup.

**Files:** `src/wam_regtest/bip39_backup_page.py`, `bip39_fusion_gui.py`, `bip39_owner_backend.py`, command allowlist in `wallet_executor.py` if an internal command is added, `tests/test_q06_bip39_backup_ack.py`, `tests/test_q06_bip39_owner_backend.py`, `tests/test_q06_bip39_fusion_gui.py`. **DoD:** Backend alone rejects bypasses independently of the GUI, original HMAC remains valid, legacy profile reading is unchanged, and Core/WSP pins remain untouched. **READY TO IMPLEMENT** once the `challenge_id`/expiry contract is finalized.

## Six `NOT VERIFIED` surfaces (evidence gaps, NOT confirmed vulnerabilities)

| ID | Required research / verification | Mandatory output | Implementation status |
|---|---|---|---|
| NV-01 Crypto / BIP352 / nonce | BIP39 128→512-bit vectors, WSP BIP352/PSBTv2 differential tests against independent libraries, malformed point/PSBT parser fuzzing, native secp256k1 hash and nonce audit | Vector diffs + redacted seed corpus + crash-free parser stats | Research; no crypto changes in initial batch |
| NV-02 Dependencies / loader | CycloneDX/SPDX SBOM from *final frozen artifacts* across 3 OSes; audit native wheels, Qt plugins, OpenSSL, SQLite, DLL/dylib/ELF loader/RPATH, point-in-time CVEs, and reachability | Per-artifact SBOM + dated SCA + exception ledger | Research; executable in parallel |
| NV-03 Power-cut / dual rollback | Disposable wallet + fault injection across `fsync`/CAS/anchor/SQLite, separate physical power-cut lab, dual-store rollback, and evidence retention | Crash-state transition map + recovery/refusal proof | High-risk lab; never on owner production host |
| NV-04 GUI / clipboard | Long/Unicode recipients, clipboard substitution, 100/125/150% DPI, accessibility/screen reader, stale modal handling, amount/fee normalization across OSes | Physical screenshots/receipts with zero secrets | Research followed by scoped UX fixes |
| NV-05 Network / privacy | Two-host V19, compromised peer scenarios, authorized packet capture, secret scanning of logs/crashes/artifacts, privacy disclosure | Redacted PCAP metadata + two-host proof | G6/V19 + dedicated network review |
| NV-06 Chain / fee / migration | 1/12/100-block reorgs, exact-intent fee/dust policy, full-history same-chain restore, *separate* v0.1.11→v0.1.13 identity migration tests | Funds-correctness matrix + owner-approved migration ADR | Research; silent migration prohibited |

## Non-negotiable invariants (must remain unchanged)

1. `REGTEST` only, `mainnet_allowed=false`, localhost-only Core RPC, and manual P2P policy remain unchanged; no live mainnet seeds or funds.
2. Official signed Core v0.1.13 member hashes and pinned WSP source remain unchanged; legacy Core/version profiles and native anchors are never auto-migrated.
3. `prepare` validates recipient/amount/fee and persists a durable reservation; `sign` validates exact commitment and UTXO/tip state; `broadcast` requires separate approval and persists uncertain state BEFORE the network call.
4. Timeouts or exceptions during sign/broadcast never trigger automatic retry, never release signed/uncertain reservations, and never adopt Core/owners by PID.
5. Historical FAIL receipts and `tests/acceptance/issue45.json` remain unmodified pending case-specific owner decisions; G6/G7/V19 remain blocked and Q06 remains `accepted=false`.
6. The Qt `PaymentApproval.open()` non-blocking liveness fix is preserved; do not revert to blocking `exec()` on this path.

## Recommended remediation sequence

- **T0 — Repository administration (H-02):** Owner configures the `main` branch ruleset and verifies effective rule enforcement without granting automation bypass rights.
- **T1 — Scoped PR A (L-01):** Implement backend challenge contract and negative regression tests across bounded files; run focused tests → full unit suite → local macOS native/frozen qualification → push → 3-OS CI. **Keep separate from auto-lock work.**
- **T2 — Scoped PR B (M-07):** Pin all 4 external Actions to verified immutable commit SHAs across all 11 workflows; validate YAML and run 3-OS CI.
- **T3 — Design gate (M-06):** Complete `M06_AUTOLOCK_ADR.md`, epoch state machine, OS adapters, and race test matrix for security review before writing implementation code.
- **T4 — Research gate (M-01 / M-05 / M-02 / M-03 / M-04):** Produce ADRs, threat models, and disposable-lab measurements prior to any runtime wallet writer changes.
- **T5 — Independent verification (NV-01 through NV-06 + M-08 reproduction):** Separate discovery from remediation and retain exact-SHA evidence.
- **T6 — Release trust architecture (H-01):** Establish owner-controlled signing root and verification procedures once source hardening stabilizes.
- **T7 — Full requalification and external gates (G6 / G7 / V19):** Exact-commit native and frozen qualification across macOS, Windows, and Linux, physical two-host V19 verification, independent security review, and case-by-case ledger reconciliation. Mainnet promotion remains a separate future decision.

## Engineering change-control discipline

- Scope runtime fixes to **one finding per PR**, restricting edits to justified files and preserving all non-negotiable invariants.
- Verify clean Git status, active branch/SHA, and the engineering lease before modifying source.
- Prove failing negative regressions before applying fixes where applicable; never mask failures by inflating timeouts or using remote CI to debug locally reproducible macOS issues.
- Pass local focused, unit, and macOS native/frozen gates before pushing; never treat macOS unit tests as substitutes for native Windows or Linux CI.
- Map every remediation change cleanly from `finding → code diff → regression test → exact source SHA → artifact digest → residual risk`.
- Self-review by the implementing engineer never qualifies as **independent G7 review**; independent verification requires a separate qualified reviewer and independent evidence.

## Verified references

- Baseline PR #141: https://github.com/Urriki1502/wam-privacy-wallet-regtest/pull/141
- WAM Fusion audit report: `docs/security-audit/WAM_Fusion_Phase_A_Security_Audit_Report_2026-11-06.md`
- Pinned WSP keystore/store: https://github.com/Urriki1502/wam-silent-payments/tree/ac55f13423620252bdbf848c7e8a280c3b84721e/src/wam_sp
- GitHub Rulesets: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
- GitHub Actions security hardening: https://docs.github.com/en/actions/reference/security/secure-use
- Apple notarization: https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
- Qt event filters: https://doc.qt.io/qt-6/eventsandfilters.html
- Apple session notifications: https://developer.apple.com/documentation/appkit/nsworkspace/sessiondidresignactivenotification
- Microsoft WTS session notifications: https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- SQLite WAL and consistency context: https://www.sqlite.org/wal.html

**Review scope note:** This document records feasible remediation designs rather than completed fixes or security certification. For items marked `DESIGN GATE` or `RESEARCH GATE`, ADRs and empirical lab evidence are required before implementing wallet writers. No claim of absolute security is made.
