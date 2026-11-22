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

## M-05 — Checkpoint/journal generation limits

**FACT:** Q06 scanner checkpoint `MAX_CHECKPOINT_GENERATIONS=4096`; Linux root-witness read giới hạn 10.000 `.anchor` và kiểm tra các generations liên tiếp. Đây là giới hạn availability dài hạn có căn cứ; không phải bằng chứng mất khóa trực tiếp.

**DESIGN:** Phase 1: readonly metrics/cảnh báo sớm (ví dụ 80/90% cap) và fixture stress sát ngưỡng; định lượng kích thước, độ trễ, write rate/ngày. Phase 2 ADR cho **epoch/compaction dưới CAS**: có authenticated summary mới chứng minh đầy đủ state, giữ reservation signed/uncertain, transition được journal trước khi xóa bất cứ gì, native witness/chứng thực chủ sở hữu; crash-cut trước/sau mỗi fsync/anchor advance đều trả về trạng thái xác minh được hoặc từ chối. Cần review logic crash trước implementation.

**Reject:** tăng số 4096/10000 tùy tiện; reset counter về 1; xóa file `.anchor`/snapshot; bỏ no-gap check. **DoD:** fixture đến/quá cap + steady-state long-run + failure injection cross-platform; no irreversible state loss. Nếu chưa đạt, giữ fail-closed và báo giới hạn.

## M-06 — Auto-lock/OS session lock: chốt kiến trúc trước khi viết GUI

**FACT:** GUI Q06 chỉ có manual Lock; executor một thao tác in-flight; `wallet_executor.request()` timeout **không hủy operation**; `PaymentApproval.open()` async và dialog có thể chờ; không có timeout/OS lock ở đường này. `wallet_session.lock()` và `bip39_spend_session.lock()` có logic bảo toàn uncertain; gọi `lock` từ timer khi worker busy có thể bị từ chối.

**DESIGN đề xuất: máy trạng thái có _authorization epoch_ và hai lớp khóa.**
- `UNLOCKED(epoch=N)` -> nhận idle/OS lock -> **đồng bộ** `LOCK_REQUESTED(epoch=N+1)` tại GUI/security gate; ngay lập tức vô hiệu các modal approvals, xóa/che dữ liệu UI, không cấp consent mới. Không dùng việc xóa UI như bằng chứng backend đã khóa.
- Backend sign/broadcast nhận *current epoch + commitment*; validate dưới serialized owner boundary ngay trước **điểm không thể đảo ngược**. Nếu lock request đến trước authorization linearization -> refuse. Nếu user đã approve và native Sign/Broadcast **thật sự bắt đầu** trước đó, không kill/cancel/retry; thao tác hoàn tất hoặc giữ uncertain, rồi khóa session dưới owner executor.
- Khi idle/OS event xảy ra lúc worker busy, request lock được ghi theo state/flag độc lập được đồng bộ (không chỉ `executor.submit('lock')` có thể bị từ chối); một lệnh close được hàng đợi một cách có kiểm soát sau worker, và UI tiếp tục deny cho đến khi state `LOCKED`/`FAULTED`. **Không cho phép Sign/Broadcast sử dụng một approval còn sống từ epoch trước**.
- Unlock bắt buộc password + original Core/native anchor attestation; không dùng OS unlock tự unlock ví; không giải phóng signed/uncertain reservation. Khởi động lại app ở trạng thái locked.
- **Giá trị thiết kế đề xuất, chưa chốt UX:** default idle 5 phút, các lựa chọn 1/5/15 phút; OS session lock/suspend -> lock ngay. Sự kiện hoạt động là thao tác người dùng thực trong app, không phải timer/sync/network activity tự gia hạn. Nếu không nhận được native OS event đáng tin trên một OS, đánh dấu giới hạn thay vì giả PASS.

**Nguồn event:** Qt `QApplication.installEventFilter()` cho keyboard/mouse; macOS `NSWorkspace` active-session/sleep notifications; Windows `WM_WTSSESSION_CHANGE` + đăng ký notification; Linux systemd-logind session `LockedHint`/desktop-specific signal cần xác thực cơ chế trên từng desktop. Qt event filter một mình **không** tương đương OS screen lock.

**Tests trước PR:** countdown/idle, keyboard/mouse, modal đang mở, approve-during-show race, timer đúng lúc Prepare complete, sign-in-flight, broadcast-uncertain, worker timeout, OS lock/wake, GUI hidden, lost lock event, GUI unresponsive, Core disconnect, 2 windows, quit/restart, cross-platform native/frozen. **Không chốt CI PASS bằng synthetic OS event nếu chưa có native observation riêng.**

**Output B1B bắt buộc:** `M06_AUTOLOCK_ADR.md` + state-transition table + lock event adapters + negative tests skeleton; **review rồi mới triển khai**. **Reject:** timer chỉ gọi `_command('lock')`; kill executor; cancel signed tx; auto-unlock theo OS.  
**Tham khảo:** https://doc.qt.io/qt-6/eventsandfilters.html ; https://developer.apple.com/documentation/appkit/nsworkspace/sessiondidresignactivenotification ; https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change

## M-07 — Pin CI Actions, nhỏ và rõ

**FACT được kiểm tra ở 11 workflow `.github/workflows/`:** các `uses:` bên ngoài được thấy thuộc **4 Actions**: `actions/checkout@v4`, `actions/setup-python@v5`, `actions/upload-artifact@v4`, `actions/download-artifact@v4`. Đa số job đã khai báo `permissions: contents: read`; một số cần `actions: read`.

**DESIGN READY:** lấy immutable full commit SHA **từ chính repository phát hành Action**, kiểm tra release/tag tương ứng và hash/owner; thay `uses` tương ứng trong cả 11 YAML, giữ comment phiên bản; kiểm tra toàn bộ `uses:` không sót; quyền token theo job tối thiểu; PR từ fork không được cấp release secrets; validate YAML và chạy workflow hiện hữu. GitHub Actions dependency lockfile hiện là phương án mạnh hơn nếu project hỗ trợ; không cần đưa thêm tooling vào B1 nếu chỉ để nâng security đơn giản.

**Không chọn:** sao chép SHA từ blog/ngẫu nhiên; chuyển sang latest tag không pin; thay token quyền write rộng để khắc phục workflow failure; viết lại toàn bộ CI làm mất evidence. **DoD:** no mutable `uses:` left, provenance of every selected SHA, workflow parse PASS, tests unaffected, artifact compare.  
**Tham khảo:** https://docs.github.com/en/actions/reference/security/secure-use

## M-08 — Transport liveness: chưa được phép sửa khi chưa tái hiện

**FACT:** `json_rpc.py` có HTTP response size cap; `response.read(cap+1)` và socket timeout, nhưng không có **wall-clock absolute deadline** cho cả stream; `wallet_executor.py` giữ pending khi caller timeout, đúng chính sách không retry financial writes. **HYPOTHESIS:** peer/Core bị chậm dần từng chunk có thể trì hoãn executor/lock.

**Thiết kế thử:** tạo fixture loopback chỉ trả chunks đều đặn trước mỗi socket timeout nhưng tổng thời gian vượt ngân sách; đo wall-clock, resource, state, GUI refusal và original-core binding. Lab riêng dùng transport giả **chỉ để tái hiện**; nghiệm thu vẫn yêu cầu genuine Core. Nếu tái hiện, đưa absolute monotonic deadline và bounded read worker *chỉ ở transport read*, không ngắt/retry write path; vẫn preserve original operation pending nếu có uncertainty. Phân loại Core thật có thể gây lỗi này không là câu hỏi khác.

**Reject:** tăng timeout 240/600/900 để che; tự cancel/kill worker khi timeout; tự gửi lại RPC write. **DoD:** deterministic before/after slow-trickle regression; native Core unaffected; UI lock eventually safe and states accurately reported.

## M-09 — Peer trust/P2P/mainnet

**FACT:** `shared_regtest.py` chỉ kiểm tra địa chỉ IP/port, handshake version/subversion và giới hạn peers; không có channel binding cryptographic identity cho remote peer. Đây là cơ chế REGTEST manual được xác định trước, **không** phải bằng chứng peer có thể điều khiển Core RPC hoặc ký ví. BIP352 không ẩn danh IP.

**DESIGN REGTEST:** giữ manual P2P cho V19; actual two-host setup test: peer sai genesis, peer giả, partition, stale chain, fork/reorg, unexpected peers, self-peer, inbound/outbound, RPC vẫn loopback; kiểm tra bảo toàn signed/uncertain. Peer host trust được người vận hành chọn; chỉ version string không là identity proof.

**DESIGN MAINNET (tương lai, ngoài PR):** dùng Core v0.1.13 native peer discovery/chain validation, nghiên cứu eclipse resistance, peer diversity, transport privacy/Tor nếu hỗ trợ/được review. Không phát minh lớp xác thực peer trong Fusion UI rồi tuyên bố bảo vệ underlying Core TCP nếu chưa có crypto-binding thực sự. **DoD:** V19 actual physical evidence + network threat model và rõ giới hạn privacy; không tự bật auto-discovery trong REGTEST hiện tại.

## L-01 — Backup 3-word challenge: cụ thể hóa cơ chế đủ để code

**FACT:** `bip39_backup_page.py` (GUI) gọi `random.sample(range(1,13),3)` và chuyển **positions và answers** vào `backup_verify`. `bip39_owner_backend.py:665-700` cho phép positions không rỗng (1–12 distinct), nên một từ chính xác cũng có thể viết acknowledged HMAC. Backend đã có MAC cho acknowledgement; hạn chế nằm ở **quyền tạo/kiểm soát challenge**, không ở BIP39 checksum.

**DESIGN đã chọn:** chuyển quyền tạo challenge sang `Bip39ReadOnlyBackend`, sinh đúng **3 vị trí khác nhau** bằng CSPRNG `secrets.SystemRandom().sample(...)`, giữ trong *memory owner session* với `challenge_id` opaque, profile/seed identifier, session epoch, expiry (đề xuất 120 giây), used/invalidated bit. GUI chỉ yêu cầu challenge và hiển thị 3 positions; submission **không gửi positions tự chọn**, chỉ `challenge_id + 3 answers`. Backend xác minh current challenge, exact 3, chưa dùng/chưa hết hạn/đúng profile/epoch, so sánh expected phrases, và **consume** challenge một lần trước khi ghi ack. Cancel, lock, restart, seed change, wrong answer hoặc timeout invalidates; UI có thể yêu cầu challenge mới, không tự tiết lộ từ đúng. Không persist challenge hoặc mnemonic. Giữ HMAC/sidecar envelope hiện hữu, trừ khi test phát hiện vấn đề độc lập.

**Test:** exact 3 correct PASS; 1/2 vị trí FAIL; altered positions FAIL; answer replay FAIL; old id FAIL; wrong wallet FAIL; expired FAIL; lock/reopen FAIL; wrong word FAIL; same-challenge simultaneous requests => only one success; deferred backup obtains fresh challenge; no seed/password in error/log; genuine frozen Qt flow vẫn PASS. **Lưu ý** GUI trước giờ hiển thị word grid, nên nếu vẫn còn mnemonic trong UI khi challenge chạy, không gọi nó là proof người dùng đã viết ra giấy; đây là UX acknowledgement, không chứng minh backup offline tồn tại.

**Files:** `src/wam_regtest/bip39_backup_page.py`, `bip39_fusion_gui.py`, `bip39_owner_backend.py`, command allowlist trong `wallet_executor.py` nếu thêm RPC nội bộ, `tests/test_q06_bip39_backup_ack.py`, `tests/test_q06_bip39_owner_backend.py`, `tests/test_q06_bip39_fusion_gui.py`. **DoD:** backend alone denies bypass (independent of GUI), original HMAC still valid, old profile reading unchanged, no altered Core/WSP pins. **READY TO IMPLEMENT** sau khi cố định contract của `challenge_id`/expiry.

## Sáu NOT VERIFIED — đây là chứng cứ cần thu thập, KHÔNG phải sáu lỗ hổng đã kết luận

| NV | Nghiên cứu/thử nghiệm cụ thể | Output bắt buộc | Trạng thái triển khai |
|---|---|---|---|
| NV-01 Crypto/BIP352/nonce | BIP39 128→512-bit vectors, WSP BIP352/PSBTv2 differential tests với thư viện độc lập, malformed points/PSBT parser fuzz, native secp256k1 hash + nonce code audit | vector diff + seed corpus redacted + crash-free parser stats | Research; không thay crypto trong B1 |
| NV-02 Dependencies/loader | SBOM CycloneDX/SPDX từ *final frozen artifacts* trên 3 OS; kiểm tra wheel native, Qt plugins, OpenSSL, SQLite, DLL/dylib/ELF loader/RPATH và CVE thời điểm audit + reachability | per-artifact SBOM + dated SCA + exception ledger | Research; có thể chạy song song |
| NV-03 Power-cut/dual rollback | Disposable wallet + fault injection theo fsync/CAS/anchor/SQLite, separate physical power-cut lab, rollback both stores and evidence retention | crash-state transition map + recovery/refusal proof | High-risk lab; không trên máy chủ sở hữu |
| NV-04 GUI/clipboard | Recipient dài/Unicode, clipboard substitution, DPI 100/125/150, accessibility/screen reader, stale modal, amount/fee normalization across OS | physical screenshot/test receipts không chứa seed | Research then UX fixes |
| NV-05 Network/privacy | Hai host V19, peer compromise, packet capture có phép, log/crash/artifact secret scan, privacy disclosure | redacted PCAP metadata + 2-host proof | G6/V19 + network review riêng |
| NV-06 Chain/fee/migration | Reorg 1/12/100, fee/dust exact-intent policy, full-history same-chain restore, *separate* v0.1.11→v0.1.13 identity migration test | funds-correctness matrix + owner-approved migration ADR | Research; cấm silent migration |

## Điều kiện giữ nguyên (không được đổi để sửa lỗi)

1. `REGTEST` only, `mainnet_allowed=false`, localhost-only Core RPC, manual P2P unchanged; no live mainnet seeds/funds.
2. Core signed v0.1.13 original member hashes and WSP source pin remain unchanged; wallet profile old Core/version + native anchors không tự migrate.
3. `prepare` validates recipient/amount/fee, durable reservation; `sign` validates exact commitment and UTXO/tip; `broadcast` requires distinct approval and persists uncertain BEFORE network call.
4. Timeout/exception from sign/broadcast không tự retry, không tự release signed/uncertain, không adopt Core/owner bằng PID.
5. Existing historical FAIL receipts and `tests/acceptance/issue45.json` kept as-is pending evidence-specific owner decision; G6/G7/V19 blocked, Q06 `accepted=false`.
6. Qt dialog `PaymentApproval.open()` liveness fix preserved; no return to blocking `exec()` for this flow.

## Thứ tự triển khai

**T0 — Quản trị repository:** cấu hình Ruleset `main` cho H-02 nếu muốn bảo vệ sớm; review thay đổi UI, không tự cấp bypass.

**T1 — Focused PR A (L-01):** làm backend challenge contract + tests; chỉ 5–7 file chính; local focused tests ⇒ toàn bộ unit ⇒ macOS native/frozen ⇒ push ⇒ 3-OS CI. **Không đồng thời auto-lock.**

**T2 — Focused PR B (M-07):** sửa 11 workflow / bốn Actions, kiểm chứng SHAs và YAML + 3-OS CI; có thể song song chuẩn bị design M06 bằng reviewer chỉ-đọc, nhưng không concurrent writer cùng worktree.

**T3 — DESIGN ONLY M06:** ADR state machine/epoch/OS adapters; security review và test matrix rồi mới implementation PR. T1/T2 không cần chờ M06.

**T4 — RESEARCH ONLY M01/M05:** custodial recovery và snapshot compaction; không sửa runtime cho đến khi design gate PASS. M02/M03/M04 thí nghiệm trên disposable lab, sau đó mới roadmap implementation.

**T5 — Independent audit NV-01/02/03/04/05/06 + M08 reproduction:** phân công người/runner; tách tìm lỗi và sửa lỗi; giữ bằng chứng exact SHA.

**T6 — H01 release architecture/owner credentials:** chỉ sau khi source/hardening ổn định; ký final artifacts phải có owner-controlled trust root. Không cần ký production gấp để tiếp tục REGTEST.

**T7 — Full requalification + G6/G7/V19:** native/frozen exact commit, human Mac/Windows/Linux, 2 actual Core hosts, independent security reviewer, Q06 ledger reconcile đúng từng case. Mainnet promotion là một dự án/quyết định khác.

## Quy tắc giới hạn phạm vi thay đổi

- Giao **một finding/một PR** khi ảnh hưởng runtime; chỉ những module được chỉ định, không đọc lại 500 file repo sau khi handoff đã có source + invariant + test targets.
- Phạm vi mỗi nhiệm vụ có đủ: `exact SHA`, `finding ID`, `allowed files`, `must-preserve invariants`, `focused tests`, `LOCAL-FIRST`, `stop conditions`, `output report`.
- Trước khi viết: kiểm tra `git status`, clean worktree, engineering lease, đúng branch, đọc *tối đa* các file trong phạm vi; chỉ mở rộng khi ghi lý do phụ thuộc cụ thể.
- Sửa theo test chứng minh lỗi, không tái cấu trúc vô cớ, không tăng timeout tùy tiện, không dùng CI để debug lỗi có thể tái hiện Mac local.
- Không push giữa các lỗi local; push sau local gate; CI Windows/Linux không thể được thay bằng macOS unit tests.
- Mỗi kết quả tạo mapping `finding→code diff→test→source SHA→artifact hash→residual risk` trong `ENGINEERING_HANDOFF.md`, không claim done nếu lacks proof.
- Không dùng thuật ngữ **independent G7 review** cho việc tự review code của nhóm thực hiện; cần người khác có năng lực và chứng cứ riêng.

## Tài liệu tham chiếu đã đối chiếu

- Baseline PR #141: https://github.com/Urriki1502/wam-privacy-wallet-regtest/pull/141
- WAM Fusion audit: `docs/security-audit/WAM_Fusion_Phase_A_Security_Audit_Report_2026-11-06.md`
- WSP pinned keystore/store: https://github.com/Urriki1502/wam-silent-payments/tree/ac55f13423620252bdbf848c7e8a280c3b84721e/src/wam_sp
- GitHub Rulesets: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
- GitHub Actions secure use: https://docs.github.com/en/actions/reference/security/secure-use
- Apple notarization: https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
- Qt event filters: https://doc.qt.io/qt-6/eventsandfilters.html
- Apple session notification: https://developer.apple.com/documentation/appkit/nsworkspace/sessiondidresignactivenotification
- Microsoft WTS lock: https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change
- OWASP KDF: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- SQLite WAL/consistency context: https://www.sqlite.org/wal.html

**Phạm vi đánh giá:** quyết định thiết kế khả thi, không phải kết quả fix hoặc security certification. Với các mục đánh dấu DESIGN/RESEARCH GATE, bước đầu tiên là tạo bằng chứng/ADR chứ không triển khai writer. Tuyệt đối không hứa 'an toàn tuyệt đối'.
