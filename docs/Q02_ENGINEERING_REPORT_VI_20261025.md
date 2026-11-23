# Q02 Technical Engineering Report — Issue #45 Core Authentication & Signed CLI Fail-Closed

> **Note:** English translation of the historical 2026-10-25 Q02 engineering report. The original filename (`Q02_ENGINEERING_REPORT_VI_20261025.md`) is preserved for link and audit-trail stability. All commit SHAs, workflow IDs, artifact digests, and gate verdicts remain unchanged.

**Date:** 2026-10-25  
**Responsible engineering session:** Engineering lease held  
**Working branch:** `acceptance/issue45-q02-core-auth-20261024`  
**PR:** #129 — *Q02: authenticated genuine Core, identity and fail-closed CLI*

## 1. Version information and scope

| Item | Value |
|---|---|
| Current source SHA (HEAD after F1 + F2 fixes + exact-head CI) | `277fb8c8bbe0947f82a90b94123c8b05a6c9900a` |
| Source SHA of the 3 earlier fixes | `913da26e0d36017b29bbc4841a495d4b1b6a7f27` |
| Source SHA after ledger/docs reconciliation #1 | `f015fd9c41d4efcdddc2bce61d383e85a72d6398` |
| Source SHA after push and report #1 | `ba0745d835f72054f5a7d1cddd489820eb610427` |
| Exact-head green source SHA before F1 fix | `f669152fca09bc06d2b477e04ded4ac3e14c7436` |
| PR remote HEAD before fixes | `9985e443c3f7424cf8dd843eabc5514ce3ba7547` |
| GitHub test-merge tree | `3de9c51dfcee7b96868fbb76c15aa6e2919b9121` |
| Pinned WSP source commit | `ac55f13423620252bdbf848c7e8a280c3b84721e` |
| Official signed Core | WAM Core v0.1.11 (macOS/Windows official-signed; Linux reviewed source-build) |
| Sole active Q | **Q02** — no Q03, no mainnet, no force-push or auto-merge |

## 2. Summary of work completed

1. **Audited PR #129 source** across `src/wam_regtest/{core,core_process,linux_headless,rpc_scope,cli_rpc,network_policy}` and `scripts/owner_acceptance.py`.
2. **Fixed 3 medium-severity reproducible defects** (commit `913da26`):
   - `src/wam_regtest/core_process.py`: handled `subprocess.SubprocessError` / decode failures from `lsof` on macOS.
   - `src/wam_regtest/linux_headless.py`: required operators to explicitly type `REAUTH` for headless `unlock`/`recover` commands.
   - `scripts/owner_acceptance.py`: registered and unregistered the owned Core scope cleanly.
3. **Resolved 2 independent review findings** on HEAD `43d94c1`:
   - **F1** — identified root cause and implemented minimal patch.
   - **F2** — audited all 115 Q02 evidence entries, marked 77 mismatched entries as `STALE`, and requalified at exact-head `f669152f`.
4. **Added regression contracts** in `tests/test_q02_contracts.py` covering all fixes.
5. **Reconciled acceptance ledger** `tests/acceptance/issue45.json`.
6. **Refreshed** `docs/Q02_CORE_AUTHENTICATION.md` and this report.
7. **Performed owner-approved normal pushes** of 3 commits to PR #129 (non-force push), followed by remediation of the subsequent review findings.

## 3. Modified files

### First 3 defect fixes (`913da26`)
- `src/wam_regtest/core_process.py`
- `src/wam_regtest/linux_headless.py`
- `scripts/owner_acceptance.py`
- `tests/test_q02_contracts.py`

### Ledger and documentation reconciliation #1 (`f015fd9`)
- `tests/acceptance/issue45.json`
- `docs/Q02_CORE_AUTHENTICATION.md`

### Engineering report #1 (`ba0745d`)
- `docs/Q02_ENGINEERING_REPORT_VI_20261025.md`

### Remediation of findings F1 + F2 (code fix pushed; ledger/docs pending final push at report time)
- `src/wam_regtest/custody.py` — added `private_temporary_directory()`
- `src/wam_regtest/core.py` — used `private_temporary_directory()` for disposable datadirs
- `src/wam_regtest/q02_probe.py` — used `private_temporary_directory()` for Q02 owned nodes
- `tests/test_q02_contracts.py` — regression contract for F1
- `tests/acceptance/issue45.json` — reconciled F2, marked `STALE`, requalified exact-head
- `docs/Q02_CORE_AUTHENTICATION.md` — updated F1/F2 details
- `docs/Q02_ENGINEERING_REPORT_VI_20261025.md` — this report

## 4. Test results

### Full source test suite after F1 patch
```text
Ran 180 tests in 7.539s
OK (skipped=33)
```
- **PASS:** 147
- **SKIP:** 33 (Windows-only / Win64-only / hardware-specific)
- **FAIL:** 0

### Dedicated Q02 regression contracts
9/9 contracts PASS, including the new contract for `private_temporary_directory`.

### Native genuine Core smoke on macOS ARM64
- 33/33 Q02 cases PASS.
- Wallet E2E PASS.
- Security E2E PASS.
- GUI real Core E2E PASS.
- Local receipt: `/private/var/folders/3l/hqzxttpd0rx2hp38q52pkb240000gn/T/opencode/wam-q02-9985e44/local-real-core-evidence-2.json`

### Exact-head CI after F1 fix (source `277fb8c8`)
All runs triggered at `277fb8c8` passed:
- macOS ARM64 native real Core E2E: run **40188235385** job 121153481853
- macOS ARM64 frozen `.app`/`.dmg` E2E: run **40188235385** job 121154716709 artifact **12597572612**
- Windows x64 credential/vault/Q02 auth: run **40188235465** job 121153482060 artifact **12597099709**
- Windows x64 WSP receive + Qt read: runs **40188235437**, **40188235458**
- Windows x64 real Core smoke: run **40188235495**
- Linux x86_64 experimental Core REGTEST: run **40188235392**
- WSP-1 canonical 28 BIP352 vectors (macOS ARM64): run **40188235360**

### F1 — macOS frozen E2E failure (run 40184340811 at `43d94c1`)
- Native job PASS; frozen `.app`/`.dmg` E2E FAIL.
- Error chain: `CORE_LOCAL_NETWORK_POLICY_DENIED` → `CORE_RPC_SCOPE_FAULTED` → `Q02_NODE_START_TIMEOUT`.
- Root cause: the system temporary directory on the macOS runner had an inherited ACL (`file-inherit`); newly created `wam.conf` files inherited that ACL and were rejected by `private_bytes`. Reproduced locally on macOS.
- Patch: `wam_regtest.custody.private_temporary_directory()` creates a private root under `cwd`, validates that no ACL is present, and only then creates temporary subdirectories. Preserves RPC auth, process ownership, network policy, and fail-closed checks without weakening any boundary.
- Exact-head CI at `277fb8c8` run 40188235385 PASS, confirming F1 resolved and G3 PASS.

### F2 — acceptance evidence provenance mismatch
- Audited 115 entries containing `workflow_run_id`: 77 entries recorded `source_sha`/`checkout_sha` values that did not match the workflow's actual head SHA.
- Affected mismatched runs: `40151555636`, `40151555639`, `40151555640`, `40151555642`, `40151555712`.
- Marked all 77 entries `STALE`, preserved CI history, requalified at exact-head `f669152f`, and refreshed to exact-head `277fb8c8` after the F1 patch landed.
- Post-refresh result: 115 entries with `workflow_run_id`, all matching source SHA; 0 mismatches.

### Ledger validation after F2 reconciliation
```bash
python -m wam_regtest.q_gate --ledger tests/acceptance/issue45.json
```
Result:
- **PASS:** 126
- **STALE:** 0
- **BLOCKED:** 8
- **FAIL:** 0
- **Coverage:** 134 cases

## 5. Gate status

| Gate | Description | Status |
|---|---|---|
| G0 | Confirm Q02 as the sole active Q | PASS |
| G1 | Source review & regression contracts | PASS |
| G2 | Native Core E2E on at least one platform | PASS |
| G3 | Frozen binary qualification (exact-source bytes) | **PASS** |
| G4 | Negative injection / fail-closed | PASS |
| G5 | Ledger reconciliation & validator PASS | **PASS** |
| G6 | Independent review / physical clean-host UX | **BLOCKED** |
| G7 | Owner merge authorization | **BLOCKED** |

## 6. Native / frozen status by platform

| Platform | Type | Status | Evidence |
|---|---|---|---|
| macOS ARM64 | Native source smoke | **PASS** | Exact-head CI run 40188235385 job 121153481853 + local receipt |
| macOS ARM64 | Frozen binary (`.app` / `.dmg`) | **PASS** | Exact-head CI run 40188235385 job 121154716709 artifact 12597572612; app.zip `2bff141825ed859f725e83b5181b9cb1fdd1dd93f9c086014d8b03eef8e5c503`, dmg `165e1bb27228fd875713be020558266e620b3245862175d9b830a6af3432ce99` |
| Windows x64 | Native source / Q02 auth | **PASS** | Exact-head CI run 40188235465 job 121153482060 |
| Windows x64 | Frozen binary | **PASS** | Exact-head CI run 40188235465 artifact 12597099709; payload zip `e39f4ad9201a8c51dd6f7cabfa3103983d13b5ef7a2ff83f0a214e5285356d52` |
| Linux x86_64 | Native source / Q02 auth | **PASS** | Exact-head CI run 40188235392 job 121153589150 |
| Linux x86_64 | Desktop frozen | **PASS** | Exact-head CI run 40188235392 job 121153982212 artifact 12596747010; payload tar.gz `7a331dfc1f6c941385b13c27fd7e1c996be08faba804cf2c4b1ae049a0e723e6` |
| Linux x86_64 | Headless frozen | **PASS** | Exact-head CI run 40188235392 job 121153982178 artifact 12597142606; payload tar.gz `5ca9ab49403473ef863e90676c6df69d38e69f4ada2513330e1743caca45fe97` |

## 7. Remaining blockers

1. **G6 — Independent review / physical operator:** requires the repository owner or an external reviewer; cannot be self-certified by engineering automation.
2. **G7 — Owner merge authorization:** requires explicit owner approval to merge once G6 is satisfied.

## 8. Recommendations and owner requests

- G0–G5 and G3 passed. No further technical edits were required at this checkpoint.
- Owner arranges independent review / physical clean-host UX (G6) and merge approval (G7).
- Retain the engineering lease protocol until Q02 acceptance or explicit owner handoff.
- Do not activate Q03, auto-merge, or interact with mainnet/real funds.

## 9. Safety notes and boundaries

- All Core execution is strictly **REGTEST**; mainnet and real funds are never used.
- No persistent HTTP/JSON-RPC architecture was introduced in Q02.
- No external Core adoption is permitted; only fixture-spawned processes are registered.
- Engineering lease enforcement (`ENGINEERING_ACTIVE_REFUSED` = 73) rejects concurrent lease acquisition.
- Q01/Q05/main snapshots are preserved untouched.

---
*Historical engineering report for PR #129 / Issue #45 Q02 (translated to English).*
