# Q02 Engineering Report — Issue #45 Core Authentication and Signed CLI Fail-Closed

**Date:** 2026-10-25  
**Test session:** Engineering lease held  
**Working branch:** `acceptance/issue45-q02-core-auth-20261024`  
**PR:** #129 — *Q02: authenticated genuine Core, identity and fail-closed CLI*

> Historical record, translated into English. The original path is retained to preserve existing references; these results are not a current-HEAD qualification.

## 1. Version and scope

| Item | Value |
|---|---|
| Source SHA (HEAD after F1/F2 fixes and exact-HEAD CI) | `277fb8c8bbe0947f82a90b94123c8b05a6c9900a` |
| Source SHA for first three fixes | `913da26e0d36017b29bbc4841a495d4b1b6a7f27` |
| Source SHA after first ledger/docs reconciliation | `f015fd9c41d4efcdddc2bce61d383e85a72d6398` |
| Source SHA after first push/report | `ba0745d835f72054f5a7d1cddd489820eb610427` |
| Exact-HEAD green SHA before F1 | `f669152fca09bc06d2b477e04ded4ac3e14c7436` |
| Remote PR HEAD before fix | `9985e443c3f7424cf8dd843eabc5514ce3ba7547` |
| GitHub test-merge tree | `3de9c51dfcee7b96868fbb76c15aa6e2919b9121` |
| Pinned WSP source commit | `ac55f13423620252bdbf848c7e8a280c3b84721e` |
| Official signed Core | WAM Core v0.1.11 (officially signed macOS/Windows; reviewed Linux source build) |
| Single active Q | **Q02** — not Q03; no mainnet, force push or automatic merge |

## 2. Work completed

1. Audited PR #129 in `src/wam_regtest/{core,core_process,linux_headless,rpc_scope,cli_rpc,network_policy}` and `scripts/owner_acceptance.py`.
2. Fixed three reproducible medium-severity defects (commit `913da26`):
   - `src/wam_regtest/core_process.py`: handle `subprocess.SubprocessError` and failed macOS `lsof` decoding.
   - `src/wam_regtest/linux_headless.py`: require explicitly typed `REAUTH` on headless `unlock`/`recover`.
   - `scripts/owner_acceptance.py`: register and unregister the managed Core scope.
3. Addressed two findings from independent review at HEAD `43d94c1`: **F1** root-cause investigation and patch; **F2** audit 115 Q02 evidence entries, mark 77 mismatched entries STALE, and requalify exact HEAD `f669152f`.
4. Added regression contracts in `tests/test_q02_contracts.py` covering the fixes.
5. Reconciled `tests/acceptance/issue45.json`.
6. Updated `docs/Q02_CORE_AUTHENTICATION.md` and this report.
7. Pushed three approved commits to PR #129 via normal, non-force push, then addressed additional findings.

## 3. Historical changed files

**Initial three fixes (`913da26`):** `src/wam_regtest/core_process.py`, `src/wam_regtest/linux_headless.py`, `scripts/owner_acceptance.py`, `tests/test_q02_contracts.py`.

**First ledger/docs reconciliation (`f015fd9`):** `tests/acceptance/issue45.json`, `docs/Q02_CORE_AUTHENTICATION.md`.

**Initial report (`ba0745d`):** `docs/Q02_ENGINEERING_REPORT_VI_20261025.md`.

**F1/F2 work (code fix pushed; final ledger/docs push pending at the recorded point):**
- `src/wam_regtest/custody.py`: add `private_temporary_directory()`.
- `src/wam_regtest/core.py`: use private temporary directories for disposable datadirs.
- `src/wam_regtest/q02_probe.py`: use private temporary directories for Q02 managed nodes.
- `tests/test_q02_contracts.py`: add F1 regression contract.
- `tests/acceptance/issue45.json`: reconcile F2, mark STALE, requalify exact HEAD.
- `docs/Q02_CORE_AUTHENTICATION.md`: update findings.
- `docs/Q02_ENGINEERING_REPORT_VI_20261025.md`: update this report.

## 4. Test results

**Full source suite after F1:**
```text
Ran 180 tests in 7.539s
OK (skipped=33)
```
**147 PASS / 33 SKIP / 0 FAIL** (skips: Windows-only, Win64-only and hardware-specific cases).

**Focused Q02 contracts:** 9/9 PASS, including `private_temporary_directory`.

**Native genuine Core on macOS ARM64:** 33/33 Q02 cases PASS; wallet E2E, security E2E and genuine-Core GUI E2E PASS. Local receipt: `/private/var/folders/3l/hqzxttpd0rx2hp38q52pkb240000gn/T/opencode/wam-q02-9985e44/local-real-core-evidence-2.json`.

**Exact-HEAD CI at `277fb8c8`:** all triggered runs were green.
- macOS ARM64 native real Core E2E: run **40188235385**, job 121153481853.
- macOS ARM64 frozen .app/.dmg E2E: run **40188235385**, job 121154716709, artifact **12597572612**.
- Windows x64 credential/vault/Q02 authentication: run **40188235465**, job 121153482060, artifact **12597099709**.
- Windows x64 WSP receive + Qt read: runs **40188235437**, **40188235458**.
- Windows x64 genuine-Core smoke: run **40188235495**.
- Linux x86_64 experimental Core REGTEST: run **40188235392**.
- WSP-1 canonical 28 BIP352 vectors (macOS ARM64): run **40188235360**.

### F1 — macOS frozen E2E failure at `43d94c1`

Run 40184340811: native job PASS, frozen .app/.dmg E2E FAIL. Error chain: `CORE_LOCAL_NETWORK_POLICY_DENIED` → `CORE_RPC_SCOPE_FAULTED` → `Q02_NODE_START_TIMEOUT`. The macOS runner's system temporary directory had inherited file-inherit ACLs, which propagated to a new `wam.conf` and caused `private_bytes` to reject it. Reproduced locally on macOS.

The patch `wam_regtest.custody.private_temporary_directory()` creates a private root beneath the current working directory, verifies it has no ACL, and only then creates child temporary directories. RPC authentication, process identity, network policy and fail-closed checks remain intact. Exact-HEAD run 40188235385 at `277fb8c8` PASS, confirming F1 fixed and G3 PASS.

### F2 — Acceptance evidence provenance mismatch

Of 115 entries with `workflow_run_id`, 77 had `source_sha`/`checkout_sha` values inconsistent with the workflow's actual HEAD SHA. Affected runs: `40151555636`, `40151555639`, `40151555640`, `40151555642`, `40151555712`. The 77 entries were marked STALE, historical CI preserved, exact HEAD `f669152f` requalified, and evidence refreshed to `277fb8c8` after F1. At completion, all 115 entries with a `workflow_run_id` matched their source SHA; 0 mismatches.

**Ledger validation:**
```bash
python -m wam_regtest.q_gate --ledger tests/acceptance/issue45.json
```
**126 PASS / 0 STALE / 8 BLOCKED / 0 FAIL; 134 cases covered.**

## 5. Gate status

| Gate | Description | Status |
|---|---|---|
| G0 | Q02 is the only active Q | PASS |
| G1 | Source review and regression contracts | PASS |
| G2 | Native genuine-Core E2E on at least one platform | PASS |
| G3 | Exact-source frozen binary qualification | **PASS** |
| G4 | Negative injection and fail-closed behavior | PASS |
| G5 | Ledger reconciliation and validator | **PASS** |
| G6 | Independent review / clean-host physical UX | **BLOCKED** |
| G7 | Merge authorization | **BLOCKED** |

## 6. Native and frozen qualification by platform

| Platform | Qualification | Status | Evidence |
|---|---|---|---|
| macOS ARM64 | Native source smoke | **PASS** | Exact-HEAD run 40188235385, job 121153481853 + local receipt |
| macOS ARM64 | Frozen .app/.dmg | **PASS** | Run 40188235385, job 121154716709, artifact 12597572612; app.zip SHA256 `2bff141825ed859f725e83b5181b9cb1fdd1dd93f9c086014d8b03eef8e5c503`; dmg SHA256 `165e1bb27228fd875713be020558266e620b3245862175d9b830a6af3432ce99` |
| Windows x64 | Native source/Q02 auth | **PASS** | Run 40188235465, job 121153482060 |
| Windows x64 | Frozen binary | **PASS** | Run 40188235465, artifact 12597099709; payload ZIP `e39f4ad9201a8c51dd6f7cabfa3103983d13b5ef7a2ff83f0a214e5285356d52` |
| Linux x86_64 | Native source/Q02 auth | **PASS** | Run 40188235392, job 121153589150 |
| Linux x86_64 | Desktop frozen | **PASS** | Run 40188235392, job 121153982212, artifact 12596747010; payload tar.gz `7a331dfc1f6c941385b13c27fd7e1c996be08faba804cf2c4b1ae049a0e723e6` |
| Linux x86_64 | Headless frozen | **PASS** | Run 40188235392, job 121153982178, artifact 12597142606; payload tar.gz `5ca9ab49403473ef863e90676c6df69d38e69f4ada2513330e1743caca45fe97` |

## 7. Remaining blockers

1. **G6:** independent review / physical testing by an external reviewer or human operator. Internal checks cannot substitute for this gate.
2. **G7:** separate authorization to merge after G6.

## 8. Recommendations

- G0–G5, including G3, PASS. No further technical modification is required under this historical Q02 scope.
- Arrange independent/clean-host UX review (G6), then separately authorize merge (G7).
- Retain the engineering lease until full Q02 acceptance or a documented handoff decision.
- Do not activate Q03, merge automatically, or access mainnet/real funds.

## 9. Safety and limitations

- All Core tests used REGTEST; never mainnet/real funds.
- No persistent HTTP/JSON-RPC architecture was implemented.
- External Core processes were not adopted; only fixture-created processes were registered.
- Engineering lease active (`ENGINEERING_ACTIVE_REFUSED` = 73); second lease requests were denied.
- Q01/Q05/main snapshots were retained without modification.

---

*Historical engineering report for PR #129 / Issue #45 Q02.*
