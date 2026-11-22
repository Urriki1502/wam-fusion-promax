# WAM Fusion ProMax

**A native, security-focused WAM wallet prototype built around genuine WAM Core and BIP352 Silent Payments.**

WAM Fusion ProMax provides a desktop wallet for developing and qualifying WAM transactions on a **disposable REGTEST network**. The project combines a 12-word BIP39 wallet, a pinned Silent Payments implementation, a genuine WAM Core node, and native desktop interfaces. It prioritizes explicit transaction authorization, state integrity, recovery safety, and evidence-based testing.

> [!WARNING]
> **REGTEST ONLY — NOT READY FOR MAINNET OR REAL FUNDS.** Do not import real recovery phrases, private keys, personal wallets, or production node data. A successful unit test, CI workflow, or experimental package build does not authorize financial use or distribution as a production wallet.

## Project status

| Area | Current position |
| --- | --- |
| Network | **REGTEST only**. Mainnet operation is not authorized. |
| Development baseline | `promax/main`, reference source commit `02e0fbd4a32e0c4ce3bd41bdc0db7e94165ee6f7` (November 2026). |
| WAM Core | Official signed **v0.1.13** binaries, checked against pinned hashes and signing evidence. |
| Silent Payments | Pinned WSP source: `ac55f13423620252bdbf848c7e8a280c3b84721e` (BIP352). |
| macOS ARM64 | Local FC-31 engineering evidence reports a **scoped PASS** on the reference commit. This is not full application or release acceptance. |
| Windows / Linux | Platform implementations and test workflows exist; historical package results do **not** qualify the current candidate. |
| Product acceptance | **Not complete**. Normal-UI production-app E2E, dynamic privacy checks, cross-platform and physical/independent gates require separate evidence. |
| Release | No approved mainnet build, production signing, or notarized public release is claimed. |

This table identifies the reference candidate, not a promise that every later commit or CI run is qualified. Always compare an acceptance receipt's **source SHA, executable hash, platform and test scope** with the artifact being assessed. Historical RC1 documents describe earlier Core versions and must not be used as current build instructions.

## Functional scope

The source implements or exercises the following REGTEST functionality. Implementation presence is **not** equivalent to an accepted end-to-end user journey.

| Capability | Implementation scope |
| --- | --- |
| Wallet onboarding | Create, open and supported restore flows for a **12-word BIP39** test wallet |
| Receiving | BIP352 Silent Payment receiving codes, genuine Core scanning and verified wallet snapshots |
| Wallet views | Overview, Receive, Send, History, Security, Settings and relevant network controls |
| Payments | Separate Prepare, Review, Sign and Broadcast stages with explicit authorization |
| Transaction safety | Amount/fee checks, dust policy, durable input reservations and uncertainty handling |
| Chain behavior | Real-Core confirmations, restart, reconciliation and reorganization scenarios |
| Storage and custody | Encrypted key material, native platform protections, checkpoint/anchor consistency checks |
| Desktop | PySide6/Qt interface, theme handling, localization and platform-specific packaging |
| Networking | Isolated REGTEST by default; explicitly configured, manual two-computer Core P2P for shared REGTEST |
| Qualification | Unit/negative contracts, native Core tests, frozen-package probes and reproducible test fixtures |

**Intentional limitations:** no silent migration of earlier wallet formats, no automatic re-broadcast of uncertain transactions, no automatic release of signed reservations, and no assumption that 12 words alone restore every off-chain transaction state. Clean-device recovery, two-physical-host qualification and cross-platform migration have additional restrictions. PayJoin is not an enabled V1 transaction flow.

## Architecture

```text
WAM Fusion ProMax
├── Qt desktop interface / onboarding
│   └── explicit user review and action state
├── wallet executor / transaction state machine
│   ├── BIP39 12-word key and recovery flows
│   ├── BIP352 WSP scanner and signing integration
│   ├── reservation, checkpoint and storage controls
│   └── verified wallet snapshots and history
├── genuine WAM Core v0.1.13
│   ├── localhost-only wallet RPC
│   └── isolated or manually peered REGTEST node
└── source, native and frozen qualification
```

Key directories and entrypoints:

| Path | Purpose |
| --- | --- |
| `src/wam_regtest/` | Application, wallet, Core integration, GUI and platform code |
| `src/wam_regtest/production_entry.py` | Separate, allowlisted macOS frozen wallet entrypoint |
| `src/wam_regtest/package_entry.py` | Qualification/development bundle entrypoint |
| `src/wam_regtest/wallet_executor.py` | Serialized wallet command boundary |
| `src/wam_regtest/wallet_session.py` | Payment and state integrity contracts |
| `src/wam_regtest/managed_onboarding.py` | Supported create/open/restore routes |
| `src/wam_regtest/official_core_v013.py` | Immutable upstream Core release identities |
| `scripts/` | Isolated environment, verification, build and qualification tools |
| `requirements/` | Hash-locked dependency profiles |
| `tests/` | Unit, integration, adversarial and acceptance contracts |
| `tests/acceptance/issue45.json` | Case-level acceptance ledger |
| `docs/` | Technical designs, operating procedures and historical evidence |
| `release-candidates/` | **Historical** candidate manifests; not current download endorsements |

## Getting started (development / disposable REGTEST)

The checked-in source is **not** a ready-to-use mainnet wallet. Start in a clean checkout without personal wallet profiles or existing Core datadirs.

**Prerequisites for the macOS ARM64 path:** Apple Silicon macOS, Git, GnuPG, Xcode command-line tools and **CPython 3.12.10**. Linux and Windows have separately defined toolchains and qualification requirements. The hash-locked build flow uses isolated environments; arbitrary `pip install` combinations are not equivalent.

### 1. Check out the candidate and pinned WSP

```bash
git clone --branch promax/main https://github.com/Urriki1502/wam-fusion-promax.git
cd wam-fusion-promax

git clone https://github.com/Urriki1502/wam-silent-payments.git wsp-upstream
git -C wsp-upstream checkout --detach ac55f13423620252bdbf848c7e8a280c3b84721e

git rev-parse HEAD
git -C wsp-upstream rev-parse HEAD
```

To reproduce a **specific historical qualification**, check out its exact recorded source SHA rather than relying on a moving branch. Do not use a personal WSP checkout that differs from the pinned commit.

### 2. Create a hash-locked development environment

The target environment directory and receipt file **must not exist** before the command. Choose new absolute paths outside the repository:

```bash
python3.12 -I scripts/q01_environment.py --profile gui \
  --environment "$HOME/wam-q01-gui-fresh" \
  --receipt "$HOME/wam-q01-install-fresh.json"
```

This authenticates the tracked source and pinned WSP, installs the declared wheel hashes and writes an installation receipt. It is a **source-install gate**, not genuine-Core or frozen acceptance.

### 3. Run source checks and obtain official Core

```bash
"$HOME/wam-q01-gui-fresh/bin/python" -I scripts/run_macos_source_tests.py

"$HOME/wam-q01-gui-fresh/bin/python" -I -m wam_regtest.release \
  --platform macos-arm64 --destination core
```

Core download requires upstream signature and digest verification. Use a **new** destination rather than overwriting an existing `core/` directory. Core staging alone must not be reported as a wallet E2E PASS.

### 4. Build the macOS packages (separate qualification required)

```bash
PATH="$HOME/wam-q01-gui-fresh/bin:$PATH" bash scripts/build_macos_bundle.sh
```

The default build uses `scripts/build_macos_production.py` to produce a separately identified **distribution candidate** and a **qualification-only** application. The latter is not a substitute for normal-UI testing of the distributed binary. Building or signing an experimental package does not constitute notarization or production acceptance.

For platform-specific procedures and older exact-SHA results, use the [documentation index](docs/README.md). Do not transplant historic Q01/Q05/RC1 commands to the current candidate without reconciling their Core and source pins.

## Security model and restrictions

- **No mainnet or real-wallet access:** all provided engineering and test flows are restricted to fresh REGTEST profiles.
- **Explicit payment authorization:** signing and broadcast are distinct. An ambiguous network outcome must not trigger blind retries.
- **Irreversible-state protection:** signed, uncertain and broadcast reservations are retained conservatively across faults and reorgs.
- **Trusted inputs:** accept only pinned Core/WSP identities; reject unexpected network/genesis, malformed credentials and unverified storage state.
- **Local network boundary:** application RPC remains on localhost. Shared REGTEST allows only explicitly configured Core-to-Core P2P connections.
- **Storage limits:** unlocked runtime SQLite and process memory can contain sensitive state. Encryption, native anchors and best-effort clearing do not guarantee protection against a compromised machine.
- **Recovery limits:** key recovery, chain scanning and restoration of off-chain irreversible transaction state are separate capabilities. A recovered seed is not proof of a fully recoverable signing session.
- **Supply-chain limits:** a signed upstream Core does not certify the Fusion wrapper. Ad-hoc signatures or artifact hashes do not replace publisher trust, independent audit or platform acceptance.

## Testing and acceptance

The repository includes GitHub Actions for BIP352 vectors, genuine WAM Core, macOS, Windows and Linux contracts. Their outcomes are scoped to the **exact tested commit**. Failed, skipped, stale or blocked cases are not PASS.

For the November 2026 reference candidate, local FC-31 evidence reported a scoped macOS qualification, while full user-facing acceptance remains open. A pre-push engineering audit additionally exercised deterministic and randomized behavior; its local report should be assessed separately from GitHub CI. Do not infer current cross-platform or physical acceptance from these historical records.

Before a future release decision, the remaining evidence includes:

1. Full normal-UI end-to-end journeys on the **actual distributed app**, using disposable REGTEST wallets.
2. Runtime privacy testing along those same journeys, including Q20.
3. Exact-commit Windows/Linux native and frozen qualification where applicable.
4. Real two-computer V19 checks and required physical and independent security review.
5. Case-by-case reconciliation of the acceptance ledger without changing historical FAIL evidence.

The [Actions dashboard](https://github.com/Urriki1502/wam-fusion-promax/actions) shows remote workflow results. **No green badge is treated as proof of complete V1 acceptance.**

## Documentation

Start with the [organized documentation index](docs/README.md). Useful reference documents include:

- [Acceptance scope and definitions](docs/ACCEPTANCE.md)
- [Wallet operation on disposable REGTEST](docs/WALLET-REGTEST.md)
- [Official Core v0.1.13 provenance](docs/WAM_CORE_V013_PROVENANCE.md)
- [Security assumptions and limitations](docs/SECURITY-REUSE.md)
- [V1 scope and compatibility ADR](docs/ADR_WAM_FUSION_V1_12WORD_SCOPE_20261106.md)
- [Shared REGTEST / two-computer procedure](docs/V1_NET_TWO_COMPUTER_ACCEPTANCE.md)
- [Package-content review](docs/RC_PACKAGE_CONTENT_VERIFICATION.md)
- [Historical release-candidate qualification](docs/RELEASE_CANDIDATE_QUALIFICATION.md)

Documents dated before this candidate may use old Core versions, branches, identifiers or acceptance states. Treat them as **historical evidence**, not current instructions unless they explicitly match the source SHA under test.

## Project boundaries

WAM Fusion ProMax is an engineering and security-qualification project. It is not a custodial service, exchange, blockchain consensus implementation or approved production wallet. No real-funds warranty or complete recovery guarantee is provided.

See [LICENSE](LICENSE) for license terms and [third-party notices](third_party/) for included upstream material.
