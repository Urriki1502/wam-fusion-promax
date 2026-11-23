# WAM Fusion ProMax

**Native WAM wallet engineering candidate — BIP39 · BIP352 Silent Payments · WAM Core v0.1.13**

WAM Fusion ProMax is a desktop wallet project focused on transaction safety, Silent Payments, durable wallet state, and reproducible testing against genuine WAM Core. The current development candidate supports isolated **REGTEST** workflows and targets macOS ARM64, Windows x64, and Linux x86_64.

> [!WARNING]
> **REGTEST ONLY — NOT APPROVED FOR MAINNET OR REAL FUNDS.**
> Do not use production recovery phrases, private keys, wallet profiles, or actual funds. Green CI confirms only the tests that were run; it does not establish complete security or release readiness.

## Where to find the current project

> [!IMPORTANT]
> **The active WAM Fusion ProMax source is on [`promax/main`](https://github.com/Urriki1502/wam-fusion-promax/tree/promax/main), not on this historical `main` branch.** This README is the repository landing page; the code displayed under `main` may reflect older RC1 work. For the current implementation, build instructions, and documentation, always use the links to `promax/main` below.

| Resource | Link |
| --- | --- |
| **Current WAM Fusion ProMax source** | [Browse `promax/main`](https://github.com/Urriki1502/wam-fusion-promax/tree/promax/main) |
| **Authoritative project README** | [`promax/main/README.md`](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/README.md) |
| **Technical documentation index** | [`promax/main/docs/README.md`](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/docs/README.md) |
| **GitHub Actions** | [Workflow runs](https://github.com/Urriki1502/wam-fusion-promax/actions) |
| **Current verified source commit** | [`23806dd9dea38`](https://github.com/Urriki1502/wam-fusion-promax/commit/23806dd9dea38b526ec162ccd13d4dff90e491e7) |

## Current engineering status

*Snapshot: November 23, 2026, source commit `23806dd9dea38b526ec162ccd13d4dff90e491e7`.*

| Area | Verified scope / remaining boundary |
| --- | --- |
| WAM Core | Genuine signed **v0.1.13** binaries with pinned authenticity checks |
| Silent Payments | **BIP352**, using WSP at commit `ac55f13423620252bdbf848c7e8a280c3b84721e` |
| Wallet onboarding | **12-word BIP39** test-wallet create, open, and supported restore flows |
| Desktop platforms | macOS ARM64, Windows x64, and Linux x86_64 engineering/CI coverage |
| Network | Disposable **REGTEST** only; supported manual two-node scenarios require separate physical qualification |
| GitHub CI | **5/5 relevant workflows successful** at the snapshot SHA; 17 jobs passed, 2 conditional jobs skipped |
| Full V1 acceptance | **Not achieved** — outstanding real-user, recovery, privacy, physical, and independent review gates |
| Distribution | No approved mainnet release, production signing, or notarized public release claimed |

### Implemented and tested capabilities

- **Silent Payments:** BIP352 receiving and scanning integrated with genuine WAM Core.
- **Wallet experience:** onboarding, overview, Receive, Send, History, Security, and Settings views.
- **Payment authorization:** distinct Prepare, Review, Sign, and Broadcast stages.
- **Funds-safety controls:** fee and dust validation, input reservations, checkpoints, and conservative handling of uncertain transaction outcomes.
- **Persistence and recovery:** encrypted key material, native storage/custody checks, same-chain recovery contracts, and reorganization tests.
- **Platform qualification:** native source and frozen artifact testing for macOS, Windows, and Linux, within each workflow's defined scope.

Implementation and passing contracts do **not** mean that a complete normal-UI wallet journey or a physical-device recovery scenario has been accepted.

## CI qualification — exact source snapshot

The following GitHub Actions runs were executed against **`promax/main` at `23806dd9`**.

| Platform / workflow | Outcome | Evidence |
| --- | --- | --- |
| macOS ARM64 — canonical BIP352 vectors | **PASS** | [Run 45094137634](https://github.com/Urriki1502/wam-fusion-promax/actions/runs/45094137634) |
| macOS ARM64 — genuine Core, Qt, Q05, Q04, frozen app/DMG | **5 jobs PASS** | [Run 45094140851](https://github.com/Urriki1502/wam-fusion-promax/actions/runs/45094140851) |
| Windows x64 — native custody, encrypted vault, qualification | **2 jobs PASS** | [Run 45094144067](https://github.com/Urriki1502/wam-fusion-promax/actions/runs/45094144067) |
| Linux — Q05 supervisor contracts | **PASS** | [Run 45094147479](https://github.com/Urriki1502/wam-fusion-promax/actions/runs/45094147479) |
| Linux x86_64 — genuine/reviewed Core and frozen wallet workflows | **8 jobs PASS; 2 conditionally SKIPPED** | [Run 45094150231](https://github.com/Urriki1502/wam-fusion-promax/actions/runs/45094150231) |

**Summary:** 17 jobs PASS, 0 jobs FAIL, 2 jobs SKIPPED. Skipped gates are not counted as passing. Results apply only to the stated source, job definitions, platform runners, and tested artifacts. Further commits require new evidence.

## Architecture at a glance

```text
WAM Fusion ProMax
├── Native Qt desktop wallet
│   ├── 12-word BIP39 onboarding
│   ├── Receive / Send / History / Security
│   └── Explicit payment confirmation
├── Serialized wallet operations
│   ├── BIP352 Silent Payments integration
│   ├── Prepare → Review → Sign → Broadcast
│   ├── Reservation and durability controls
│   └── Recovery / synchronization / reorg handling
├── Verified WAM Core v0.1.13
│   ├── Localhost-restricted RPC
│   └── Isolated REGTEST / manual test P2P
└── Evidence-based qualification
    ├── Source and adversarial tests
    ├── Genuine-Core end-to-end contracts
    └── Platform-native and frozen-artifact checks
```

## Getting the current source

For engineering and disposable REGTEST testing, check out the **active** branch explicitly:

```bash
git clone --branch promax/main https://github.com/Urriki1502/wam-fusion-promax.git
cd wam-fusion-promax
git rev-parse HEAD
```

The pinned Silent Payments source is:

```bash
git clone https://github.com/Urriki1502/wam-silent-payments.git wsp-upstream
git -C wsp-upstream checkout --detach ac55f13423620252bdbf848c7e8a280c3b84721e
```

Use the [current setup and build instructions](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/README.md#getting-started-development--disposable-regtest), including the hash-locked Python environment, signed Core intake, and exact-commit tests. **Do not use legacy RC1/v0.1.11 build recipes from this historical branch.**

## Security boundaries and incomplete acceptance

The engineering project intentionally fails closed when source identity, Core binaries, wallet state, or transaction outcomes are ambiguous. The following items remain outside completed V1 acceptance:

1. Full **normal-UI production-app user acceptance**: create, receive, send, confirm, quit, reopen, restore, and negative user journeys.
2. **Q20 runtime privacy** checks across real application flows.
3. **Q06 full acceptance**, including reconciliation of any pending, stale, or blocked acceptance evidence.
4. **V19 two-physical-computer** REGTEST checks.
5. Independent and hands-on **G6/G7** security and release review.
6. Physical crash/power-loss recovery evidence and release-specific publisher trust.

The application does not promise full recovery of off-chain signed/uncertain state from a seed phrase alone. An unlocked runtime can contain sensitive data, and local custody controls do not guarantee protection against a compromised host. Mainnet and real funds remain prohibited for the current candidate.

## Documentation and provenance

Technical documentation is organized under the [current documentation index](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/docs/README.md).

- [Acceptance rules](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/docs/ACCEPTANCE.md)
- [REGTEST wallet behavior](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/docs/WALLET-REGTEST.md)
- [Official Core v0.1.13 provenance](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/docs/WAM_CORE_V013_PROVENANCE.md)
- [V1 wallet scope and compatibility](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/docs/ADR_WAM_FUSION_V1_12WORD_SCOPE_20261106.md)
- [Shared REGTEST / V19 procedure](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/docs/V1_NET_TWO_COMPUTER_ACCEPTANCE.md)
- [Security limits](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/docs/SECURITY-REUSE.md)
- [Case-level acceptance ledger](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/tests/acceptance/issue45.json)

Historical files and test receipts are retained for traceability. Old qualification results must never be presented as current-source acceptance.

## License

See the [repository LICENSE](https://github.com/Urriki1502/wam-fusion-promax/blob/promax/main/LICENSE) and upstream [third-party notices](https://github.com/Urriki1502/wam-fusion-promax/tree/promax/main/third_party).

**WAM Fusion ProMax remains an engineering REGTEST candidate — not a production wallet or a financial service.**
