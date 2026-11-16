"""The one place that says which WAM Core the wallet is compatible with (audit F-11).

Official target for every platform: WAM Core v0.1.13. v0.1.11 is legacy and
is never a target or fallback; its historical handling (q_gate ledger
evidence, the cli_rpc stop-reply fixture) stays where it is, read-only.

Contracts carried here, with values that must never change for an existing
profile or a v0.1.13 node:
  * CORE_RELEASE is written to and verified from ``supervisor.profile``
    (``version``), a persisted format value.
  * SUPPORTED_RPC is the RPC wire identity ``getnetworkinfo`` must report:
    (version, subversion, protocolversion). A mismatch fails closed.
Signed-archive names, sizes and hashes are intake pins and stay in
official_core_v013 / release / windows_release_preflight / q05_platforms;
a test checks that they agree with CORE_RELEASE.
Supporting a future Core release is a reviewed change to this module plus
those pins and new qualification, never a silent fallback.
"""

CORE_RELEASE = 'v0.1.13'
RPC_VERSION = 113
RPC_SUBVERSION = '/WAM:0.1.13/'
PROTOCOL_VERSION = 70016
SUPPORTED_RPC = (RPC_VERSION, RPC_SUBVERSION, PROTOCOL_VERSION)
DISPLAY_NAME = 'WAM Core ' + CORE_RELEASE
