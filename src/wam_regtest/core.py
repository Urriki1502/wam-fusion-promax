"""Runtime helpers for a verified local WAM Core.

Path checks, a free local port, one-shot CLI routing and the private REGTEST
config. The disposable smoke harness lives in qualification.real_core_smoke
and is not part of the shipped wallet.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import socket
import stat

from .release import ARCHIVES, CLI_SHA256, FINGERPRINT, VERSION, _sha
from .official_core_v013 import ARCHIVES as SIGNED_ARCHIVES
from .telemetry import increment

class CoreSmokeError(RuntimeError):
    """Fixed redacted errors, no paths/passwords/logs."""


def verified_core_paths(core_dir: Path) -> tuple[Path, Path, dict]:
    increment('verified_core_paths')
    import sys
    if sys.platform == 'linux':
        from .linux_runtime import verified_paths
        try:return verified_paths(core_dir)
        except (ValueError,OSError):raise CoreSmokeError('CORE_LINUX_EXPLICIT_TRUST_DENIED') from None
    if sys.platform == "win32":
        from .windows_core_transport import verified_core_paths as windows_paths
        return windows_paths(core_dir)
    if not core_dir.is_absolute() or core_dir.is_symlink():
        raise CoreSmokeError("CORE_DIRECTORY_DENIED")
    try:
        receipt = json.loads((core_dir / "receipt.json").read_text())
        platform = receipt["platform"]
        node = core_dir / "wamd"
        cli = core_dir / "wam-cli"
        if (platform != "macos-arm64" or platform not in ARCHIVES
                or receipt.get("tag") != VERSION
                or receipt.get("archive") != SIGNED_ARCHIVES["macos-arm64"][0]
                or receipt.get("archive_sha256") != SIGNED_ARCHIVES["macos-arm64"][2]
                or receipt.get("publisher_fingerprint") != FINGERPRINT or
                receipt["signed_archive_verified"] is not True or
                receipt.get("mainnet_allowed") is not False or
                receipt.get("loader_process_binding_qualified") is not False or
                receipt["wamd_sha256"] != ARCHIVES[platform][1] or
                (platform in CLI_SHA256 and receipt.get("wam_cli_sha256") != CLI_SHA256[platform])):
            raise CoreSmokeError("CORE_RECEIPT_DENIED")
        for path, key in ((node, "wamd_sha256"), (cli, "wam_cli_sha256")):
            s = path.lstat()
            if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1
                    or s.st_size <= 0 or s.st_size > 128 * 1024 * 1024
                    or path.is_symlink() or _sha(path) != receipt[key]):
                raise CoreSmokeError("CORE_EXACT_BINARY_DENIED")
        return node, cli, receipt
    except CoreSmokeError:
        raise
    except (OSError, KeyError, TypeError, ValueError):
        raise CoreSmokeError("CORE_EXACT_BINARY_DENIED") from None


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _read_cli(cmd: list[str], timeout: int = 15) -> object:
    """Existing one-shot signed CLI, narrowed equally on all three platforms."""
    from .network_policy import local_rpc_port,NetworkPolicyError
    from .cli_rpc import CliRpcError
    from .rpc_scope import route
    try:
        if (type(cmd) is not list or len(cmd)<3 or any(type(v) is not str for v in cmd)
                or not cmd[1].startswith('-datadir=')):
            raise CoreSmokeError('CORE_LOCAL_RPC_COMMAND_DENIED')
        directory=Path(cmd[1][9:])
        if not Path(cmd[0]).is_absolute() or not directory.is_absolute():
            raise CoreSmokeError('CORE_LOCAL_RPC_COMMAND_DENIED')
        local_rpc_port(directory) # Deny unsafe/remote profiles before process or RPC.
        return route(Path(cmd[0]),directory,cmd[2:],timeout=timeout)
    except NetworkPolicyError:
        from .rpc_scope import quarantine
        quarantine(directory)
        raise CoreSmokeError('CORE_LOCAL_NETWORK_POLICY_DENIED') from None
    except CliRpcError as error:raise CoreSmokeError(error.args[0]) from None
    except CoreSmokeError:raise
    except (OSError,ValueError):raise CoreSmokeError('CORE_LOCAL_RPC_COMMAND_DENIED') from None


def _write_private_config(datadir: Path, rpcport: int, p2pport: int) -> None:
    import sys
    if sys.platform == "win32":
        from .windows_core_regtest_smoke import _config
        return _config(datadir,rpcport,p2pport)
    # Password stays in owner-only wam.conf; never passed as a command argument.
    password = secrets.token_hex(32)
    user = "disposable_" + secrets.token_hex(8)
    # Bitcoin Core/WAM Core requires network-scoped settings such as
    # connect/port/rpcport under the explicit [regtest] stanza. Putting these
    # options in the global stanza makes real wamd EXIT 1 before RPC starts.
    global_values = {"regtest": "1", "server": "1"}
    network_values = {
        "rpcuser": user, "rpcpassword": password,
        "rpcbind": "127.0.0.1", "rpcallowip": "127.0.0.1", "rpcport": str(rpcport),
        "port": str(p2pport), "listen": "0", "connect": "0", "dnsseed": "0",
        "discover": "0", "upnp": "0", "txindex": "1", "blockfilterindex": "1",
        "coinstatsindex": "1", "fallbackfee": "0.0001",
    }
    config = datadir / "wam.conf"
    fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        for k, v in global_values.items():
            out.write(f"{k}={v}\n")
        out.write("[regtest]\n")
        for k, v in network_values.items():
            out.write(f"{k}={v}\n")
        out.flush()
        os.fsync(out.fileno())
