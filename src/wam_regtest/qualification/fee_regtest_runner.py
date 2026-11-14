"""Native macOS source runner for FEE-3 step 1. Never imported by the app.

Run with --help. Each fixture gets a NEW retained disposable REGTEST profile.
The CLI consent authorizes fixture mining only; payment Sign/Broadcast still
use the existing separate visible GUI approvals. No startup flags, injected
coins, fee overrides, frozen entrypoint or production module edits.
"""
from __future__ import annotations

import argparse
from concurrent.futures import Future
from contextlib import ExitStack
from datetime import datetime, timezone
from decimal import localcontext
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch

from ..wallet_executor import COMMANDS, WalletExecutor, WalletExecutorError
from .fee_regtest import (
    CHARACTERIZATION_PENDING_STATUS, FIXTURES, INSUFFICIENT_DATA_ERROR_SHA256,
    OUTSIDE_STEP, aggregate_status, assertions_pass, assert_tma,
    confirmed_debit_holds, exact_atoms, json_capture, proposal_trace_holds,
    reopen_clean_holds, sign_order_holds, tma_capture,
    valid_characterization_result, valid_pass_result, write_artifact,
)

QUALIFICATION_COMMANDS = frozenset((
    "fee_fixture", "fee_inspect", "fee_baseline", "fee_observe", "fee_preflight",
    "fee_signed_evidence", "fee_resume_replay", "fee_safety",
))


class QualificationFeeExecutor(WalletExecutor):
    """Qualification-only executor admitting the 8 harness actions alongside COMMANDS."""

    ALLOWED_COMMANDS = COMMANDS | QUALIFICATION_COMMANDS

    def submit(self, action, *args, **kwargs):
        future = Future()
        with self._guard:
            if (action not in self.ALLOWED_COMMANDS or self._closed
                    or self._pending is not None
                    or threading.get_ident() == self._thread.ident):
                future.set_exception(WalletExecutorError("WALLET_EXECUTOR_BUSY_OR_CLOSED"))
                return future
            self._pending = future
            self._queue.put_nowait((action, args, kwargs, future))
        return future


def resolve_actor(explicit=None):
    """Resolve the active run actor from CLI option or environment context."""
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    for key in ("WAM_QUALIFICATION_ACTOR", "PEER_AGENT", "USER", "LOGNAME"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return "operator"


def utc():
    return datetime.now(timezone.utc).isoformat()


class Blocked(ValueError):
    pass


def require(value, code):
    if value is not True:
        raise ValueError(code)


def plain(value):
    """Copy immutable executor containers into JSON-shaped evidence."""
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [plain(v) for v in value]
    return value


def authenticate(core, archive, gpg, manifest_dir):
    """Recheck the signed manifest, retained archive and executable members.

    Work on temporary copies: verification never changes the intake directory.
    Existing signed intake pins authenticate the exact member bytes; this is
    independent of the mutable receipt's signed_archive_verified assertion.
    """
    from ..core import verified_core_paths
    from ..official_core_v013 import ARCHIVES, MEMBERS, SUMS_SHA256, SIGNATURE_SHA256
    from ..release import _validate_signed_sums
    node, cli, receipt = verified_core_paths(core)
    name, size, digest = ARCHIVES["macos-arm64"]
    if not archive.is_file():
        raise Blocked("F3_RETAINED_SIGNED_ARCHIVE_REQUIRED")
    require(archive.stat().st_size == size and sha256(archive.read_bytes()).hexdigest() == digest,
            "F3_ARCHIVE_PIN")
    with tempfile.TemporaryDirectory(prefix="fee3-gpg-") as temp:
        folder = Path(temp)
        for item in ("SIGNING-KEY.asc", "SHA256SUMS", "SHA256SUMS.asc"):
            if not (manifest_dir / item).is_file():
                raise Blocked("F3_SIGNED_MANIFEST_REQUIRED")
            shutil.copyfile(manifest_dir / item, folder / item)
        require(sha256((folder / "SHA256SUMS").read_bytes()).hexdigest() == SUMS_SHA256,
                "F3_SUMS_PIN")
        require(sha256((folder / "SHA256SUMS.asc").read_bytes()).hexdigest() == SIGNATURE_SHA256,
                "F3_SIGNATURE_PIN")
        require(_validate_signed_sums(gpg, folder, name) == digest, "F3_SIGNATURE")
    members = {"wamd": sha256(node.read_bytes()).hexdigest(),
               "wam-cli": sha256(cli.read_bytes()).hexdigest()}
    require(members == MEMBERS["macos-arm64"], "F3_MEMBER_PINS")
    return {"archive_sha256": digest, "members": members,
            "trust": "official-signed-v0.1.13", "signature_verified_now": True,
            "publisher_fingerprint": receipt["publisher_fingerprint"]}


def source_identity():
    root = Path(__file__).resolve().parents[3]

    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args])

    inventory = []
    for raw in git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0"):
        if raw:
            name = raw.decode()
            path = root / name
            inventory.append({"path": name, "sha256": sha256(path.read_bytes()).hexdigest()
                              if path.is_file() else None})
    return {"sha": git("rev-parse", "HEAD").decode().strip(),
            "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "dirty_inventory": git("status", "--porcelain=v1").decode().splitlines(),
            "inventory": inventory,
            "inventory_sha256": sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()}


def backend_type():
    """Late import keeps --help and pure tests free of native wallet startup."""
    from ..bip39_owner_backend import Bip39ReadOnlyBackend
    from ..gui_errors import operation_error
    from ..wallet_session import WalletCoreCli
    from wam_sp.wallet import Wallet, Signer

    class FeeBackend(Bip39ReadOnlyBackend):
        def __init__(self, *args, observations, **kwargs):
            super().__init__(*args, **kwargs)
            self.observations = observations

        def execute(self, action, args, kwargs):
            if action == "fee_fixture":
                return self.fund(args[0])
            if action == "fee_inspect":
                return self.inspect()
            if action == "fee_preflight" and "events" not in self.observations:
                return self.preflight()
            if action == "fee_baseline":
                from dataclasses import asdict
                from ..domain.fee_policy import parse_policy_inputs, quote
                rpc = self._spend_session._rpc()
                rpc.attest()
                network = rpc.call("getnetworkinfo", [])
                network = {k: network[k] for k in ("version", "subversion", "relayfee", "incrementalfee")}
                mempool = rpc.call("getmempoolinfo", [])
                smart = {t: rpc.call("estimatesmartfee", [t, "conservative"]) for t in (2, 6, 25)}
                try:
                    estimaterawfee = rpc.call("estimaterawfee", [6])
                except Exception:
                    estimaterawfee = None
                return {"quote": asdict(quote(parse_policy_inputs(
                            rpc.verified_network, network, mempool, smart, {6: estimaterawfee}))),
                        "rpc": json_capture({"network": network, "mempool": mempool,
                                             "smart": [smart[t] for t in (2, 6, 25)],
                                             "estimaterawfee": estimaterawfee})}
            if action == "fee_observe":
                self.observations.update(events=[], proposals=[], releases=[], policy=[], submissions=[])
                return None
            # Observe the actual calls, returning their original values and
            # preserving exceptions. No argument or raw transaction is logged.
            o = self.observations
            if "events" not in o:
                return super().execute(action, args, kwargs)
            with ExitStack() as stack:
                o["events"].append("ACTION_" + action.upper())
                def wrap(cls, method, before=None, after=None, on_error=None):
                    original = getattr(cls, method)

                    def observed(obj, *a, **kw):
                        if before:
                            try:
                                before(obj, a, kw)
                            except Exception:
                                o.setdefault("observer_errors", []).append("BEFORE_CAPTURE_DENIED")
                        try:
                            result = original(obj, *a, **kw)
                        except Exception as exc:
                            if on_error:
                                try:
                                    on_error(obj, a, exc)
                                except Exception:
                                    o.setdefault("observer_errors", []).append("ERROR_CAPTURE_DENIED")
                            raise
                        if after:
                            try:
                                after(obj, a, result)
                            except Exception:
                                o.setdefault("observer_errors", []).append("AFTER_CAPTURE_DENIED")
                        return result

                    stack.enter_context(patch.object(cls, method, observed))

                def proposal_built(_obj, a, _result):
                    o["proposals"].append(a[1])
                    o["events"].append("PROPOSE")

                def proposal_refused(_obj, a, error):
                    o["proposals"].append({
                        "fee": a[1],
                        "refused": True,
                        "code": operation_error("prepare_auto", error),
                    })
                    o["events"].append("PROPOSE_REFUSED")

                def release(_obj, a, _result):
                    o["releases"].append(sha256(a[0].encode()).hexdigest())
                    o["events"].append("RELEASE_DRAFT")

                def rpc_before(_obj, a, _kw):
                    from .fee_regtest_recovery import MUTATIONS
                    if a[0].upper() in MUTATIONS or a[0] == "testmempoolaccept":
                        o["events"].append(a[0].upper())
                    if a[0] == "sendrawtransaction":
                        session = self._spend_session
                        rows = session.scanner.store.db.execute(
                            "SELECT token,state FROM reservations ORDER BY txid,vout").fetchall()
                        body = session._read_payment_evidence(rows[0][0], "uncertain")
                        o["submissions"].append({"raw_sha256": sha256(bytes.fromhex(a[1][0])).hexdigest(),
                            "states": [r[1] for r in rows],
                            "uncertain_evidence_txid": body["txid"] if body else None})

                def rpc_after(_obj, a, result):
                    if a[0] == "gettxout":
                        o["events"].append("GETTXOUT")
                    if a[0] in WalletCoreCli.FEE_POLICY_READS:
                        # Restrict networkinfo to relevant public fields.
                        if a[0] == "getnetworkinfo":
                            result = {k: result[k] for k in
                                      ("version", "subversion", "relayfee", "incrementalfee") if k in result}
                        entry = {"method": a[0], "result": json_capture(result)}
                        params = a[1] if len(a) > 1 else None
                        if (a[0] in ("estimatesmartfee", "estimaterawfee")
                                and isinstance(params, (list, tuple)) and params and type(params[0]) is int):
                            entry["target"] = params[0]
                        o["policy"].append(entry)
                        o["events"].append("POLICY_READ")

                wrap(Wallet, "propose", after=proposal_built, on_error=proposal_refused)
                wrap(Wallet, "release_draft", after=release)
                wrap(Wallet, "mark_signed", before=lambda *a: o["events"].append("MARK_SIGNED"))
                wrap(Signer, "sign", before=lambda *a: o["events"].append("SIGN"))
                wrap(WalletCoreCli, "call", after=rpc_after)
                wrap(WalletCoreCli, "_call", before=rpc_before)
                session = self._spend_session
                if session is not None:
                    original_save = session._save

                    def save():
                        result = original_save()
                        o["events"].append("SAVE")
                        try:
                            rows = session.scanner.store.db.execute("SELECT state FROM reservations").fetchall()
                            if rows and {r[0] for r in rows} == {"uncertain"}:
                                o["events"].append("SAVE_UNCERTAIN")
                        except Exception:
                            o.setdefault("observer_errors", []).append("SAVE_CAPTURE_DENIED")
                        return result

                    stack.enter_context(patch.object(session, "_save", save))
                    wrap(type(session), "_retain_signed_payment", after=lambda obj, a, r:
                         o["events"].append("EVIDENCE_" + a[0].upper() + "_SAVED"))
                try:
                    if action == "fee_preflight":
                        return self.preflight()
                    if action == "fee_safety":
                        from .fee_regtest_safety import fault_boundary
                        require(len(args) == 2 and not kwargs, "F3_SAFETY_ARGUMENTS")
                        with fault_boundary(args[0], session, o):
                            return super().execute("broadcast" if args[0] == "lost-send-response" else "sign", (args[1],), {})
                    if action == "fee_signed_evidence":
                        return self.signed_evidence()
                    if action == "fee_resume_replay":
                        # Re-read the authoritative token privately; never log it.
                        token, = {r[0] for r in session.scanner.store.db.execute("SELECT token FROM reservations")}
                        try:
                            session.resume_signed_intent(token, args[0], approved=True)
                        except Exception as error:
                            from .q06_fix_scenarios import failure_code
                            return failure_code(error)
                        return None
                    return super().execute(action, args, kwargs)
                except Exception as error:
                    if error.args in (("PAYMENT_AMOUNT",), ("INSUFFICIENT_SINGLE_CLUSTER_FUNDS",), ("FEE_DISPROPORTIONATE",), ("WALLET_CHANGE_BELOW_DUST",)):
                        o["original_refusal"] = error.args[0]
                    raise

        def fund(self, amounts):
            from ..managed_wallet_checkpoint import _owned
            from ..wsp_live import public_regtest_mining_address
            from wam_sp.core import Input, pub, send
            from wam_sp.transaction import p2wpkh, signed_single_input
            require(amounts in tuple(f.coins for f in FIXTURES), "F3_FIXTURE_DENIED")
            owner = self._core()
            _owned(owner)
            require(self._secret is not None and self._seed_folder is not None
                    and self._spend_session is None, "F3_FRESH_READONLY_OWNER_REQUIRED")
            seed_id = self._seed_folder.name.removeprefix("bip39-12-")
            require(not (owner.directory / ("bip39-12-scan-" + seed_id)).exists(),
                    "F3_EXISTING_CHECKPOINT_DENIED")
            rpc = WalletCoreCli(owner.cli, owner.directory)
            try:
                rpc.attest()
                require(rpc.call("getblockcount") == 0, "F3_NEW_CHAIN_REQUIRED")
                address = public_regtest_mining_address(self.source)
                rpc._call("generatetoaddress", ["101", address])
                require(rpc.call("getblockcount") == 101, "F3_MATURITY_HEIGHT")
                funding = []
                for index, amount in enumerate(amounts, 1):
                    block_hash = rpc.call("getblockhash", [index])
                    block = rpc._call("getblock", [block_hash, "2"])
                    require(block.get("hash") == block_hash and len(block["tx"]) == 1,
                            "F3_COINBASE_BLOCK")
                    coinbase = block["tx"][0]
                    matches = [v for v in coinbase["vout"]
                               if v["scriptPubKey"].get("hex") == p2wpkh(31).hex()]
                    require(len(matches) == 1, "F3_PUBLIC_COINBASE")
                    out = matches[0]
                    value = exact_atoms(out["value"])
                    require(value > amount + 10_000 + 330, "F3_FUNDING_VALUE")
                    txin = Input(coinbase["txid"], out["n"], p2wpkh(31),
                                 witness=(b"\x30", pub(31)), secret=31)
                    output = b"\x51\x20" + send((txin,), (self._public["receive_code"],))[0]
                    raw = signed_single_input(txin, value, (
                        (amount, output), (value - amount - 10_000, p2wpkh(31))), 31)
                    txid = rpc._call("sendrawtransaction", [raw])
                    rpc._call("generatetoaddress", ["1", address])
                    require(type(txid) is str and len(txid) == 64
                            and rpc.call("getblockcount") == 101 + index, "F3_FUNDING_CONFIRMATION")
                    funding.append({"txid": txid, "atoms": amount})
                _owned(owner)
                rpc.attest()
                info = rpc.call("getnetworkinfo", [])
                require(info["version"] == 113 and info["subversion"] == "/WAM:0.1.13/",
                        "F3_CORE_VERSION")
                return {"funding": funding, "version": info["version"],
                        "subversion": info["subversion"], "chain": "regtest",
                        "genesis": rpc.call("getblockhash", [0]),
                        "peers": info["connections"]}
            finally:
                if rpc._transport is not None:
                    rpc._transport.close()

        def signed_evidence(self):
            from wam_sp.psbt import PSBT
            from ..infrastructure.tx_size import serialized_vsize
            session = self._spend_session
            token, = {r[0] for r in session.scanner.store.db.execute("SELECT token FROM reservations")}
            body = session._read_payment_evidence(token, "signed")
            if body is None:
                raise ValueError("F3_SIGNED_EVIDENCE_MISSING")
            raw = PSBT.decode(bytes.fromhex(body["signed_psbt"])).finalize()
            basis = body.get("fee_basis")
            fee_quote = None
            if isinstance(basis, dict) and basis.get("kind") == "quote":
                fee_quote = dict(basis["quote"])
                fee_quote["reasons"] = tuple(fee_quote["reasons"])
            return {"raw_sha256": sha256(raw).hexdigest(), "txid": body["txid"],
                    "atoms": body["atoms"], "fee": body["fee"], "vsize": serialized_vsize(raw),
                    "encrypted_sha256": sha256((session._evidence_store()._folder() /
                        (token + "-signed.enc")).read_bytes()).hexdigest(),
                    "commitment": body["commitment"], "token_sha256": sha256(token.encode()).hexdigest(),
                    "fee_quote": fee_quote}

        def inspect(self):
            session = self._spend_session
            fresh_transport = session.faulted
            if fresh_transport:
                from ..managed_wallet_checkpoint import _owned
                owner = session._q06_owner
                require(self.owner is owner, "F3_INSPECT_SAME_OWNER_REQUIRED")
                _owned(owner)
                session._q06_guard.check()
                rpc = WalletCoreCli(owner.cli, owner.directory)
            else:
                rpc = session._rpc()
            try:
                return self._inspect_with_rpc(session, rpc)
            finally:
                if fresh_transport and rpc._transport is not None:
                    rpc._transport.close()

        def _inspect_with_rpc(self, session, rpc):
            from wam_sp.wallet import Wallet
            rpc.attest()
            coins = session.scanner.coins()
            groups = {(c["account"], c["label"]) for c in coins}
            rows = session.scanner.store.db.execute(
                "SELECT txid,vout,token,state,created FROM reservations").fetchall()
            anchor_value = session.vault.anchor.read()
            anchor = json.dumps(anchor_value, sort_keys=True, default=str).encode()
            return {"coins": sorted(c["atoms"] for c in coins), "cluster_count": len(groups),
                    "inventory": [{"txid": c["txid"], "vout": c["vout"], "atoms": c["atoms"],
                                   "cluster_sha256": sha256(repr((c["account"], c["label"])).encode()).hexdigest()}
                                  for c in coins],
                    "balance": Wallet(session.scanner).balance(),
                    "tip": list(session.scanner.store.tip()),
                    "identity_sha256": sha256(session.ring.public_metadata()["account_id"].encode()).hexdigest(),
                    "anchor_generation": anchor_value[0],
                    "token_sha256": sha256(rows[0][2].encode()).hexdigest() if rows else None,
                    "reservations": len(rows), "reservation_states": sorted(r[3] for r in rows),
                    "reservation_rows": [{"txid": r[0], "vout": r[1], "state": r[3]} for r in rows],
                    "reservation_sha256": sha256(repr(sorted(tuple(r) for r in rows)).encode()).hexdigest(),
                    "anchor_sha256": sha256(anchor).hexdigest(),
                    "mempool": rpc._call("getrawmempool", []),
                    "mempool_info": json_capture(rpc.call("getmempoolinfo", [])),
                    "review_sha256": sha256(json.dumps(review_evidence(session._review), sort_keys=True).encode()).hexdigest() if session._review else None,
                    "faulted": session.faulted, "prepared": session._prepared is not None,
                    "signed": session._signed is not None}

        def preflight(self):
            from wam_sp.psbt import PSBT
            from ..infrastructure.tx_size import serialized_vsize
            session = self._spend_session
            psbt = PSBT.decode(session._signed)
            raw = psbt.finalize()
            rpc = session._rpc()
            before = rpc._call("getrawmempool", [])
            reply = rpc.call("testmempoolaccept", [[raw.hex()]])
            after = rpc._call("getrawmempool", [])
            txid = psbt.txid()
            wtxid = sha256(sha256(raw).digest()).digest()[::-1].hex()
            return {"capture": tma_capture(reply), "raw_sha256": sha256(raw).hexdigest(),
                    "txid": txid, "wtxid": wtxid, "final_vsize": serialized_vsize(raw),
                    "outputs": [v for v, _ in psbt.tx.outputs],
                    "selected_inputs": [{"txid": c["txid"], "vout": c["vout"], "atoms": c["atoms"]}
                                        for c in session._prepared.proposal.coins],
                    "witness_sizes": [len(v) for v in psbt.signatures],
                    "checks": assert_tma(reply, session._review.vsize, session._review.fee, txid, wtxid),
                    "mempool_unchanged": before == after}

    return FeeBackend


def review_evidence(review):
    from dataclasses import asdict
    # The receive code is omitted. Only a commitment digest is public.
    values = asdict(review)
    values.pop("code")
    return values


_SPEED_CHOICE_WORD_RE = re.compile(
    r"\b(?:fast|normal|slow|nhanh|bình thường|thường|chậm|cepat|lambat)\b",
    re.IGNORECASE,
)
_SPEED_CHOICE_TERMS = (
    "快速", "普通", "慢速",
    "빠름", "보통", "일반", "느림",
    "高速", "速い", "通常", "低速", "遅い",
)


def _has_speed_choice_text(text):
    if not text:
        return False
    return bool(_SPEED_CHOICE_WORD_RE.search(text)) or any(term in text for term in _SPEED_CHOICE_TERMS)


def no_manual_fee_controls(window, dialog=None):
    """Verify no manual fee widgets or Fast/Normal/Slow choices across all 6 catalog languages."""
    from PySide6.QtWidgets import (
        QAbstractButton, QCheckBox, QComboBox, QDoubleSpinBox, QGroupBox,
        QLabel, QLineEdit, QPlainTextEdit, QPushButton, QRadioButton, QSlider,
        QSpinBox,
    )

    forbidden_attr_words = ("fee", "speed", "priority", "tier")
    input_or_choice_types = (
        QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QSlider, QRadioButton, QAbstractButton,
    )
    for host in (window, dialog):
        if host is None:
            continue
        if any(any(w in name.lower() for w in forbidden_attr_words) and isinstance(val, input_or_choice_types)
               for name, val in vars(host).items()):
            return False

    extra_choice_types = (QComboBox, QRadioButton, QSlider, QSpinBox, QDoubleSpinBox, QCheckBox)
    send_page = window.stack.widget(3) if hasattr(window, "stack") and window.stack.count() > 3 else None
    send_scopes = []
    for candidate in (
        send_page,
        getattr(window.recipient_input, "parentWidget", lambda: None)(),
        getattr(window.broadcast, "parentWidget", lambda: None)(),
    ):
        if candidate is not None and candidate not in send_scopes:
            send_scopes.append(candidate)
    if send_scopes:
        line_edits = {w for scope in send_scopes for w in scope.findChildren(QLineEdit)}
        if line_edits != {window.recipient_input, window.amount_input}:
            return False
        if any(scope.findChildren(kind) for scope in send_scopes for kind in extra_choice_types):
            return False

    if dialog is not None:
        if dialog.findChildren(QLineEdit) or any(dialog.findChildren(kind) for kind in extra_choice_types):
            return False
        if {btn.text() for btn in dialog.findChildren(QPushButton)} != {dialog.cancel.text(), dialog.approve.text()}:
            return False

    text_hosts = []
    inspect_scopes = list(send_scopes)
    if dialog is not None:
        inspect_scopes.append(dialog)
    for scope in inspect_scopes:
        for cls in (QLabel, QAbstractButton, QGroupBox, QLineEdit, QPlainTextEdit):
            for widget in scope.findChildren(cls):
                if widget.objectName() == "ReceiveCode":
                    continue
                if isinstance(widget, QLineEdit):
                    text_hosts.extend((widget.text(), widget.placeholderText()))
                elif isinstance(widget, QPlainTextEdit):
                    text_hosts.append(widget.toPlainText())
                elif isinstance(widget, QGroupBox):
                    text_hosts.append(widget.title())
                else:
                    text_hosts.append(widget.text())
        for combo in scope.findChildren(QComboBox):
            text_hosts.extend(combo.itemText(i) for i in range(combo.count()))
    for cls in (QAbstractButton, QComboBox):
        for control in window.findChildren(cls):
            if isinstance(control, QComboBox):
                text_hosts.extend(control.itemText(i) for i in range(control.count()))
            else:
                text_hosts.append(control.text())
    return not any(_has_speed_choice_text(text) for text in text_hosts)


def approve_payment(app, window, button, caption, done, wait, checks, result, kind,
                    decision="approve", captured=None):
    """Inspect the visible native dialog BEFORE clicking Approve or Cancel."""
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QLabel, QWidget
    from ..fusion_pages import PaymentApproval, approval_amount_text
    from ..bip39_locale import t
    from ..qualification_gui import click_visible_approval

    timer = QTimer()
    timer.setInterval(150)
    failed = []
    acted = []

    def money(value):
        return "%d.%08d" % divmod(value, 100_000_000)

    def inspect():
        if acted or failed:
            return
        for dialog in app.allWidgets():
            if not isinstance(dialog, PaymentApproval) or not dialog.isVisible():
                continue
            if dialog.approve.text() != caption:
                continue
            review = window._last_review
            source_text = t("fee.source." + review.rate_source)
            fee_text = money(review.fee)
            total_text = money(review.atoms + review.fee)
            avail_before_text = money(review.available_before)
            avail_after_text = money(review.available_after)
            expected = approval_amount_text(review)
            labels = [label.text() for label in dialog.findChildren(QLabel)]
            joined_labels = "\n".join(labels)
            receive_widget = dialog.findChild(QWidget, "ReceiveCode")
            recipient_visible = (receive_widget is not None
                                 and hasattr(receive_widget, "toPlainText")
                                 and receive_widget.toPlainText() == review.code)
            has_fields = all(text in joined_labels for text in (
                fee_text, source_text, total_text, avail_before_text, avail_after_text,
            ))
            checks["gui_" + kind + "_review"] = expected in labels and has_fields and recipient_visible
            checks["gui_" + kind + "_cancel_default"] = (dialog.isModal()
                and dialog.cancel.isDefault() and not dialog.approve.isDefault())
            checks["gui_no_manual_fee_field"] = no_manual_fee_controls(window, dialog)
            if captured is not None:
                captured["review"] = review
                if callable(captured.get("capture_draft")):
                    captured["draft"] = captured["capture_draft"]()
            result.setdefault("gui", {})[kind] = {
                "amount_text_sha256": sha256(expected.encode()).hexdigest(),
                "recipient_sha256": sha256(review.code.encode()).hexdigest(),
                "observed_before_approval": True,
                "decision": decision,
            }
            timer.stop()
            acted.append(True)
            if not all(checks[k] is True for k in (
                    "gui_" + kind + "_review", "gui_" + kind + "_cancel_default", "gui_no_manual_fee_field")):
                failed.append(True)
                dialog.cancel.click()
                return
            if decision == "close":
                dialog.close()
            elif decision == "cancel":
                click_visible_approval(app, dialog.cancel.text())
            else:
                click_visible_approval(app, caption)
            return

    def guarded_inspect():
        try:
            inspect()
        except Exception:
            # Qt callback exceptions must not print arbitrary exception text
            # or leave an approval timer running after evidence capture fails.
            failed.append(True)
            checks["gui_" + kind + "_review"] = False
            timer.stop()

    timer.timeout.connect(guarded_inspect)
    timer.start()
    try:
        button.click()
        wait(lambda: bool(failed) or done(), "FEE_" + kind.upper())
        require(not failed, "F3_GUI_REVIEW_MISMATCH")
    finally:
        timer.stop()


def reopen_verified_owner(state, root, core, source, adapter, wait, approve, idle, *, open_owner=None):
    """Reopen a checkpointed owner via q06_fix_scenarios' ready -> activate -> snapshot pattern."""
    if open_owner is None:
        from .q06_fix_scenarios import _open_owner
        open_owner = _open_owner
    executor, window = open_owner(
        state, root, core, source, adapter, "reopen",
        keychain=root / "q05-disposable.keychain-db",
    )
    wait(lambda: idle() and window._ready, "REOPEN")
    approve(window.activate, "Approve", lambda: window._spend_enabled, "ENABLE_REOPEN")
    wait(lambda: (idle() and window._last_verified is not None
                  and window._pending_confirm_txid is None
                  and not window.confirm.isEnabled()), "REOPEN_SNAPSHOT")
    return executor, window


def run_fixture(fixture, app, adapter, core, source, result, actor=None):
    from ..bip39_fusion_gui import Bip39FusionWindow
    from ..bip39_12 import Bip39Regtest12Keys
    from ..bip39_locale import t
    from mnemonic import Mnemonic
    from .q06_fix_scenarios import (
        _profile, _bind, _finish_backup, _shutdown, _PASSWORD,
    )
    from .q06_fix_scenarios import failure_code
    actor_name = resolve_actor(actor)
    observations = {}
    wait_report = {}
    state = {"app": app, "window": None, "executor": None}
    checks = result["assertions"]
    root = _profile()
    result["profile_fixture_id"] = sha256(str(root).encode()).hexdigest()
    write_artifact(root.parent / "fee3-case.json", {
        "profile_fixture_id": result["profile_fixture_id"],
        "case_id": fixture.case, "fixture": fixture.name})
    try:
        executor = QualificationFeeExecutor(lambda: backend_type()(
            root, core, source, _anchor_factory=adapter.make_anchor, observations=observations))
        state["executor"] = executor

        def request(action, *args, **kwargs):
            return plain(executor.request(action, *args, **kwargs))

        window = Bip39FusionWindow(executor)
        state["window"] = window
        idle, wait, approve = _bind(state, app, wait_report, "fee")
        window.show()
        window.start(_PASSWORD, "create", "")
        wait(lambda: idle() and window._backup_flow_active, "CREATE")
        _finish_backup(window, idle, wait)
        result["core_runtime"] = request("fee_fixture", fixture.coins, timeout=240)
        require(result["core_runtime"]["peers"] == 0, "F3_PEERS")
        approve(window.activate, "Approve", lambda: window._spend_enabled, "ACTIVATE")
        before = request("fee_inspect", timeout=240)
        result["before"] = before
        checks["confirmed_inventory"] = (before["coins"] == sorted(fixture.coins)
            and before["cluster_count"] == 1 and before["reservations"] == 0
            and before["balance"]["available_atoms"] == sum(fixture.coins)
            and {c["txid"] for c in before["inventory"]} ==
                {c["txid"] for c in result["core_runtime"]["funding"]})
        checks["empty_loaded_mempool"] = (before["mempool"] == []
            and before["mempool_info"]["response"].get("loaded") is True)
        require(assertions_pass(checks), "F3_FIXTURE_SETUP")
        baseline_evidence = request("fee_baseline", timeout=240)
        result["baseline"] = baseline_evidence
        baseline = baseline_evidence["quote"]
        if not (baseline["floor_atoms_per_kvb"] == 1000
                and baseline["rate_atoms_per_kvb"] == 2000
                and baseline["estimator"] == "UNAVAILABLE"):
            raise Blocked("F3_DEFAULT_FLOOR_FIXTURE_UNAVAILABLE")
        with Bip39Regtest12Keys(Mnemonic("english").to_mnemonic(bytes([1]*16)),
                               source=source, authorized_disposable=True) as payee:
            destination = payee.public_metadata()["receive_code"]
        request("fee_observe")
        if fixture.case == "F3-14":
            from .fee_regtest_safety import run_safety
            run_safety(fixture, app=app, window=window, request=request, idle=idle,
                wait=wait, approve_payment=approve_payment, observations=observations,
                destination=destination, checks=checks, result=result)
        elif fixture.case in ("F3-11", "F3-12", "F3-13"):
            from .fee_regtest_recovery import run_recovery

            def restart_recovery():
                nonlocal executor, window
                observations["restart_start"] = len(observations["events"])
                require(_shutdown(state) is False, "F3_RECOVERY_SHUTDOWN")
                executor = QualificationFeeExecutor(lambda: backend_type()(
                    root, core, source, keychain=root / "q05-disposable.keychain-db",
                    observations=observations))
                state["executor"] = executor
                window = Bip39FusionWindow(executor)
                state["window"] = window
                window.show()
                window.start(_PASSWORD, "reopen", "")
                wait(lambda: idle() and window._ready, "RECOVERY_REOPEN")
                approve(window.activate, "Approve", lambda: window._spend_enabled, "RECOVERY_ACTIVATE")
                wait(lambda: idle() and window._last_verified is not None, "RECOVERY_SNAPSHOT")

            result["no_manual_controls"] = no_manual_fee_controls(window)
            run_recovery(fixture, app=app, request=request, restart=restart_recovery,
                current_window=lambda: window, idle=idle, wait=wait, approve=approve,
                approve_payment=approve_payment, observations=observations, before=before,
                destination=destination, checks=checks, result=result)
        elif fixture.refusal:
            refusal = None
            try:
                request("prepare_auto", destination, fixture.amount, timeout=240)
            except Exception as error:
                refusal = failure_code(error)
            result["refusal"] = refusal
            after = request("fee_inspect", timeout=240)
            expected = ("WALLET_INPUT_AMOUNT_INVALID" if fixture.amount == 329
                        else "FEE_DISPROPORTIONATE" if fixture.amount in (330, 331)
                        else "WALLET_CHANGE_BELOW_DUST" if fixture.case == "D-FEE2-2" or fixture.name == "change-329"
                        else "WALLET_INPUT_FUNDS_UNAVAILABLE")
            checks["exact_refusal"] = refusal == expected
            checks["original_refusal"] = observations.get("original_refusal") == (
                "PAYMENT_AMOUNT" if fixture.amount == 329
                else "FEE_DISPROPORTIONATE" if fixture.amount in (330, 331)
                else "WALLET_CHANGE_BELOW_DUST" if fixture.case == "D-FEE2-2" or fixture.name == "change-329"
                else "INSUFFICIENT_SINGLE_CLUSTER_FUNDS")
            checks["no_state_change"] = (after["reservation_sha256"] == before["reservation_sha256"]
                and after["anchor_sha256"] == before["anchor_sha256"]
                and after["balance"] == before["balance"]
                and not after["prepared"] and not after["signed"] and not after["faulted"])
            checks["no_sign_or_submit"] = not any(e in observations["events"]
                                                   for e in ("SIGN", "MARK_SIGNED", "SENDRAWTRANSACTION"))
            checks["no_mempool_change"] = after["mempool"] == before["mempool"]
        elif fixture.case == "F3-01":
            window.recipient_input.setText(destination)
            window.amount_input.setText("%d.%08d" % divmod(fixture.amount, 100_000_000))
            captured = {}
            approve_payment(
                app, window, window.send, t("pages.approve_sign"),
                lambda: idle() and window.status.text() == t("owner.draft_cancelled"),
                wait, checks, result, "sign", decision="cancel", captured=captured,
            )
            review = captured.get("review")
            require(review is not None, "F3_FLOOR_PREPARE")
            result["review"] = review_evidence(review)
            checks.update(quote_checks(review, fixture, observations))
            cancelled = request("fee_inspect", timeout=240)
            checks["unsigned_cancel_releases"] = (
                cancelled["reservation_sha256"] == before["reservation_sha256"]
                and cancelled["reservations"] == 0
                and not cancelled["prepared"] and not cancelled["signed"] and not cancelled["faulted"]
            )
            checks["no_sign_or_submit"] = not any(e in observations["events"]
                                                   for e in ("SIGN", "MARK_SIGNED", "SENDRAWTRANSACTION"))
            checks["no_mempool_change"] = cancelled["mempool"] == before["mempool"]
        else:
            window.recipient_input.setText(destination)
            window.amount_input.setText("%d.%08d" % divmod(fixture.amount, 100_000_000))
            with localcontext() as ctx:
                ctx.prec = 6
                approve_payment(app, window, window.send, "Approve Sign",
                    lambda: idle() and window._signed_ready, wait, checks, result, "sign")
            review = window._last_review
            result["review"] = review_evidence(review)
            checks.update(quote_checks(review, fixture, observations))
            signed = request("fee_inspect", timeout=240)
            result["signed"] = signed
            checks["signed_reservations"] = (signed["reservation_states"] == ["signed"]*review.input_count
                                            and signed["anchor_sha256"] != before["anchor_sha256"])
            checks["no_submission_before_approval"] = "SENDRAWTRANSACTION" not in observations["events"]
            preflight = request("fee_preflight", timeout=120)
            result["tma"] = preflight
            checks.update({"tma_" + k: v for k, v in preflight["checks"].items()})
            checks["final_quote_core_vsize"] = preflight["final_vsize"] == review.vsize == fixture.vsize
            checks["witness_65_bytes"] = preflight["witness_sizes"] == [65]*review.input_count
            checks["input_output_fee_identity"] = (sum(preflight["outputs"]) + review.fee
                == sum(c["atoms"] for c in preflight["selected_inputs"])
                == sum(fixture.coins) - review.available_after)
            checks["output_structure"] = (len(preflight["outputs"]) == (1 if review.change_atoms == 0 else 2)
                and sorted(preflight["outputs"]) == sorted([fixture.amount] +
                      ([review.change_atoms] if review.change_atoms else [])))
            post_preflight = request("fee_inspect", timeout=240)
            checks["preflight_read_only"] = (preflight["mempool_unchanged"] is True
                and signed["reservation_sha256"] == post_preflight["reservation_sha256"]
                and signed["anchor_sha256"] == post_preflight["anchor_sha256"]
                and post_preflight["signed"] and not post_preflight["faulted"])
            require(assertions_pass(checks), "F3_PRE_BROADCAST_ASSERTIONS")
            approve_payment(app, window, window.broadcast, "Approve Broadcast",
                lambda: idle() and window._pending_confirm_txid is not None,
                wait, checks, result, "broadcast")
            txid = window._pending_confirm_txid
            checks["exact_broadcast_txid"] = txid == preflight["txid"]
            mempool = request("fee_inspect", timeout=240)["mempool"]
            checks["broadcast_present"] = txid in mempool
            approve(window.confirm, "Approve", lambda: window._pending_confirm_txid is None, "CONFIRM")
            after = request("snapshot", timeout=240)
            after_inspect = request("fee_inspect", timeout=240)
            pre_confirmed_atoms = before["balance"]["confirmed_atoms"]
            post_confirmed_atoms = after["confirmed_atoms"]
            result["confirmed_atoms"] = {
                "pre": pre_confirmed_atoms,
                "post": post_confirmed_atoms,
            }
            checks["confirmed_debit"] = confirmed_debit_holds(
                pre_confirmed_atoms=pre_confirmed_atoms,
                post_confirmed_atoms=post_confirmed_atoms,
                post_available_atoms=after["available_atoms"],
                amount=fixture.amount,
                fee=review.fee,
                selected_inputs=preflight["selected_inputs"],
                reservation_rows=after_inspect["reservation_rows"],
            )
            # Exact history debit is independently read from the verified DB.
            history = window.history_page.rows
            matches = [row for row in history if row.txid == txid]
            checks["history_exact_debit"] = (len(matches) == 1 and
                matches[0].credit_atoms - matches[0].debit_atoms == -(fixture.amount + review.fee))
            events = observations["events"]
            checks["one_sign_one_mark_one_submission"] = all(events.count(e) == 1
                for e in ("SIGN", "MARK_SIGNED", "SENDRAWTRANSACTION"))
            checks["sign_order"] = sign_order_holds(events)
            # Reopen only after verified original-owner shutdown.
            require(_shutdown(state) is False, "F3_PRE_REOPEN_SHUTDOWN")
            executor, window = reopen_verified_owner(
                state, root, core, source, adapter, wait, approve, idle,
            )
            reopened = request("snapshot", timeout=240)
            checks["reopen_clean"] = reopen_clean_holds(
                reopened,
                expected_confirmed_atoms=after["confirmed_atoms"],
                expected_reservation_count=after["reservation_count"],
            )
        passed = assertions_pass(checks)
        result["status"] = (
            (CHARACTERIZATION_PENDING_STATUS if fixture.characterization else "PASS")
            if passed else "FAIL"
        )
    except Blocked as error:
        result["status"] = "BLOCKED"
        result["failure_code"] = failure_code(error)
        result["blocker"] = {"actor": actor_name, "action": "provide the specified fixture prerequisites",
                             "code": failure_code(error)}
    except Exception as error:
        result["status"] = "FAIL"
        result["failure_code"] = failure_code(error)
    finally:
        gui_denied = wait_report.get("fee", {}).get("gui_denied")
        if gui_denied is not None:
            result["gui_denied"] = gui_denied
        result["observations"] = observations
        uncertain = _shutdown(state)
        checks["observer_integrity"] = not observations.get("observer_errors")
        result["cleanup"] = {"verified_original_owner_shutdown": not uncertain,
                             "profile_retained": True, "actor": actor_name,
                             "action": "inspect retained original owner" if uncertain else "none"}
        if uncertain:
            result["status"] = "FAIL"
            result["prior_failure_code"] = result.get("failure_code")
            result["failure_code"] = ("F3_SHUTDOWN_TIMEOUT"
                if state.get("shutdown_failure_code") == "Q06_FIX_SHUTDOWN_TIMEOUT"
                else "F3_SHUTDOWN_UNCERTAIN")
            result["cleanup"]["failure_code"] = state.get(
                "shutdown_failure_code", "Q06_FIX_SHUTDOWN_UNCERTAIN")
        elif (result["status"] in ("PASS", CHARACTERIZATION_PENDING_STATUS)
              and not checks["observer_integrity"]):
            result["status"] = "FAIL"
            result["failure_code"] = "F3_OBSERVER_CAPTURE_DENIED"


def _count_policy_reads(events):
    """Count contiguous POLICY_READ phases in the observed event trace."""
    if not isinstance(events, list):
        return 0
    return sum(
        1 for i, event in enumerate(events)
        if event == "POLICY_READ" and (i == 0 or events[i - 1] != "POLICY_READ")
    )


def _action_has_policy_read(events, action):
    if action not in events:
        return True
    start = events.index(action) + 1
    end = next((i for i in range(start, len(events))
                if isinstance(events[i], str) and events[i].startswith("ACTION_")), len(events))
    return "POLICY_READ" in events[start:end]


def _unavailable_smart_entry_holds(entry):
    target = entry.get("target")
    if type(target) is not int or not 1 <= target <= 1008:
        return False
    response = entry.get("result", {}).get("response", {})
    blocks = response.get("blocks")
    return (
        "feerate" not in response
        and type(blocks) is int
        and 0 <= blocks <= target
        and response.get("errors") == [{"text_sha256": INSUFFICIENT_DATA_ERROR_SHA256}]
    )


def quote_checks(review, fixture, observations):
    # Independent integer equations; no quoted_fee_holds/shared size oracle.
    q = review.fee_quote
    need = (review.vsize * review.rate_atoms_per_kvb + 999)//1000
    selected = sum(fixture.coins) - review.available_after
    policy = observations["policy"]
    smart_entries = [p for p in policy if p.get("method") == "estimatesmartfee"]
    networks = [p["result"]["response"] for p in policy if p["method"] == "getnetworkinfo"]
    mempools = [p["result"]["response"] for p in policy if p["method"] == "getmempoolinfo"]
    # Captured decimal strings carry original type schema alongside them.
    from decimal import Decimal
    def _measured_floor(net, mem):
        return max(exact_atoms(Decimal(v)) for v in
                   (net["relayfee"], mem["mempoolminfee"], mem["minrelaytxfee"]))
    floor = _measured_floor(networks[0], mempools[0])
    floors_consistent = (
        len(networks) == len(mempools)
        and all(_measured_floor(n, m) == floor for n, m in zip(networks, mempools))
    )
    fees = observations["proposals"]
    built = [f for f in fees if type(f) is int]
    events = observations.get("events", [])
    policy_reads = _count_policy_reads(events)
    if "ACTION_CANCEL" in events:
        release_count = events[:events.index("ACTION_CANCEL")].count("RELEASE_DRAFT")
    else:
        release_count = len(observations["releases"])
    return {
        "unavailable_smart": (
            policy_reads > 0
            and _action_has_policy_read(events, "ACTION_PREPARE_AUTO")
            and _action_has_policy_read(events, "ACTION_SIGN")
            and len(smart_entries) == 3 * policy_reads
            and all(_unavailable_smart_entry_holds(entry) for entry in smart_entries)
        ),
        "floor_quote": floors_consistent and q.estimator == "UNAVAILABLE" and q.source == "NETWORK_FLOOR_2X"
            and q.rate_atoms_per_kvb == 2 * q.floor_atoms_per_kvb == 2 * floor == 2000,
        "structure": review.input_count == fixture.inputs and review.vsize == fixture.vsize,
        "exact_intent": review.atoms == fixture.amount,
        "fee_covers_quote": review.fee >= need and review.overpay_atoms == review.fee - need,
        "bounded_overpay": review.overpay_atoms == (86 if fixture.change == 0 else 0),
        "bounded_proposals": proposal_trace_holds(fees),
        "released_unsaved_drafts": len(built) >= 1 and release_count == len(built) - 1,
        "exact_change": review.change_atoms == selected - fixture.amount - review.fee
            and (fixture.change is None or review.change_atoms == fixture.change)
            and (review.change_atoms == 0 or review.change_atoms >= 330),
        "debit_available": review.total_debit == fixture.amount + review.fee
            and review.available_before == sum(fixture.coins)
            and review.available_after == sum(fixture.coins) - selected,
    }


def main(argv=None, *, exit_on_uncertain=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--core-archive", required=True, type=Path)
    parser.add_argument("--signed-manifest-dir", required=True, type=Path,
                        help="retained SIGNING-KEY.asc, SHA256SUMS, SHA256SUMS.asc")
    parser.add_argument("--wsp-source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new run directory (must not exist)")
    parser.add_argument("--gpg", default="gpg")
    parser.add_argument("--actor", default=None, help="actor name recorded in blocker/cleanup metadata")
    parser.add_argument("--consent-disposable-regtest", action="store_true", required=True)
    args = parser.parse_args(argv)
    actor = resolve_actor(args.actor)
    if getattr(sys, "frozen", False):
        parser.error("source-only qualification; frozen mode is not implemented")
    for value in (args.core, args.core_archive, args.signed_manifest_dir, args.wsp_source, args.output):
        if not value.is_absolute():
            parser.error("absolute paths required")
    if args.output.is_relative_to(Path(__file__).resolve().parents[3]):
        parser.error("evidence output must be outside the source checkout")
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    identity = source_identity()
    command = [sys.executable, "-m", __spec__.name, *list(sys.argv[1:] if argv is None else argv)]
    setup = None
    core_identity = None
    app = adapter = None
    from .q06_fix_scenarios import failure_code
    try:
        from .q06_fix_scenarios import _require_cocoa
        from ..q05_platforms import DarwinArm64Adapter
        from ..wsp_live import _pinned_source
        if sys.platform != "darwin" or platform.machine().lower() != "arm64":
            raise Blocked("F3_NATIVE_MACOS_ARM64_REQUIRED")
        app = _require_cocoa()
        adapter = DarwinArm64Adapter()
        adapter.enforce_host()
        _pinned_source(args.wsp_source)
        core_identity = authenticate(args.core, args.core_archive, args.gpg, args.signed_manifest_dir)
    except Exception as error:
        setup = failure_code(error)
    results = {}
    digests = {}
    for fixture in FIXTURES:
        folder = args.output / fixture.case / fixture.name
        folder.mkdir(mode=0o700, parents=True)
        result = {"schema": "wam-fee3-source/v1", "case_id": fixture.case,
                  "fixture": fixture.name, "status": "BLOCKED", "started_utc": utc(),
                  "test_layer": "REAL_CORE", "network": "regtest", "mainnet_allowed": False,
                  "command": command, "source": identity, "core": core_identity,
                  "os": {"system": platform.system(), "arch": platform.machine(),
                         "qt_platform": app.platformName() if app is not None else None},
                  "wsp_source_commit": "ac55f13423620252bdbf848c7e8a280c3b84721e",
                  "safe_startup_flags": [], "assertions": {}, "artifacts": {},
                  "profile_fixture_id": None, "cleanup": {"not_started": True}}
        from .fee_regtest_safety import FAULTS
        if fixture.case == "F3-14" and fixture.name in FAULTS:
            result.update(test_layer="FAULT_INJECTED_REAL_CORE", fault_boundary=FAULTS[fixture.name])
        if setup:
            result["blocker"] = {"actor": actor,
                "action": ("inspect retained original owner before another fixture"
                           if setup == "F3_PRIOR_OWNER_UNCERTAIN"
                           else "provide native host and authenticated inputs"),
                "code": setup}
        else:
            try:
                run_fixture(fixture, app, adapter, args.core, args.wsp_source, result, actor=actor)
            except Exception as error:
                # An exception outside the scenario's protected lifetime must
                # never permit a second owner or erase the failed receipt.
                result.update(status="FAIL", failure_code=failure_code(error), cleanup={
                    "verified_original_owner_shutdown": False, "profile_retained": True,
                    "actor": actor, "action": "inspect unverified setup/owner before continuing"})
        result["ended_utc"] = utc()
        expected_ok_status = CHARACTERIZATION_PENDING_STATUS if fixture.characterization else "PASS"
        result["exit_code"] = 0 if result["status"] == expected_ok_status else 2
        observations = result.pop("observations", {})
        for name, payload in (("policy.json", observations.get("policy", [])),
                              ("events.json", {k: v for k, v in observations.items() if k != "policy"}),
                              ("tma.json", result.pop("tma", {}))):
            result["artifacts"][name] = write_artifact(folder / name, payload)
        if fixture.characterization:
            if result["status"] == CHARACTERIZATION_PENDING_STATUS and not valid_characterization_result(result):
                result.update(status="FAIL", exit_code=2, failure_code="F3_REPORT_CONTRACT_INCOMPLETE")
        elif result["status"] == "PASS" and not valid_pass_result(result):
            result.update(status="FAIL", exit_code=2, failure_code="F3_REPORT_CONTRACT_INCOMPLETE")
        digests[fixture.name] = write_artifact(folder / "result.json", result)
        results[fixture.name] = result["status"]
        print(f"FEE3 {fixture.case}/{fixture.name} {result['status']}", flush=True)
        # Never create another owner while shutdown is unverified.
        if result.get("cleanup", {}).get("verified_original_owner_shutdown") is False:
            setup = "F3_PRIOR_OWNER_UNCERTAIN"
    unchanged = source_identity() == identity
    status = aggregate_status(results) if unchanged else "FAIL"
    write_artifact(args.output / "manifest.json", {
        "schema": "wam-fee3-source-run/v1", "status": status, "cases": results,
        "result_sha256": digests, "source_unchanged": unchanged, "exit_code": 0 if status == "PASS" else 2,
        "outside_step": dict(OUTSIDE_STEP),
        "accepted": False, "engineering_handoff": False,
    })
    if exit_on_uncertain and setup == "F3_PRIOR_OWNER_UNCERTAIN":
        # Receipts (including every later BLOCKED row) are durable first.
        # A retained non-daemon owner must not trap CLI interpreter shutdown.
        # Do not adopt/kill its Core PID or release its custody from this thread.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(2)
    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main(exit_on_uncertain=True))
