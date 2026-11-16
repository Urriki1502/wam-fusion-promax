"""F3-14 qualification only. Faults are single-boundary, source-only witnesses.

No fault permits synthetic funding, identity, custody, policy approval or success.
All other operations use the owned backend and its real Core transport.
"""
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
import sys
from time import monotonic
from unittest.mock import patch

from .fee_regtest_recovery import MUTATIONS, submission_order_holds
from .fee_regtest import sign_order_holds

NATURAL = ("tamper-sign", "tamper-broadcast", "dismiss-sign", "close-sign",
           "dismiss-broadcast", "close-broadcast", "separate-approvals")
FAULTS = {
    "utxo-changed": "WalletCoreCli.call:gettxout reply",
    "stale-quote": "read_policy_inputs:return mempoolminfee above approved rate",
    "crypto-failure": "Signer.sign:raise before crypto after durable mark",
    "lost-send-response": "WalletCoreCli._call:raise after actual send returns",
}
NAMES = NATURAL + tuple(FAULTS)


def safety_assertions(fixture):
    required = {"safety_invariant", "no_automatic_retry_or_release", "review_unchanged"}
    if fixture.name not in ("tamper-sign", "utxo-changed", "stale-quote", "crypto-failure"):
        required |= {"gui_sign_review", "gui_sign_cancel_default", "gui_no_manual_fee_field"}
    if fixture.name in ("dismiss-broadcast", "close-broadcast", "separate-approvals"):
        required |= {"gui_broadcast_review", "gui_broadcast_cancel_default"}
    return required


def unchanged_holds(before, after, events, refusal, expected):
    """Negative approval and stale/input refusals must not mutate authority."""
    if not isinstance(before, dict) or not isinstance(after, dict) or not isinstance(events, list):
        return False
    try:
        keys = ("reservation_sha256", "anchor_sha256", "balance", "mempool", "tip",
                "identity_sha256", "prepared", "signed", "faulted", "review_sha256")
        return (refusal == expected and not MUTATIONS.intersection(events)
                and all(before[k] == after[k] for k in keys))
    except (KeyError, TypeError):
        return False


def irreversible_holds(snapshot, events, refusal):
    if not isinstance(snapshot, dict) or not isinstance(events, list):
        return False
    try:
        mark, crypto = events.index("MARK_SIGNED"), events.index("SIGN")
        return (refusal == "WALLET_SIGN_UNCERTAIN_LOCK_RETAINED"
                and events.count("MARK_SIGNED") == events.count("SIGN") == 1
                and "SAVE" in events[mark + 1:crypto]
                and snapshot["reservation_states"] == ["signed"]
                and snapshot["faulted"] is True and snapshot["signed"] is False
                and not {"SENDRAWTRANSACTION", "RELEASE_DRAFT"}.intersection(events))
    except (KeyError, ValueError, TypeError):
        return False


def preflight_holds(before, after, events, response):
    if not isinstance(response, dict) or not isinstance(events, list):
        return False
    try:
        return (isinstance(response["checks"], dict)
                and response["mempool_unchanged"] is True
                and {"single_response", "allowed", "vsize", "txid", "wtxid", "base_fee",
                     "effective_rate", "effective_includes"} <= response["checks"].keys()
                and all(v is True for v in response["checks"].values())
                and events.count("TESTMEMPOOLACCEPT") == 1
                and unchanged_holds(before, after, events, None, None))
    except (KeyError, TypeError):
        return False


def uncertain_send_holds(before, after, events, submissions, original, refusal):
    """A lost reply is reconciled read-only against the same owned Core."""
    try:
        return (refusal == "WALLET_BROADCAST_UNCERTAIN_LOCK_RETAINED"
                and after["reservation_states"] == ["uncertain"]
                and after["faulted"] is True and after["signed"] is False
                and all(before[k] == after[k] for k in ("identity_sha256", "tip", "balance"))
                and original["txid"] not in before["mempool"]
                and set(after["mempool"]) == set(before["mempool"]) | {original["txid"]}
                and not {"SIGN", "MARK_SIGNED", "RELEASE_DRAFT"}.intersection(events)
                and submission_order_holds(events, submissions, original))
    except (KeyError, TypeError):
        return False


def no_automatic_holds(events):
    if not isinstance(events, list) or any(type(e) is not str for e in events):
        return False
    return (events.count("SIGN") <= 1 and events.count("MARK_SIGNED") <= 1
            and events.count("SENDRAWTRANSACTION") <= 1 and "RELEASE_DRAFT" not in events)


@contextmanager
def fault_boundary(name, session, observations):
    """Exactly one patched boundary; real methods run everywhere else."""
    if getattr(sys, "frozen", False):
        raise ValueError("F3_SOURCE_ONLY_FAULT_DENIED_FROZEN")
    from ..wallet_session import WalletCoreCli
    from wam_sp.wallet import Signer
    def hit():
        observations.setdefault("fault_hits", []).append(name)
    if name == "stale-quote":
        from ..infrastructure import fee_rpc
        original = fee_rpc.read_policy_inputs
        def stale(*args, **kwargs):
            fresh = original(*args, **kwargs)
            hit()
            return replace(fresh, mempoolminfee=session._review.rate_atoms_per_kvb + 1)
        target, method, replacement = fee_rpc, "read_policy_inputs", stale
    elif name == "crypto-failure":
        def crypto(*args, **kwargs):
            observations["events"].append("SIGN")
            hit()
            raise ValueError("F3_INJECTED_CRYPTO_FAILURE")
        target, method, replacement = Signer, "sign", crypto
    elif name == "utxo-changed":
        original = WalletCoreCli.call
        def missing(obj, method, *args, **kwargs):
            reply = original(obj, method, *args, **kwargs)
            if method == "gettxout":
                hit()
                return None
            return reply
        target, method, replacement = WalletCoreCli, "call", missing
    elif name == "lost-send-response":
        original = WalletCoreCli._call
        def lost(obj, method, *args, **kwargs):
            reply = original(obj, method, *args, **kwargs)
            if method == "sendrawtransaction":
                hit()
                raise ValueError("F3_INJECTED_RESPONSE_LOSS")
            return reply
        target, method, replacement = WalletCoreCli, "_call", lost
    else:
        raise ValueError("F3_SAFETY_FAULT_DENIED")
    with patch.object(target, method, replacement):
        yield


def run_safety(fixture, *, app, window, request, idle, wait, approve_payment,
               observations, destination, checks, result):
    from .fee_regtest_runner import review_evidence, require, quote_checks
    from .q06_fix_scenarios import failure_code
    from ..bip39_locale import t
    from ..fusion_pages import PaymentApproval

    name = fixture.name
    checks["review_unchanged"] = False
    if name in FAULTS:
        require(result["test_layer"] != "FROZEN_QUALIFICATION", "F3_FAULT_NEVER_FROZEN")
        result.update(test_layer="FAULT_INJECTED_REAL_CORE", fault_boundary=FAULTS[name])
    window.recipient_input.setText(destination)
    window.amount_input.setText("%d.%08d" % divmod(fixture.amount, 100_000_000))
    def inspect():
        return request("fee_inspect", timeout=240)
    def refused(action, *args):
        try:
            request(action, *args, timeout=240)
        except Exception as error:
            return failure_code(error)
        return None
    def approve(kind, decision="approve"):
        button = window.send if kind == "sign" else window.broadcast
        if kind == "sign":
            done = (lambda: idle() and window._signed_ready) if decision == "approve" else (
                lambda: idle() and window.status.text() == t("owner.draft_cancelled"))
        else:
            done = (lambda: idle() and window._pending_confirm_txid is not None) if decision == "approve" else (
                lambda: idle() and not any(isinstance(w, PaymentApproval) and w.isVisible() for w in app.allWidgets()))
        approve_payment(app, window, button, t("pages.approve_sign" if kind == "sign" else "pages.approve_broadcast_2"), done,
                        wait, checks, result, kind, decision=decision)

    if name in ("dismiss-sign", "close-sign"):
        captured = {"capture_draft": inspect}
        approve_payment(app, window, window.send, t("pages.approve_sign"),
            lambda: idle() and window.status.text() == t("owner.draft_cancelled"),
            wait, checks, result, "sign", decision="close" if name == "close-sign" else "cancel", captured=captured)
        review = captured["review"]
        after = inspect()
        checks.update(quote_checks(review, fixture, observations))
        checks["review_unchanged"] = captured["draft"]["review_sha256"] == sha256(
            json.dumps(review_evidence(review), sort_keys=True).encode()).hexdigest()
        result["safety"] = {"draft": captured["draft"], "after": after}
        events = observations["events"]
        checks["safety_invariant"] = (events.count("RELEASE_DRAFT") == 1
            and not (MUTATIONS - {"RELEASE_DRAFT"}).intersection(events)
            and after["reservations"] == 0 and not after["signed"] and not after["faulted"])
        end = len(events)
        deadline = monotonic() + 0.5
        wait(lambda: idle() and monotonic() >= deadline, "SAFETY_NO_AUTOMATIC_ACTION")
        app.processEvents()
        final = inspect()
        result["safety"]["final"] = final
        checks["no_automatic_retry_or_release"] = (events.count("RELEASE_DRAFT") == 1
            and not MUTATIONS.intersection(events[end:])
            and after["reservation_sha256"] == final["reservation_sha256"])
    else:
        signed = name in ("tamper-broadcast", "dismiss-broadcast", "close-broadcast",
                          "separate-approvals", "lost-send-response")
        if signed:
            approve("sign")
            review = window._last_review
        else:
            review = request("prepare_auto", destination, fixture.amount, timeout=240)
        checks.update(quote_checks(review, fixture, observations))
        before = inspect()
        result["safety"] = {"before": before}
        start = len(observations["events"])
        original_review = before["review_sha256"]
        if name.startswith("tamper-"):
            action = name.removeprefix("tamper-")
            bad = ("0" if review.commitment[0] != "0" else "1") + review.commitment[1:]
            refusal = refused(action, bad)
            checks["safety_invariant"] = unchanged_holds(before, inspect(), observations["events"][start:],
                refusal, "WALLET_EXACT_INTENT_APPROVAL_REQUIRED" if action == "sign" else "WALLET_BROADCAST_APPROVAL_REQUIRED")
        elif name in ("dismiss-broadcast", "close-broadcast"):
            approve("broadcast", "close" if name == "close-broadcast" else "cancel")
            checks["safety_invariant"] = unchanged_holds(before, inspect(), observations["events"][start:], None, None)
        elif name == "separate-approvals":
            # Signing alone has not submitted anything. Preflight is read-only.
            checks["safety_invariant"] = "SENDRAWTRANSACTION" not in observations["events"]
            result["tma"] = request("fee_preflight", timeout=240)
            checks["safety_invariant"] &= preflight_holds(before, inspect(), observations["events"][start:], result["tma"])
            original = request("fee_signed_evidence")
            approve("broadcast")
            checks["review_unchanged"] = original["commitment"] == review.commitment and original["fee"] == review.fee and original["atoms"] == review.atoms
            checks["safety_invariant"] &= sign_order_holds(observations["events"])
            events = observations["events"]
            sign_action = next((i for i, e in enumerate(events) if e == "ACTION_SIGN"), len(events))
            mark = next((i for i, e in enumerate(events) if e == "MARK_SIGNED"), -1)
            checks["safety_invariant"] &= (sign_action < mark and "GETTXOUT" in events[sign_action:mark])
            checks["safety_invariant"] &= submission_order_holds(observations["events"], observations["submissions"], original)
            checks["safety_invariant"] &= all(checks.get(k) is True for k in (
                "gui_sign_review", "gui_sign_cancel_default", "gui_broadcast_review", "gui_broadcast_cancel_default"))
        else:
            original = request("fee_signed_evidence") if signed else None
            refusal = refused("fee_safety", name, review.commitment)
            after = inspect()
            events = observations["events"][start:]
            result["refusal"] = refusal
            if name == "crypto-failure":
                checks["safety_invariant"] = irreversible_holds(after, events, refusal)
            elif name == "lost-send-response":
                checks["safety_invariant"] = uncertain_send_holds(
                    before, after, events, observations["submissions"], original, refusal)
            else:
                checks["safety_invariant"] = unchanged_holds(before, after, events, refusal,
                    "FEE_QUOTE_STALE" if name == "stale-quote" else "WALLET_REVIEW_UTXO_CHANGED")
            checks["safety_invariant"] &= observations.get("fault_hits") == [name]
        # Wait for the real GUI/worker to settle, then inspect without retrying.
        wait(idle, "SAFETY_IDLE")
        end = len(observations["events"])
        held = inspect()
        deadline = monotonic() + 0.5
        wait(lambda: idle() and monotonic() >= deadline, "SAFETY_NO_AUTOMATIC_ACTION")
        app.processEvents()
        final = inspect()
        result["safety"].update(held=held, final=final)
        if name != "separate-approvals":
            checks["review_unchanged"] = held["review_sha256"] == original_review
        checks["no_automatic_retry_or_release"] = (no_automatic_holds(observations["events"])
            and not MUTATIONS.intersection(observations["events"][end:])
            and held["reservation_sha256"] == final["reservation_sha256"])
    result["safety"]["no_automatic_observation_seconds"] = 0.5
    result["review"] = review_evidence(review)
