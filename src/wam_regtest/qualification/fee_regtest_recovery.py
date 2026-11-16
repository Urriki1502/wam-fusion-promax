"""FEE-3 recovery fixtures and fail-closed oracles; no wallet authority.

All observations wrap real operations. Public evidence contains digests only,
never tokens, recipients, raw transactions, PSBTs or decrypted evidence bodies.
"""
from __future__ import annotations

from .fee_regtest import assertions_pass, reopen_clean_holds

MUTATIONS = frozenset(("SIGN", "MARK_SIGNED", "RELEASE_DRAFT", "SENDRAWTRANSACTION",
                       "GENERATETOADDRESS", "GENERATEBLOCK", "GENERATE", "SUBMITBLOCK",
                       "ADDNODE", "PRIORITISETRANSACTION", "SENDTOADDRESS", "SENDMANY",
                       "INVALIDATEBLOCK", "RECONSIDERBLOCK", "ABANDONTRANSACTION",
                       "SETBAN", "DISCONNECTNODE"))
GUI_SIGN = {"gui_sign_review", "gui_sign_cancel_default", "gui_no_manual_fee_field"}
CANCEL = {"cancel_window", "cancel_replay_refused", "cancel_restart_consistent"}
SPEND = {"same_signed_evidence", "persisted_fee_metadata", "reopen_read_only",
         "submission_write_ahead", "one_submission_no_resign", "replay_refused",
         "confirmed_debit", "history_exact_debit", "reopen_clean", "sign_order"}


def recovery_assertions(fixture):
    if fixture.case == "F3-13":
        if fixture.name == "fresh-cancel":
            return GUI_SIGN | CANCEL
        return {"gui_no_manual_fee_field", "unsigned_reopen_read_only"} | CANCEL
    return GUI_SIGN | SPEND | ({"resumable_status", "explicit_resume_approval"} if fixture.case == "F3-11" else {
        "gui_broadcast_review", "gui_broadcast_cancel_default", "pending_recovered"})


def read_only_holds(before, after, events, state):
    """Reactivation may advance the native anchor; authoritative rows may not change."""
    try:
        return (not MUTATIONS.intersection(events)
                and before["reservation_sha256"] == after["reservation_sha256"]
                and bool(after["reservation_states"])
                and set(after["reservation_states"]) == {state}
                and before["balance"] == after["balance"]
                and after["balance"]["available_atoms"] < after["balance"]["confirmed_atoms"]
                and before["mempool"] == after["mempool"]
                and before["identity_sha256"] == after["identity_sha256"]
                and before["tip"] == after["tip"]
                and after["anchor_generation"] >= before["anchor_generation"]
                and not after["faulted"])
    except (KeyError, TypeError):
        return False


def same_signed_holds(original, recovered):
    try:
        keys = ("raw_sha256", "encrypted_sha256", "txid", "atoms", "fee", "vsize", "commitment", "token_sha256")
        return (all(original[k] == recovered[k] for k in keys)
                and all(type(original[k]) is int and original[k] > 0 for k in ("atoms", "fee", "vsize"))
                and all(type(original[k]) is str and len(original[k]) == 64
                        and all(c in '0123456789abcdef' for c in original[k])
                        for k in ("raw_sha256", "encrypted_sha256", "txid", "commitment", "token_sha256")))
    except (KeyError, TypeError):
        return False


def resumable_status_holds(status, evidence):
    try:
        item, = status["intents"]
        return (status["write_attempted"] is False and status["automatic_resume"] is False
                and status["abandon_available"] is False and status["mainnet_allowed"] is False
                and item["classification"] == "SIGNED_NOT_SUBMITTED_RESUMABLE"
                and item["evidence"] == "verified" and item["state"] == "signed"
                and all(item[k] == evidence[k] for k in ("txid", "atoms", "fee")))
    except (KeyError, TypeError, ValueError):
        return False


def refusal_keeps_locks_holds(before, after, events, refusal):
    return (refusal in ("Q06_RESUME_NOT_ELIGIBLE", "Q06_RESUME_SESSION_NOT_IDLE",
                        "Q06_INTENT_STATUS_SESSION_FAULTED")
            and read_only_holds(before, after, events, "signed"))


def submission_order_holds(events, submissions, expected):
    """A successful save of all-uncertain rows AND sealed evidence precedes send."""
    try:
        send, = [i for i, e in enumerate(events) if e == "SENDRAWTRANSACTION"]
        evidence = events.index("EVIDENCE_UNCERTAIN_SAVED")
        durable = events.index("SAVE_UNCERTAIN")
        row, = submissions
        return (evidence < durable < send
                and row["states"] == ["uncertain"]
                and row["raw_sha256"] == expected["raw_sha256"]
                and row["uncertain_evidence_txid"] == expected["txid"])
    except (KeyError, ValueError, TypeError):
        return False


def history_debit_holds(snapshot, txid, amount, fee):
    """The public snapshot projects history as net atoms, not ledger columns."""
    try:
        row, = [r for r in snapshot["history"] if r["txid"] == txid]
        return type(row["atoms"]) is int and row["atoms"] == -(amount + fee)
    except (KeyError, TypeError, ValueError):
        return False


def resume_order_holds(events, submissions, expected):
    """Recovered bytes use an explicit resume window, with no second crypto."""
    try:
        start, = [i for i, e in enumerate(events) if e == "ACTION_RESUME_INTENT"]
        end = next((i for i in range(start + 1, len(events))
                    if events[i].startswith("ACTION_")), len(events))
        window = events[start:end]
        if {"SIGN", "MARK_SIGNED", "RELEASE_DRAFT"}.intersection(window):
            return False
        evidence = window.index("EVIDENCE_UNCERTAIN_SAVED")
        durable = window.index("SAVE_UNCERTAIN")
        send = window.index("SENDRAWTRANSACTION")
        return (submission_order_holds(window, submissions, expected)
                and window.count("TESTMEMPOOLACCEPT") == 2
                and "TESTMEMPOOLACCEPT" in window[:evidence]
                and "SAVE" in window[evidence + 1:durable]
                and "TESTMEMPOOLACCEPT" in window[durable + 1:send]
                and "SAVE" in window[send + 1:])
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def cancel_holds(before, draft, after, events, releases):
    try:
        return (not (MUTATIONS - {"RELEASE_DRAFT"}).intersection(events)
                and events.count("RELEASE_DRAFT") == 1
                and releases == [draft["token_sha256"]]
                and draft["reservation_states"] == ["draft"]
                and after["reservations"] == 0 and after["reservation_states"] == []
                and not after["prepared"] and not after["signed"] and not after["faulted"]
                and after["balance"] == before["balance"]
                and after["balance"]["available_atoms"] == after["balance"]["confirmed_atoms"]
                and before["mempool"] == after["mempool"]
                and all(before[k] == after[k] for k in ("identity_sha256", "tip"))
                and after["anchor_generation"] > draft["anchor_generation"])
    except (KeyError, TypeError):
        return False


def cancel_replay_holds(before, after, events, refusal):
    try:
        return (refusal == "WALLET_ONLY_UNSIGNED_DRAFT_CAN_CANCEL"
                and not MUTATIONS.intersection(events)
                and all(before[k] == after[k] for k in (
                    "reservation_sha256", "anchor_sha256", "balance", "mempool", "tip", "identity_sha256")))
    except (KeyError, TypeError):
        return False


def fee_metadata_holds(persisted, original):
    # Missing persistence is a candidate failure, never rebuilt from the report.
    return isinstance(persisted, dict) and bool(persisted) and persisted == original


def approve_resume(app, window, idle, wait, checks):
    """Click Yes on the real QMessageBox after checking its default-No choice."""
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QMessageBox
    timer = QTimer()
    timer.setInterval(150)
    acted = []
    def inspect():
        for dialog in app.allWidgets():
            if isinstance(dialog, QMessageBox) and dialog.isVisible():
                yes, no = (dialog.button(b) for b in (
                    QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No))
                if yes is not None and no is not None:
                    checks["explicit_resume_approval"] = dialog.defaultButton() is no
                    timer.stop()
                    acted.append(True)
                    (yes if checks["explicit_resume_approval"] else no).click()
                    return
    timer.timeout.connect(inspect)
    timer.start()
    try:
        window.resume.click()
        wait(lambda: idle() and bool(acted) and window._pending_confirm_txid is not None,
             "EXPLICIT_RESUME")
    finally:
        timer.stop()


def run_recovery(fixture, *, app, request, restart, current_window, idle, wait,
                 approve, approve_payment, observations, before, destination, checks, result):
    """Shared unchanged by source/frozen runners; each independent fixture is fresh."""
    from .fee_regtest_runner import require, quote_checks, review_evidence
    from .fee_regtest import confirmed_debit_holds, sign_order_holds
    from ..bip39_locale import t

    def inspect():
        return request("fee_inspect", timeout=240)

    def replay(action, *args):
        from .q06_fix_scenarios import failure_code
        try:
            request(action, *args, timeout=240)
        except Exception as error:
            return failure_code(error)
        return None

    def reopen():
        restart()
        return current_window()

    window = current_window()
    window.recipient_input.setText(destination)
    window.amount_input.setText("%d.%08d" % divmod(fixture.amount, 100_000_000))
    if fixture.case == "F3-13":
        if fixture.name == "fresh-cancel":
            captured = {"capture_draft": inspect}
            start = len(observations["events"])
            release_start = len(observations["releases"])
            approve_payment(app, window, window.send, t("pages.approve_sign"),
                lambda: idle() and window.status.text() == t("owner.draft_cancelled"),
                wait, checks, result, "sign", decision="cancel", captured=captured)
            review = captured["review"]
            # Capture the exact active draft at the visible approval boundary.
            draft = captured["draft"]
        else:
            review = request("prepare_auto", destination, fixture.amount, timeout=240)
            draft = inspect()
            window = reopen()
            reopened = inspect()
            checks["unsigned_reopen_read_only"] = read_only_holds(
                draft, reopened, observations["events"][observations["restart_start"]:], "draft")
            wait(lambda: idle() and window._recovered_unsigned_cancel and window.cancel.isEnabled(),
                 "RECOVERED_UNSIGNED_CANCEL")
            start = len(observations["events"])
            release_start = len(observations["releases"])
            observations["events"].append("ACTION_CANCEL")
            window.cancel.click()
            wait(lambda: idle() and not window._recovered_unsigned_cancel, "CANCEL")
            # No Sign approval is used for the deliberately unsigned fixture.
            checks["gui_no_manual_fee_field"] = result["no_manual_controls"]
        after = inspect()
        checks["cancel_window"] = cancel_holds(before, draft, after,
            observations["events"][start:], observations["releases"][release_start:])
        checks.update(quote_checks(review, fixture, observations))
        result["review"] = review_evidence(review)
        start = len(observations["events"])
        refusal = replay("cancel")
        checks["cancel_replay_refused"] = cancel_replay_holds(after, inspect(), observations["events"][start:], refusal)
        window = reopen()
        final = inspect()
        checks["cancel_restart_consistent"] = (final["reservations"] == 0
            and final["balance"] == before["balance"] and final["identity_sha256"] == before["identity_sha256"]
            and final["tip"] == before["tip"] and not window._recovered_unsigned_cancel
            and final["reservation_sha256"] == after["reservation_sha256"]
            and final["anchor_generation"] >= after["anchor_generation"])
        result["recovery"] = {"draft": draft, "cancelled": after, "final": final, "replay_refusal": refusal}
        return

    approve_payment(app, window, window.send, t("pages.approve_sign"),
                    lambda: idle() and window._signed_ready, wait, checks, result, "sign")
    review = window._last_review
    result["review"] = review_evidence(review)
    checks.update(quote_checks(review, fixture, observations))
    require(assertions_pass(checks), "F3_RECOVERY_SIGN_ASSERTIONS")
    original = request("fee_signed_evidence")
    result["tma"] = request("fee_preflight", timeout=240)
    require(assertions_pass(result["tma"]["checks"]), "F3_RECOVERY_PREFLIGHT")
    require("SENDRAWTRANSACTION" not in observations["events"], "F3_RECOVERY_EARLY_SUBMIT")
    if fixture.case == "F3-12":
        approve_payment(app, window, window.broadcast, t("pages.approve_broadcast_2"),
            lambda: idle() and window._pending_confirm_txid is not None,
            wait, checks, result, "broadcast")
    held = inspect()
    window = reopen()
    if fixture.case == "F3-12":
        wait(lambda: idle() and window._pending_confirm_txid == original["txid"]
             and window.confirm.isEnabled(), "RECOVERY_PENDING")
    reopened = inspect()
    checks["reopen_read_only"] = read_only_holds(held, reopened,
        observations["events"][observations["restart_start"]:],
        "signed" if fixture.case == "F3-11" else "broadcast")
    recovered = request("fee_signed_evidence")
    checks["same_signed_evidence"] = (same_signed_holds(original, recovered)
        and original["atoms"] == review.atoms and original["fee"] == review.fee
        and original["commitment"] == review.commitment
        and original["vsize"] == review.vsize == result["tma"]["final_vsize"]
        and original["raw_sha256"] == result["tma"]["raw_sha256"]
        and original["txid"] == result["tma"]["txid"])
    checks["persisted_fee_metadata"] = fee_metadata_holds(
        recovered.get("fee_quote"), result["review"]["fee_quote"])
    if fixture.case == "F3-11":
        status = request("intent_status")
        checks["resumable_status"] = resumable_status_holds(status, recovered)
        # Use the actual visible default-No recovery approval.
        window.intents.click()
        wait(lambda: idle() and window._resumable_intent is not None, "INTENT_STATUS")
        checks["reopen_read_only"] &= read_only_holds(held, inspect(),
            observations["events"][observations["restart_start"]:], "signed")
        require(checks["same_signed_evidence"] and checks["resumable_status"]
                and checks["reopen_read_only"], "F3_RECOVERY_AUTHORITY")
        approve_resume(app, window, idle, wait, checks)
    else:
        pending = request("snapshot", timeout=240)
        checks["pending_recovered"] = (pending["pending_confirm_txid"] == original["txid"]
            and window._pending_confirm_txid == original["txid"] and window.confirm.isEnabled()
            and original["txid"] in reopened["mempool"]
            and pending["confirmed_atoms"] == before["balance"]["confirmed_atoms"]
            and pending["available_atoms"] == review.available_after)
    checks["submission_write_ahead"] = submission_order_holds(
        observations["events"], observations.get("submissions", []), original)
    replay_before = inspect()
    start = len(observations["events"])
    refusal = request("fee_resume_replay", original["txid"])
    replay_after = inspect()
    checks["replay_refused"] = (refusal == "Q06_RESUME_SESSION_NOT_IDLE"
        and read_only_holds(replay_before, replay_after, observations["events"][start:], "broadcast")
        and replay_before["anchor_sha256"] == replay_after["anchor_sha256"])
    approve(window.confirm, "Approve", lambda: window._pending_confirm_txid is None, "CONFIRM")
    after = request("snapshot", timeout=240)
    after_inspect = inspect()
    result["confirmed_atoms"] = {"pre": before["balance"]["confirmed_atoms"], "post": after["confirmed_atoms"]}
    checks["confirmed_debit"] = confirmed_debit_holds(
        pre_confirmed_atoms=before["balance"]["confirmed_atoms"], post_confirmed_atoms=after["confirmed_atoms"],
        post_available_atoms=after["available_atoms"], amount=review.atoms, fee=review.fee,
        selected_inputs=result["tma"]["selected_inputs"], reservation_rows=after_inspect["reservation_rows"])
    def history_holds(snapshot):
        return history_debit_holds(snapshot, original["txid"], review.atoms, review.fee)
    checks["history_exact_debit"] = history_holds(after)
    window = reopen()
    final = request("snapshot", timeout=240)
    from ..bip39_owner_gui import reservation_warning
    from ..bip39_fusion_gui import displayed_reserved_inputs
    checks["reopen_clean"] = (reopen_clean_holds(final, expected_confirmed_atoms=after["confirmed_atoms"],
        expected_reservation_count=after["reservation_count"]) and history_holds(final)
        and not window.confirm.isEnabled() and not window.last_txid.text().strip()
        and not reservation_warning(final) and displayed_reserved_inputs(final) == 0)
    events = observations["events"]
    checks["one_submission_no_resign"] = all(events.count(e) == 1 for e in ("SIGN", "MARK_SIGNED", "SENDRAWTRANSACTION"))
    checks["sign_order"] = (resume_order_holds(events, observations.get("submissions", []), original)
                            if fixture.case == "F3-11" else sign_order_holds(events))
    result["recovery"] = {"original": original, "recovered": recovered,
                          "held": held, "reopened": reopened, "replay_refusal": refusal}
