"""Which wallet controls are enabled: a pure function of explicit inputs (audit F-08).

Before this module the predicates lived inside ``Bip39TrialWindow._set_actions``
and ``Bip39FusionWindow._set_actions`` and read widget/executor attributes
directly. They are moved here unchanged, so the decision can be tested and
reviewed without Qt, and the windows only gather inputs and apply results.

This is presentation, not authority. Enabling a control never authorizes
anything: prepare/sign/broadcast/cancel require the backend's owned spend
session, confirm re-checks the exact pending TXID, and lock/unlock re-checks
custody on the wallet-owner thread.
"""
from dataclasses import dataclass

BASE_CONTROLS = ('sync', 'fund', 'activate', 'send', 'broadcast', 'cancel', 'confirm',
                 'recovery', 'inspect', 'intents', 'resume', 'lock', 'unlock', 'quit')


@dataclass(frozen=True)
class ActionInputs:
    # Window presentation state (mirrors of backend results; see audit F-08).
    ready: bool
    spend_enabled: bool
    signed_ready: bool
    pending_confirm: bool          # a broadcast TXID awaits its first confirmation
    approved_commitment: bool      # a reviewed, not yet signed payment exists
    recovered_unsigned_cancel: bool
    resumable_intent: bool
    unlock_allowed: bool
    test_funded: bool
    quit_requested: bool
    # Work in flight: a Qt worker, the executor's pending request, or result delivery.
    busy: bool
    # Wallet-owner executor state.
    executor_closed: bool
    faulted: bool
    locked: bool
    reauthentication_required: bool
    core_alive: object             # True / False / None (unknown)


@dataclass(frozen=True)
class SharedInputs:
    coordinator: bool
    connected: bool


def available_actions(i):
    """Enabled state of the base wallet controls (was Bip39TrialWindow._set_actions)."""
    safe = not i.faulted
    spend_safe = (safe and not i.locked and not i.reauthentication_required
                  and i.core_alive is True)
    free = not i.busy and not i.quit_requested
    spend = spend_safe and i.spend_enabled and free
    idle_payment = (not i.approved_commitment and not i.signed_ready
                    and not i.pending_confirm)
    no_payment_in_flight = (idle_payment and not i.resumable_intent
                            and not i.recovered_unsigned_cancel)
    return {
        'sync': i.ready and safe and free,
        'fund': (i.ready and safe and not i.locked and not i.reauthentication_required
                 and i.core_alive is True and free and no_payment_in_flight),
        'activate': i.ready and safe and not i.spend_enabled and free,
        'send': spend and not i.approved_commitment and not i.recovered_unsigned_cancel,
        'broadcast': spend and i.signed_ready,
        'cancel': (spend and (i.approved_commitment or i.recovered_unsigned_cancel)
                   and not i.signed_ready),
        'confirm': spend and i.pending_confirm,
        'recovery': spend and not i.pending_confirm,
        'inspect': spend,
        'intents': spend and idle_payment,
        'resume': spend and idle_payment and i.resumable_intent,
        'lock': i.ready and free,
        'unlock': i.unlock_allowed and not i.ready and free,
        'quit': not i.busy and not i.executor_closed,
    }


def apply_shared_profile(actions, shared):
    """Shared REGTEST mode: only the coordinator mines/confirms; nothing spends offline."""
    if shared is None:
        return dict(actions)
    result = dict(actions)
    if not shared.coordinator:
        result['fund'] = result['confirm'] = False
    if not shared.connected:
        for name in ('fund', 'confirm', 'send', 'broadcast'):
            result[name] = False
    return result


def fusion_actions(i, actions, shared):
    """Fusion-only controls derived from the (shared-adjusted) base actions."""
    idle = not i.busy
    unlocked = not i.locked and i.ready
    ready = i.ready and not i.faulted and not i.locked
    return {
        'reconcile': idle and not i.quit_requested and i.core_alive is True,
        'custody_switch': idle and not i.quit_requested and (actions['lock'] or actions['unlock']),
        'custody_unlocked': unlocked,
        'go_send': (ready and idle and i.spend_enabled and i.core_alive is True
                    and not i.reauthentication_required
                    and (shared is None or shared.connected)),
        'open_security': not i.quit_requested,
    }
