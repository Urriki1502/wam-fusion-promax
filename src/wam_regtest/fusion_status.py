"""Semantic GUI status from verified backend facts. Never invents Core health."""
from __future__ import annotations

STATES = ('unknown', 'pending', 'verified', 'warning', 'error')


def classify(kind, *, snap=None, locked=False, operational=False, faulted=False,
             core_alive=None, busy=False, network=None):
    """Map one indicator to (state, title, detail). Unknown is not verified."""
    # Called by GUI slots/renderers; keep module import safe for non-GUI users.
    from .bip39_locale import t

    network = network or {}
    if kind not in ('core', 'chain', 'security', 'network', 'snapshot'):
        raise ValueError('FUSION_STATUS_KIND_DENIED')
    if faulted:
        if kind == 'security':
            return ('error', t('status.faulted'),
                    t('status.reservations_preserved'))
        if kind == 'snapshot':
            return ('error', t('status.core_error'), t('status.owned_core_fault'))
        if kind == 'core':
            return ('error', t('status.core_fault'), t('status.core_fault_reservations'))
    if kind == 'core':
        if snap is not None:
            if core_alive is False:
                return ('warning', t('status.identity_pinned'),
                        t('status.pinned_disconnected'))
            if core_alive is True:
                return ('verified', t('status.identity_pinned'),
                        t('status.pinned_snapshot'))
            return ('warning', t('status.identity_pinned'),
                    t('status.pinned_process_unconfirmed'))
        if busy:
            return ('pending', t('status.verifying'), t('status.checking_identity'))
        if core_alive is False:
            return ('unknown', t('status.not_connected'), t('status.core_not_running'))
        if core_alive is True:
            return ('pending', t('status.core_running'), t('status.process_alive_unverified'))
        return ('unknown', t('status.not_verified'), t('status.identity_after_snapshot'))
    if kind == 'chain':
        if snap is not None:
            return ('verified', t('status.height').format(height=str(snap.height)),
                    t('status.verified_height'))
        if busy:
            return ('pending', t('status.syncing'), t('status.waiting_snapshot'))
        return ('unknown', t('status.not_verified'), t('status.height_after_snapshot'))
    if kind == 'security':
        if locked or snap is None or not operational:
            return ('unknown', t('status.locked'),
                    t('status.password_required'))
        return ('warning', t('status.unlocked'),
                t('status.keys_open'))
    if kind == 'network':
        shared = bool(network.get('shared'))
        if 'peer_count' in network and type(network['peer_count']) is int:
            if network.get('connected') is False:
                return ('error', t('status.disconnected'),
                        t('status.peers_disconnected').format(peer_count=str(network['peer_count'])))
            if network.get('connected') is True:
                return ('verified', t('status.connected'),
                        t('status.peers_verified').format(peer_count=str(network['peer_count'])))
            return ('warning', t('status.peer_check'),
                    t('status.peers_unconfirmed').format(peer_count=str(network['peer_count'])))
        if shared:
            return ('pending' if busy else 'unknown', t('status.awaiting_peer_check'),
                    t('status.peer_state_after_check'))
        return ('unknown', t('status.isolated'), t('status.zero_peer'))
    if snap is not None:
        return ('verified', t('status.snapshot_verified'), t('status.wallet_verified_snapshot'))
    if busy:
        return ('pending', t('status.verifying'), t('status.refreshing_state'))
    if core_alive is True:
        return ('pending', t('status.core_running'), t('status.core_alive_unverified'))
    return ('unknown', t('status.snapshot_not_verified'), t('status.header_snapshot_state'))


def never_green_when_unknown(state):
    return state in STATES and state != 'verified'
