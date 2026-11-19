"""PM-060 synthetic characterization. No Core, custody, profile or native store.

Public test address only; PM-041b live incoming is NOT qualified by fixtures.
"""
from dataclasses import replace
import itertools
import json
import unittest
from unittest.mock import patch

from PySide6.QtCore import QPoint, QRect
from PySide6.QtWidgets import QLabel
from wam_regtest.desktop import qt_application
from wam_regtest.bip39_locale import t
from wam_regtest.fusion_status import classify
from wam_regtest.fusion_ui import FusionOverview, pending_amount_text
from wam_regtest.wallet_read import WalletReadSnapshot, HistoryRow
from wam_sp.keystore import ScanAccount
from wam_sp.core import pub


def snapshot(**changes):
    # Public deterministic scan account, never an opened wallet/profile.
    return replace(WalletReadSnapshot(
        'regtest', 112, '34' * 32,
        ScanAccount(0, 1, pub(2), birthday=1).payment_code(),
        100000, 1, (HistoryRow('ab' * 32, 112, 1, 100000, 0),), '56' * 32,
        available_atoms=7000, pending_atoms=None, pending_spent_atoms=None,
        signer_allowed=True, broadcast_allowed=True), **changes)


def result(snap=None, **changes):
    snap = snap or snapshot()
    return dict(fusion_snapshot=snap, receive_code=snap.receive_code,
                confirmed_atoms=snap.confirmed_atoms, available_atoms=snap.available_atoms,
                signer_allowed=snap.signer_allowed, broadcast_allowed=snap.broadcast_allowed,
                height=snap.height, tip=snap.tip, history=(), **changes)


class OverviewState(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = qt_application()

    def page(self):
        page = FusionOverview()
        self.addCleanup(page.deleteLater)
        return page

    def test_every_classifier_leaf_and_card_rendering(self):
        s = snapshot()
        # Expected tone/title/detail are independent literals/catalog keys, not
        # classify compared to itself. Every return leaf, plus fault fallthrough.
        cases = [
            ('core', {'faulted': True}, 'error', 'core_fault', 'core_fault_reservations'),
            ('core', {'snap': s, 'core_alive': False}, 'warning', 'identity_pinned', 'pinned_disconnected'),
            ('core', {'snap': s, 'core_alive': True}, 'verified', 'identity_pinned', 'pinned_snapshot'),
            ('core', {'snap': s}, 'warning', 'identity_pinned', 'pinned_process_unconfirmed'),
            ('core', {'busy': True}, 'pending', 'verifying', 'checking_identity'),
            ('core', {'core_alive': False}, 'unknown', 'not_connected', 'core_not_running'),
            ('core', {'core_alive': True}, 'pending', 'core_running', 'process_alive_unverified'),
            ('core', {}, 'unknown', 'not_verified', 'identity_after_snapshot'),
            ('chain', {'snap': s}, 'verified', 'height', 'verified_height'),
            ('chain', {'busy': True}, 'pending', 'syncing', 'waiting_snapshot'),
            ('chain', {}, 'unknown', 'not_verified', 'height_after_snapshot'),
            ('chain', {'snap': s, 'faulted': True}, 'verified', 'height', 'verified_height'),
            ('security', {'faulted': True}, 'error', 'faulted', 'reservations_preserved'),
            ('security', {'snap': s, 'operational': True, 'locked': True}, 'unknown', 'locked', 'password_required'),
            ('security', {'operational': True}, 'unknown', 'locked', 'password_required'),
            ('security', {'snap': s}, 'unknown', 'locked', 'password_required'),
            ('security', {'snap': s, 'operational': True}, 'warning', 'unlocked', 'keys_open'),
            ('network', {'network': {'peer_count': 0, 'connected': False}}, 'error', 'disconnected', 'peers_disconnected'),
            ('network', {'network': {'peer_count': 2, 'connected': True}}, 'verified', 'connected', 'peers_verified'),
            ('network', {'network': {'peer_count': 2}}, 'warning', 'peer_check', 'peers_unconfirmed'),
            ('network', {'network': {'shared': True}, 'busy': True}, 'pending', 'awaiting_peer_check', 'peer_state_after_check'),
            ('network', {'network': {'shared': True}}, 'unknown', 'awaiting_peer_check', 'peer_state_after_check'),
            ('network', {}, 'unknown', 'isolated', 'zero_peer'),
            ('network', {'network': {'shared': True, 'peer_count': True, 'connected': True}}, 'unknown', 'awaiting_peer_check', 'peer_state_after_check'),
            ('snapshot', {'faulted': True}, 'error', 'core_error', 'owned_core_fault'),
            ('snapshot', {'snap': s, 'locked': True}, 'verified', 'snapshot_verified', 'wallet_verified_snapshot'),
            ('snapshot', {'busy': True}, 'pending', 'verifying', 'refreshing_state'),
            ('snapshot', {'core_alive': True}, 'pending', 'core_running', 'core_alive_unverified'),
            ('snapshot', {}, 'unknown', 'snapshot_not_verified', 'header_snapshot_state'),
        ]
        page = self.page()
        for kind, facts, tone, title, detail in cases:
            with self.subTest(kind=kind, title=title, facts=list(facts)):
                peer = facts.get('network', {}).get('peer_count')
                expected = (tone, t('status.' + title).format(height=112),
                            t('status.' + detail).format(peer_count=peer))
                self.assertEqual(classify(kind, **facts), expected)
                if kind != 'snapshot':
                    card = getattr(page, kind + '_card')
                    page.render_snapshot(**dict({'snap': None}, **facts))
                    self.assertEqual(card.value.text(), expected[1])
                    self.assertEqual(card.detail.text(), expected[2])
        with self.assertRaisesRegex(ValueError, 'FUSION_STATUS_KIND_DENIED'):
            classify('connected')

    def test_optional_amounts_unitless_and_known_zero_numeric_in_real_overview(self):
        page = self.page()
        for invalid in (None, -1, True, False, '0', 0.0, float('nan')):
            with self.subTest(value=repr(invalid)):
                self.assertEqual(pending_amount_text(invalid), t('pending.unknown'))
                page.render_snapshot(snapshot(available_atoms=invalid, pending_atoms=invalid,
                                              pending_spent_atoms=invalid))
                # SPEC-UX0102 §3.1.4 / §4.2.5: no lock summary appends
                # fusion.locks_count_unknown as its own segment. The three
                # amount segments stay one unitless pending.unknown.
                text = page.fund_details.text()
                unknown = t('pending.unknown')
                parts = [part.strip() for part in text.split('  ·  ')]
                self.assertEqual(len(parts), 4)
                self.assertEqual(parts[-1], t('fusion.locks_count_unknown'))
                for part in parts[:3]:
                    self.assertEqual(part.count(unknown), 1)
                    self.assertNotIn('WAM', part)
                self.assertNotIn('WAM', text)
                self.assertNotIn(unknown + ' WAM', text)
        page.render_snapshot(snapshot(confirmed_atoms=0, available_atoms=0,
                                      pending_atoms=0, pending_spent_atoms=0))
        self.assertIn('0.00000000', page.balance_value.text())
        self.assertEqual(page.fund_details.text().count('0.00000000 WAM'), 3)

    def test_four_independent_facts_not_derived_from_each_other_or_activity(self):
        page = self.page()
        page.render_snapshot(snapshot(confirmed_atoms=100000, available_atoms=7000,
                                      pending_spent_atoms=90000, pending_atoms=8000),
                             reservation_count=2)
        self.assertIn('0.00100000', page.balance_value.text())
        for amount in ('0.00007000 WAM', '0.00090000 WAM', '0.00008000 WAM'):
            self.assertIn(amount, page.fund_details.text())
        self.assertIn('2', page.fund_details.text())

    def test_action_predicates_exhaustive_boundary_flags(self):
        from wam_regtest.presentation.action_state import ActionInputs, SharedInputs, available_actions, fusion_actions
        for ready, busy, quit_, fault, locked, spend, reauth, alive, unlock, shared in itertools.product(
                (False, True), (False, True), (False, True), (False, True),
                (False, True), (False, True), (False, True), (None, False, True),
                (False, True), (None, False, True)):
            i = ActionInputs(ready=ready, busy=busy, quit_requested=quit_, faulted=fault,
                locked=locked, spend_enabled=spend, reauthentication_required=reauth,
                core_alive=alive, unlock_allowed=unlock, signed_ready=False,
                pending_confirm=False, approved_commitment=False, recovered_unsigned_cancel=False,
                resumable_intent=False, test_funded=False, executor_closed=False)
            a = available_actions(i)
            f = fusion_actions(i, a, None if shared is None else SharedInputs(True, shared))
            free = not busy and not quit_
            self.assertEqual(a['sync'], ready and not fault and free)
            self.assertEqual(a['lock'], ready and free)
            self.assertEqual(a['unlock'], unlock and not ready and free)
            self.assertEqual(f['custody_switch'], free and (a['lock'] or a['unlock']))
            self.assertEqual(f['open_security'], not quit_)
            # Existing go_send does not itself consult quit_requested (§3 exactness).
            self.assertEqual(f['go_send'], ready and not fault and not locked and not busy
                             and spend and alive is True and not reauth
                             and (shared is None or shared))


class ReceiveGeometry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = qt_application()

    def measure(self, width, height):
        from types import SimpleNamespace
        from wam_regtest.wallet_executor import ExecutorState
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        owner = SimpleNamespace(state=ExecutorState(locked=False, core_alive=True), busy=False, closed=False)
        w = Bip39FusionWindow(owner)
        self.addCleanup(w.deleteLater)
        w._poll.stop()
        w.resize(width, height)
        w.receive_page.render_snapshot(snapshot())
        w.navigation.setCurrentRow(1)
        w.show()
        for _ in range(8): self.app.processEvents()
        page = w.receive_page
        labels = {key: next(x for x in page.findChildren(QLabel) if x.text() == t(key))
                  for key in ('pages.silent_payments_note', 'pages.disposable_funds')}
        view = page.scroll.viewport()
        bar = page.scroll.verticalScrollBar()
        observations = []
        for position in (0, bar.maximum()):
            bar.setValue(position)
            for _ in range(4): self.app.processEvents()
            row = {'client': [w.width(), w.height()], 'scroll': bar.value(),
                   'maximum': bar.maximum(), 'viewport': [view.width(), view.height()]}
            for key, label in dict(labels, address=page.receive_code, qr=page.qr,
                                   copy=page.copy_button).items():
                if key in ('pages.silent_payments_note', 'pages.disposable_funds'):
                    rect = QRect(label.mapTo(page, QPoint(0, 0)), label.size())
                    row[key] = [rect.x(), rect.y(), rect.width(), rect.height()]
                    row[key + '_fully_visible'] = page.rect().contains(rect) and label.isVisible()
                else:
                    rect = QRect(label.mapTo(view, QPoint(0, 0)), label.size())
                    row[key] = [rect.x(), rect.y(), rect.width(), rect.height()]
                    row[key + '_fully_visible'] = view.rect().contains(rect) and label.isVisible()
            observations.append(row)
        print('PM060_R7 ' + json.dumps(observations, sort_keys=True), flush=True)
        w.hide()
        return observations

    def assert_persistent_warning(self, size):
        observations = self.measure(*size)
        for row in observations:
            for key in ('pages.silent_payments_note', 'pages.disposable_funds'):
                self.assertTrue(row[key + '_fully_visible'], 'D2A-1 R-7: ' + json.dumps(row))

    def test_receive_warning_persistent_900(self):
        """D2A-1: R-7 warning is inside scrolling body, below initial fold."""
        self.assert_persistent_warning((900, 630))

    def test_receive_warning_persistent_1100(self):
        """D2A-1: R-7 at 1100×720, both initial and bottom recorded."""
        self.assert_persistent_warning((1100, 720))

    def test_receive_warning_visibility_1440_observation(self):
        rows = self.measure(1440, 900)
        # Today at this height both warnings fit; this is not 36-variant proof.
        for row in rows:
            for key in ('pages.silent_payments_note', 'pages.disposable_funds'):
                self.assertTrue(row[key + '_fully_visible'])

    def test_receive_fixed_header_geometry(self):
        """PM-065: fixed title/warnings stay put at both scroll ends."""
        from types import SimpleNamespace
        from wam_regtest.wallet_executor import ExecutorState
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.fusion_ui import SHELL
        for size in ((900, 630), (1100, 720)):
            with self.subTest(size=size):
                owner = SimpleNamespace(state=ExecutorState(locked=False, core_alive=True), busy=False, closed=False)
                w = Bip39FusionWindow(owner)
                self.addCleanup(w.deleteLater)
                w._poll.stop()
                w.resize(*size)
                w.receive_page.render_snapshot(snapshot())
                w.navigation.setCurrentRow(1)
                w.show()
                for _ in range(8): self.app.processEvents()
                page = w.receive_page
                title = next(x for x in page.findChildren(QLabel)
                             if x.text() == t('pages.receive') and x.objectName() == 'PageTitle')
                warnings = [next(x for x in page.findChildren(QLabel) if x.text() == t(key))
                            for key in ('pages.silent_payments_note', 'pages.disposable_funds')]
                bar = page.scroll.verticalScrollBar()
                for position in (0, bar.maximum()):
                    bar.setValue(position)
                    for _ in range(4): self.app.processEvents()
                    title_rect = QRect(title.mapTo(page, QPoint(0, 0)), title.size())
                    self.assertTrue(title.isVisible())
                    self.assertTrue(page.rect().contains(title_rect),
                                    'title not fully in page: %r %r' % (title_rect, page.rect()))
                    for warning in warnings:
                        rect = QRect(warning.mapTo(page, QPoint(0, 0)), warning.size())
                        self.assertGreaterEqual(rect.x(), SHELL['page_side'])
                        self.assertGreater(rect.top(), title_rect.bottom())
                w.hide()
