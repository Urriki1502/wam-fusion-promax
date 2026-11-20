"""PM-107: lock/status sentences on Security (and peers) grow with wrapped text.

The wallet-protection lock-status line was rendered in the giant numeric
"value" style (FusionCardValue) that overflows/clips when it wraps (native
Cocoa evidence, monkey-F2-ja-security.png). Presentation-only assertions on an
inert executor; no wallet, Core or secrets.
"""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QRect, Qt
from PySide6.QtWidgets import QApplication, QWidget

from wam_regtest.desktop import qt_application
from wam_regtest.wallet_executor import ExecutorState
from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
from wam_regtest.presentation.strings import text as t

LOCALES = ('en', 'vi', 'zh-Hans', 'ja', 'ko', 'id')
SIZES = ((900, 630), (1100, 720))


def visible_label_clips(lbl):
    """True if the label's wrapped text overflows its own box (ui_layout_probe
    text_fits rule) or spills past its immediate parent (native left-edge clip)."""
    if lbl.isHidden() or not lbl.isVisible():
        return True
    r = lbl.contentsRect()
    if r.width() <= 0 or not lbl.text():
        return True
    fm = lbl.fontMetrics()
    needed = fm.boundingRect(
        QRect(0, 0, max(1, r.width()), 10000),
        int(Qt.TextFlag.TextWordWrap), lbl.text()).height()
    bounds = fm.boundingRect(
        QRect(0, 0, max(1, r.width()), 10000),
        int(Qt.TextFlag.TextWordWrap), lbl.text())
    if r.height() < needed:
        return True
    if bounds.width() > r.width():
        return True
    parent = lbl.parentWidget()
    if parent is not None:
        pr = parent.rect()
        g = lbl.geometry()
        if g.left() < 0 or g.right() > pr.width():
            return True
    return False


class LockLineWrap(unittest.TestCase):
    def setUp(self):
        qt_application()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        old = os.environ.get('WAM_UI_SETTINGS_PATH')
        os.environ['WAM_UI_SETTINGS_PATH'] = str(Path(self.tmp.name) / 'ui.ini')
        self.addCleanup(lambda: os.environ.pop('WAM_UI_SETTINGS_PATH', None)
                        if old is None else os.environ.__setitem__(
                            'WAM_UI_SETTINGS_PATH', old))
        self.w = Bip39FusionWindow(SimpleNamespace(
            state=ExecutorState(), busy=False, closed=False))
        self.w._poll.stop()
        self.w.reduce_motion.setChecked(True)
        self.addCleanup(self.w.deleteLater)

    def _settle(self):
        for _ in range(10):
            QApplication.processEvents()

    def _setsize(self, size):
        self.w.resize(*size)
        self.w.show()

    def _set_lang(self, language):
        self.w.language_tiles[language].click()
        self._settle()

    def _render_state(self, locked):
        # Drive the security lock-status sentence through the real control path.
        self.w._ready = self.w._spend_enabled = True
        self.w.executor.state = ExecutorState(
            locked=locked, faulted=False, core_alive=True)
        self.w._set_actions()
        self._settle()
        # Network peer/status/reconciliation lines (sentence length).
        self.w.network_page.render(
            shared=True, connected=True, peer_count=1, height=112,
            tip='0' * 20, coordinator=True, core_alive=True)
        self.w.receive_page.render_snapshot(None)
        self._settle()

    def test_ja_locked_lock_status_is_sentence_body_not_giant_numeric_value(self):
        """RED gate on the current code: the lock guidance must not use the giant
        numeric value style (its single-line number font overflows the card and
        clips on native Qt). It must be a sentence body label and must carry the
        exact locked copy."""
        self.w = Bip39FusionWindow(SimpleNamespace(
            state=ExecutorState(), busy=False, closed=False))
        self.w._poll.stop()
        self.w.reduce_motion.setChecked(True)
        self._set_lang('ja')
        self._render_state(locked=True)
        label = self.w.security_state
        self.assertEqual(label.text(), t('wallet.security_locked', 'ja'))
        self.assertNotEqual(
            label.objectName(), 'FusionCardValue',
            "lock-status is a sentence, not a giant numeric value")
        self.w.deleteLater()

    def test_security_and_peer_status_lines_never_clip_all_locales_sizes_states(self):
        for language in LOCALES:
            self._set_lang(language)
            for size in SIZES:
                self._setsize(size)
                for locked in (True, False):
                    self._render_state(locked)
                    # Security page -> wallet-protection lock-status line.
                    self.w.navigation.setCurrentRow(4)
                    self._settle()
                    self.assertFalse(visible_label_clips(self.w.security_state),
                                     (language, size, locked,
                                      self.w.security_state.text()))
                    # Network page -> every status/peer/identity line.
                    self.w.navigation.setCurrentRow(5)
                    # The manual-controls guidance sentence only renders once
                    # its collapsible panel is expanded; show it to measure it.
                    self.w.network_page.controls_toggle.setChecked(True)
                    self._settle()
                    for name in ('mode_value', 'connection_value', 'peer_value',
                                 'height_value', 'sync_value', 'identity_value'):
                        lbl = getattr(self.w.network_page, name)
                        self.assertFalse(visible_label_clips(lbl),
                                         (language, size, locked, name,
                                          lbl.text()))
                    self.assertFalse(
                        visible_label_clips(self.w.network_page.controls_note),
                        (language, size, locked,
                         self.w.network_page.controls_note.text()))
                    # Receive page status line.
                    self.w.navigation.setCurrentRow(1)
                    self._settle()
                    self.assertFalse(
                        visible_label_clips(self.w.receive_page.received),
                        (language, size, locked,
                         self.w.receive_page.received.text()))


if __name__ == '__main__':
    unittest.main()
