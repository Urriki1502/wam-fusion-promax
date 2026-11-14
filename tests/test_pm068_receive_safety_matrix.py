"""PM-068: Receive fixed safety-band geometry across locale/size/theme matrix.

Source-widget regression tests only for the PM-065 fixed header: the
PageTitle and the two Receive warnings stay fully inside the ReceivePage
and the window client area, outside the scrolling body, at both scroll
ends, in every catalog language, client size and appearance. This does
NOT qualify Copy/QR equality, native/frozen builds, VoiceOver, or close
R-7; those gates stay separate.

No real WalletExecutor backend, Core, wallet, profile, network, signing,
credentials, production entrypoint or native settings store is touched:
windows use the passive SimpleNamespace owner and the synthetic
snapshot() fixture, and all construction runs under the PM-063 isolated
INI with the native store disabled.
"""
import itertools
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from PySide6.QtCore import QPoint, QRect
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QLabel

from wam_regtest import ui_settings
from wam_regtest.bip39_locale import t
from wam_regtest.desktop import qt_application
from wam_regtest.fusion_ui import SHELL
from wam_regtest.presentation.strings import SUPPORTED_LANGUAGES

try:
    from tests.test_pm060_d2a_overview_state import snapshot
    from tests.test_pm063_d6a_settings_state import _isolated_ini
except ImportError:  # tests run as top-level modules (unittest discovery)
    from test_pm060_d2a_overview_state import snapshot
    from test_pm063_d6a_settings_state import _isolated_ini

LANGUAGES = tuple(SUPPORTED_LANGUAGES)
SIZES = ((900, 630), (1100, 720), (1440, 900))
# (theme name, existing ThemeSlider appearance index: 1=Light, 2=Dark)
THEMES = (("light", 1), ("dark", 2))
SMALL_SIZE = (900, 630)
VARIANTS = tuple(itertools.product(LANGUAGES, SIZES, THEMES))
WARNING_KEYS = ("pages.silent_payments_note", "pages.disposable_funds")


class ReceiveSafetyMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = qt_application()

    def _pump(self, rounds=4):
        for _ in range(rounds):
            self.app.processEvents()

    def _settle_transition(self, window):
        # Bounded: page slide is PAGE_MS (320ms); never wait unbounded.
        for _ in range(50):
            if window.stack._motion is None and window.stack._shift == 0:
                break
            self.app.processEvents()
            QTest.qWait(20)
        self._pump(4)

    def _cleanup(self, window):
        # Passive owner has no shutdown methods: never call close().
        window._poll.stop()
        window.hide()
        window.deleteLater()
        self._pump(4)

    def _find_fixed_labels(self, page):
        titles = [w for w in page.findChildren(QLabel)
                  if w.objectName() == "PageTitle" and w.text() == t("pages.receive")]
        self.assertEqual(len(titles), 1, "fixed PageTitle by text+objectName")
        title = titles[0]
        self.assertEqual(title.text(), t("pages.receive"))
        warnings = []
        for key in WARNING_KEYS:
            matches = [w for w in page.findChildren(QLabel) if w.text() == t(key)]
            self.assertEqual(len(matches), 1, f"warning label for {key}")
            self.assertEqual(matches[0].text(), t(key))
            warnings.append(matches[0])
        return title, warnings

    def _rect_in(self, widget, ancestor):
        return QRect(widget.mapTo(ancestor, QPoint(0, 0)), widget.size())

    def _assert_contract_at_both_scroll_ends(self, window, phase):
        page = window.receive_page
        self.assertIs(window.stack.currentWidget(), page)
        self.assertTrue(page.isVisible(), phase)
        title, warnings = self._find_fixed_labels(page)
        bar = page.scroll.verticalScrollBar()
        viewport = page.scroll.viewport()
        recorded = []
        for position in (0, bar.maximum()):
            bar.setValue(position)
            self._pump(4)
            self.assertEqual(bar.value(), position, phase)
            viewport_page = self._rect_in(viewport, page)
            entry = {}
            labelled = [("title", title)] + [
                (f"warning{index}", warning)
                for index, warning in enumerate(warnings)]
            for name, widget in labelled:
                self.assertTrue(widget.isVisible(), f"{phase} {name} hidden")
                page_rect = self._rect_in(widget, page)
                window_rect = self._rect_in(widget, window)
                self.assertTrue(
                    page.rect().contains(page_rect),
                    f"{phase} {name} outside page: {page_rect} vs {page.rect()}")
                self.assertTrue(
                    window.rect().contains(window_rect),
                    f"{phase} {name} outside window client: "
                    f"{window_rect} vs {window.rect()}")
                entry[name] = (tuple(page_rect.getRect()),
                               tuple(window_rect.getRect()))
            title_page = self._rect_in(title, page)
            previous_bottom = title_page.bottom()
            for warning in warnings:
                rect = self._rect_in(warning, page)
                self.assertGreaterEqual(
                    rect.x(), SHELL["page_side"],
                    f"{phase} warning x inset: {rect}")
                self.assertGreater(
                    rect.top(), previous_bottom,
                    f"{phase} title/warnings visual order: {rect}")
                previous_bottom = rect.bottom()
                self.assertFalse(
                    page.scroll.isAncestorOf(warning),
                    f"{phase} warning inside body scroll area")
                self.assertFalse(
                    viewport_page.intersects(rect),
                    f"{phase} warning overlaps scroll viewport: "
                    f"{rect} vs {viewport_page}")
                self.assertLess(
                    rect.bottom(), viewport_page.top(),
                    f"{phase} warning not above viewport top: "
                    f"{rect} vs {viewport_page}")
            recorded.append(entry)
        self.assertEqual(
            recorded[0], recorded[1],
            f"{phase} fixed title/warnings moved across scroll: {recorded}")

    def _check_variant(self, language, size, theme_name, theme_index):
        from wam_regtest.bip39_fusion_gui import Bip39FusionWindow
        from wam_regtest.wallet_executor import ExecutorState

        with _isolated_ini():
            self.assertFalse(ui_settings.native_store_enabled())
            with patch("wam_regtest.bip39_locale._lang",
                       return_value=language):
                owner = SimpleNamespace(
                    state=ExecutorState(locked=False, core_alive=True),
                    busy=False, closed=False)
                window = None
                try:
                    window = Bip39FusionWindow(owner)
                    window._poll.stop()
                    # Existing appearance selector API, under isolated INI.
                    window.header_theme.setCurrentIndex(
                        theme_index, animate=False)
                    self._pump()
                    self.assertEqual(window.header_theme.currentIndex(),
                                     theme_index)
                    self.assertEqual(window.settings_theme.currentIndex(),
                                     theme_index)
                    self.assertEqual(window._styled_mode, theme_name)

                    window.resize(*size)
                    window.receive_page.render_snapshot(snapshot())
                    window.navigation.setCurrentRow(1)
                    window.show()
                    self._settle_transition(window)
                    self.assertEqual((window.width(), window.height()), size)
                    self._assert_contract_at_both_scroll_ends(
                        window, f"{language} {size} {theme_name} initial")

                    # Resize down, hide/re-show the SAME window, recheck:
                    # catches stale layout while preserving language/theme.
                    window.resize(*SMALL_SIZE)
                    self._pump()
                    window.hide()
                    self._pump()
                    window.show()
                    self._settle_transition(window)
                    self.assertEqual((window.width(), window.height()),
                                     SMALL_SIZE)
                    self.assertEqual(window.header_theme.currentIndex(),
                                     theme_index)
                    self.assertEqual(window.settings_theme.currentIndex(),
                                     theme_index)
                    self.assertEqual(window._styled_mode, theme_name)
                    self._assert_contract_at_both_scroll_ends(
                        window, f"{language} {size}->{SMALL_SIZE} "
                                f"{theme_name} reshow")
                finally:
                    if window is not None:
                        self._cleanup(window)
            self.assertFalse(ui_settings.native_store_enabled())

    def test_variant_inventory_is_full_cartesian_product(self):
        self.assertEqual(set(LANGUAGES),
                         {"en", "zh-Hans", "vi", "ko", "id", "ja"})
        expected = tuple(itertools.product(LANGUAGES, SIZES, THEMES))
        self.assertEqual(VARIANTS, expected)
        self.assertEqual(len(VARIANTS), 36)
        self.assertEqual(len(set(VARIANTS)), 36)

    def test_receive_safety_band_all_36_variants(self):
        exercised = []
        for language, size, (theme_name, theme_index) in VARIANTS:
            variant = (language, size, (theme_name, theme_index))
            with self.subTest(language=language, size=size, theme=theme_name):
                exercised.append(variant)
                self._check_variant(language, size, theme_name, theme_index)
        self.assertEqual(exercised, list(VARIANTS))
        self.assertEqual(len(exercised), 36)


if __name__ == "__main__":
    unittest.main()
