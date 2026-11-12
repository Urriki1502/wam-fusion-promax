"""Fusion Black & Gold Qt presentation: verified snapshots, never wallet authority."""
from __future__ import annotations
from .bip39_locale import t as ui_text
from .presentation.strings import CATALOG

from PySide6.QtCore import QEvent, QObject, Qt, QRectF, QPointF, QSize, Signal, Property, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import (
    QColor, QPainter, QPen, QIcon, QPixmap, QPolygonF, QLinearGradient,
    QPainterPath, QFont, QFontMetrics, QRadialGradient,
)
from PySide6.QtWidgets import (
    QApplication, QBoxLayout, QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QVBoxLayout, QWidget, QToolTip, QSizePolicy, QTableWidget, QTableWidgetItem,
    QPlainTextEdit, QCheckBox, QToolButton, QButtonGroup,
)
from .wallet_read import WalletReadSnapshot, format_wam
from .branding import brand_image
from .fusion_motion import motion_reduced, slide_geometry, fade_widget, CHART_MS, StatusGlyph
from .fusion_status import classify
from .infrastructure import core_compat

# TOKEN_TABLE_START
# One scale. Kickers and other reading text stay at 12px or larger so CJK
# stays legible. display/heading/section/body/caption are the roles the
# stylesheet and the shell layouts actually read.
SPACING = {'xs': 4, 'sm': 8, 'md': 12, 'lg': 16, 'xl': 24, 'xxl': 32}
TYPE = {
    'display': 56, 'display_compact': 40, 'heading': 28, 'section': 16,
    'brand': 18, 'denom': 24, 'number': 20, 'word': 17, 'body': 14,
    'secondary': 13, 'caption': 12,
}
WEIGHT = {'semibold': 600, 'bold': 700}
TRACKING = {'brand': 0.2, 'kicker': 0.4, 'balance': -1}
RADIUS = {
    'panel': 18, 'inset': 14, 'control': 12, 'nav': 11, 'badge': 10,
    'segment': 9, 'progress': 8, 'check': 4, 'scroll': 3, 'hero': 20,
}
FOCUS = 2
# Shell geometry. Steps that already match the spacing scale reference it.
# The remaining values are the current shell metrics, named so the sidebar,
# top bar, page header and cards do not carry raw pixel literals.
SHELL = {
    'sidebar_width': 232,
    'sidebar_pad_x': 18,
    'sidebar_pad_top': SPACING['xl'],
    'sidebar_pad_bottom': 18,
    'sidebar_gap': 14,
    'brand_gap': SPACING['sm'],
    'logo': 58,
    'logo_box': 62,
    'nav_icon': 18,
    'nav_gap': 2,
    'content_left': 34,
    'content_top': 19,
    'content_right': 30,
    'content_bottom': 17,
    'content_gap': 17,
    'topbar_bottom': 18,
    'topbar_gap': SPACING['md'],
    'divider': 1,
    'page_top': SPACING['xs'],
    'page_side': SPACING['xs'],
    'page_right': SPACING['md'],
    'page_bottom': SPACING['lg'],
    'page_gap': 20,
    'panel_x': 22,
    'panel_y': 20,
    'panel_gap': SPACING['md'],
    'card_x': SPACING['md'],
    'card_y': 10,
    'card_gap': SPACING['xs'],
    'card_row': SPACING['sm'],
    'badge_h': 28,
    'warning_min': 64,
}
# accent is the focus colour. green is received and success. red is error
# only. pending is the in-progress status. shadow had no reader and is gone.
# sent is blue, the history direction, and is not red.
_THEME_COLORS = {
    'dark': dict(
        bg='#0B0B0D', surface='#141416', panel='#1C1C20', text='#F7F4EC',
        muted='#B7B1A4', border='#2F2A22', tint='#1F1C16', accent='#E0C36A',
        onaccent='#1A1406', warning='#3A3018', warning_text='#F1C77D',
        green='#3DDC97', blue='#7EB6FF', red='#FF8B8F', hero_bottom='#1A150C',
        selection='#3A3018', grid='#3A342C', chart_empty='#8E8A80',
        hover='#24221C', sidebar='#09090B', pending='#E5BE79',
        brand='#E8C98A', segment='#1A1814'),
    'light': dict(
        bg='#F6F3EC', surface='#FFFFFF', panel='#F3EEE3', text='#1C1914',
        muted='#6A6458', border='#E4DCC8', tint='#EFE6D4', accent='#7A5A12',
        onaccent='#FFF8E8', warning='#FFF4D8', warning_text='#80561A',
        green='#0F7A52', blue='#1666CC', red='#B8424C', hero_bottom='#F4EBD6',
        selection='#F0E2BE', grid='#E4DCC8', chart_empty='#8E8A80',
        hover='#E8DCC3', sidebar='#F4EFE4', pending='#91601D',
        brand='#9B742E', segment='#E9E1CF'),
}
_DIMMER = 'rgba(12,12,14,0.38)'
# QR modules stay paper and ink in both themes so a camera can read them.
QR = {'paper': '#FFFFFF', 'ink': '#101010', 'caption': '#5D6C82'}
# TOKEN_TABLE_END
# Stable English compatibility view; widgets resolve their labels at construction.
FUSION_NAV_PAGES = (
    (CATALOG['en']['fusion.overview'], 'overview'),
    (CATALOG['en']['fusion.receive'], 'receive'),
    (CATALOG['en']['fusion.history'], 'history'),
    (CATALOG['en']['fusion.send'], 'send'),
    (CATALOG['en']['fusion.security'], 'security'),
    (CATALOG['en']['fusion.network'], 'network'),
    (CATALOG['en']['fusion.settings'], 'settings'),
)


def fusion_nav_pages():
    return (
        (ui_text('fusion.overview'), 'overview'),
        (ui_text('fusion.receive'), 'receive'),
        (ui_text('fusion.history'), 'history'),
        (ui_text('fusion.send'), 'send'),
        (ui_text('fusion.security'), 'security'),
        (ui_text('fusion.network'), 'network'),
        (ui_text('fusion.settings'), 'settings'),
    )


def fusion_palette(mode):
    base = _THEME_COLORS.get(mode)
    if base is None:
        raise ValueError('FUSION_THEME_DENIED')
    colors = dict(base)
    # One stored colour per meaning. These names are aliases, not a second hex.
    colors['focus'] = colors['accent']
    colors['success'] = colors['green']
    colors['error'] = colors['red']
    colors['received'] = colors['green']
    colors['sent'] = colors['blue']
    colors['dimmer'] = _DIMMER
    return colors


def direction_tone(colors, net):
    """Received and sent each use one colour. Red is reserved for errors."""
    try:
        net = int(net)
    except (TypeError, ValueError):
        net = 0
    if net > 0:
        return colors['received']
    if net < 0:
        return colors['sent']
    return colors['muted']


def fusion_stylesheet(mode):
    c = fusion_palette(mode)
    t, w, r, s = TYPE, WEIGHT, RADIUS, SPACING
    ring = FOCUS
    return f"""
    QMainWindow,QWidget#WalletRoot,QDialog,QMessageBox,QInputDialog {{
        background:{c['bg']};color:{c['text']};
    }}
    QWidget {{font-size:{t['body']}px;}}
    QFrame#FusionSidebar {{background:{c['sidebar']};border-right:1px solid {c['border']};}}
    QFrame#FusionTopbar {{background:{c['bg']};border-bottom:1px solid {c['border']};}}
    QFrame#FusionDivider {{background:{c['border']};border:0;}}
    QFrame#FusionPanel,QFrame#ContentCard,QFrame#HeaderCard,QDialog#FusionApproval,QDialog#FusionPanel {{
        background:{c['surface']};border:1px solid {c['border']};border-radius:{r['panel']}px;
    }}
    QFrame#FusionInset {{background:{c['panel']};border:1px solid {c['border']};border-radius:{r['inset']}px;}}
    QFrame#FusionHero {{background:transparent;}}
    QFrame#FusionSegmented {{background:{c['segment']};border:1px solid {c['border']};border-radius:{r['control']}px;}}
    QToolButton#FusionSegment {{background:transparent;color:{c['muted']};border:0;border-radius:{r['segment']}px;padding:{s['sm']}px {s['md']}px;font-weight:{w['semibold']};}}
    QToolButton#FusionSegment:checked {{background:transparent;color:{c['onaccent']};}}
    QToolButton#FusionSegment:hover:!checked {{color:{c['text']};}}
    QToolButton#FusionAdvanced {{background:transparent;color:{c['accent']};border:0;text-align:left;padding:10px;font-weight:{w['semibold']};}}
    QToolButton#FusionQuick {{
        background:{c['surface']};color:{c['text']};border:1px solid {c['border']};
        border-radius:{r['inset']}px;padding:{s['md']}px 14px;font-weight:{w['semibold']};text-align:left;
    }}
    QToolButton#FusionQuick:hover:enabled {{border:1px solid {c['accent']};background:{c['hover']};}}
    QToolButton#FusionQuick:disabled {{color:{c['muted']};}}
    QFrame#FusionThemeThumb {{background:{c['accent']};border:0;border-radius:{r['badge']}px;}}
    QFrame#FusionDimmer {{background:{c['dimmer']};border:0;}}
    QFrame#FusionFlyout {{
        background:{c['surface']};border:1px solid {c['border']};border-radius:{r['panel']}px;
    }}
    QWidget#FusionInner,QScrollArea#FusionScroll,QWidget#FusionTransparent,QWidget#FusionHeroCopy {{background:transparent;border:0;}}
    QLabel {{color:{c['text']};background:transparent;border:0;}}
    QLabel#BrandTitle {{font-size:{t['brand']}px;font-weight:{w['bold']};letter-spacing:{TRACKING['brand']}px;color:{c['brand']};}}
    QLabel#PageTitle {{font-size:{t['heading']}px;font-weight:{w['bold']};}}
    QLabel#FusionBalance,QLabel#BalanceValue {{font-size:{t['display']}px;font-weight:{w['bold']};color:{c['text']};letter-spacing:{TRACKING['balance']}px;}}
    QLabel#FusionDenom {{font-size:{t['denom']}px;font-weight:{w['bold']};color:{c['brand']};}}
    QLabel#FusionKicker {{font-size:{t['caption']}px;font-weight:{w['semibold']};color:{c['muted']};letter-spacing:{TRACKING['kicker']}px;}}
    QLabel#FusionCardTitle {{font-size:{t['section']}px;font-weight:{w['semibold']};}}
    QLabel#FusionCardValue {{font-size:{t['number']}px;font-weight:{w['semibold']};}}
    QLabel#FusionMuted,QLabel#SecondaryLabel,QLabel#StatusText,QLabel#FusionEmpty {{color:{c['muted']};font-size:{t['secondary']}px;}}
    QLabel#FusionVerified {{color:{c['success']};font-weight:{w['semibold']};}}
    QLabel#FusionInfo {{color:{c['blue']};}}
    QLabel#FusionGold {{color:{c['warning_text']};font-weight:{w['semibold']};}}
    QLabel#FusionBadge {{color:{c['onaccent']};background:{c['accent']};border:0;border-radius:{r['badge']}px;padding:5px 10px;font-size:{t['caption']}px;font-weight:{w['bold']};}}
    QLabel#Warning {{color:{c['warning_text']};background:{c['warning']};border-radius:{r['segment']}px;padding:10px;min-height:{SHELL['warning_min']}px;font-size:{t['caption']}px;}}
    QLabel#ReceiveCode,QPlainTextEdit#ReceiveCode {{
        font-size:{t['body']}px;background:{c['panel']};border:1px solid {c['border']};border-radius:{r['control']}px;padding:{s['lg']}px;
    }}
    QListWidget {{background:transparent;color:{c['muted']};border:0;padding:2px;font-size:{t['body']}px;outline:0;}}
    QListWidget::item {{padding:9px {s['md']}px;border-radius:{r['nav']}px;margin:2px 0;}}
    QListWidget::item:selected {{background:{c['accent']};color:{c['onaccent']};font-weight:{w['bold']};}}
    QListWidget::item:hover:!selected {{background:{c['hover']};color:{c['text']};}}
    QListWidget:focus {{border:{ring}px solid {c['focus']};padding:0;}}
    QLineEdit,QTextEdit,QPlainTextEdit {{
        background:{c['panel']};color:{c['text']};selection-background-color:{c['selection']};
        border:1px solid {c['border']};border-radius:{r['control']}px;padding:{s['md']}px;
    }}
    QLineEdit:focus,QTextEdit:focus,QPlainTextEdit:focus {{border:{ring}px solid {c['focus']};padding:11px;}}
    QPushButton:focus,QComboBox:focus {{border:{ring}px solid {c['focus']};padding:11px 16px;}}
    QToolButton:focus {{border:{ring}px solid {c['focus']};}}
    QPlainTextEdit#ReceiveCode:focus {{border:{ring}px solid {c['focus']};padding:15px;}}
    QToolButton#FusionSegment:focus {{border:{ring}px solid {c['focus']};padding:6px 10px;}}
    QToolButton#FusionQuick:focus {{border:{ring}px solid {c['focus']};padding:10px 12px;}}
    QToolButton#FusionAdvanced:focus {{border:{ring}px solid {c['focus']};padding:8px;}}
    QLineEdit:disabled {{color:{c['muted']};background:{c['bg']};}}
    QPushButton,QComboBox {{
        background:{c['tint']};color:{c['text']};border:1px solid {c['border']};
        border-radius:{r['control']}px;padding:{s['md']}px 17px;font-weight:{w['semibold']};
    }}
    QPushButton#PrimaryButton,QPushButton#FusionPrimary {{
        background:{c['accent']};color:{c['onaccent']};border:1px solid {c['accent']};
    }}
    QPushButton#FusionPrimary:focus,QPushButton#PrimaryButton:focus {{border:{ring}px solid {c['onaccent']};padding:11px 16px;}}
    QPushButton#FusionSecondary {{background:{c['tint']};color:{c['text']};border:1px solid {c['border']};}}
    QPushButton#FusionDestructive {{background:{c['surface']};color:{c['error']};border:1px solid {c['border']};}}
    QPushButton:hover:enabled,QComboBox:hover {{background:{c['hover']};border:1px solid {c['focus']};}}
    QPushButton#FusionPrimary:hover:enabled,QPushButton#PrimaryButton:hover:enabled {{
        background:{c['brand']};border:1px solid {c['onaccent']};
    }}
    QPushButton:pressed:enabled {{background:{c['selection']};}}
    QPushButton#FusionPrimary:disabled,QPushButton#PrimaryButton:disabled,
    QPushButton#FusionSecondary:disabled,QPushButton#FusionDestructive:disabled,QPushButton:disabled {{
        background:{c['panel']};color:{c['muted']};border:1px solid {c['border']};
    }}
    QComboBox::drop-down {{border:0;width:22px;}}
    QComboBox QAbstractItemView {{
        background:{c['surface']};color:{c['text']};selection-background-color:{c['selection']};
        border:1px solid {c['border']};
    }}
    QCheckBox {{color:{c['text']};spacing:{s['sm']}px;}}
    QCheckBox::indicator {{width:17px;height:17px;border:1px solid {c['muted']};border-radius:{r['check']}px;background:{c['panel']};}}
    QCheckBox::indicator:checked {{background:{c['accent']};border:1px solid {c['accent']};}}
    QCheckBox::indicator:focus {{border:{ring}px solid {c['focus']};}}
    QCheckBox::indicator:checked:focus {{background:{c['accent']};border:{ring}px solid {c['onaccent']};}}
    QTableWidget,QTableWidget#FusionActivityTable {{
        background:{c['surface']};alternate-background-color:{c['surface']};color:{c['text']};
        border:0;gridline-color:{c['border']};selection-background-color:{c['selection']};selection-color:{c['text']};
    }}
    QTableWidget:focus,QTableWidget#FusionActivityTable:focus {{border:{ring}px solid {c['focus']};}}
    QTableWidget::item {{padding:10px;border-bottom:1px solid {c['border']};}}
    QTableWidget::item:selected {{background:{c['selection']};color:{c['text']};}}
    QTableWidget::item:focus {{border:{ring}px solid {c['focus']};}}
    QHeaderView::section {{
        background:{c['surface']};color:{c['muted']};border:0;border-bottom:1px solid {c['border']};
        padding:10px;font-size:{t['caption']}px;font-weight:{w['semibold']};
    }}
    QProgressBar:horizontal {{background:{c['panel']};border:1px solid {c['border']};border-radius:{r['progress']}px;min-height:6px;max-height:6px;}}
    QProgressBar::chunk {{background:{c['accent']};border-radius:{r['check']}px;}}
    QScrollBar:vertical {{background:transparent;width:7px;}}
    QScrollBar::handle:vertical {{background:{c['border']};border-radius:{r['scroll']}px;min-height:30px;}}
    QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{height:0;}}
    QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical {{background:transparent;}}
    QToolTip {{background:{c['surface']};color:{c['text']};border:1px solid {c['border']};padding:{s['sm']}px;}}
    """


class StateSwitch(QCheckBox):
    """Two-position visual switch retaining Qt checkbox focus/key semantics."""
    def sizeHint(self):
        return QSize(self.fontMetrics().horizontalAdvance(self.text()) + 68, 34)

    def hitButton(self, position):
        return self.rect().contains(position)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if not self.isEnabled():
            painter.setOpacity(0.45)
        mode = self.property('fusion_mode') or 'dark'
        colors = fusion_palette(mode if mode in ('dark', 'light') else 'dark')
        track = QRectF(2, (self.height() - 24) / 2, 46, 24)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(colors['success'] if self.isChecked() else colors['border']))
        painter.drawRoundedRect(track, 12, 12)
        painter.setBrush(QColor(colors['onaccent'] if self.isChecked() else colors['text']))
        painter.drawEllipse(QRectF(28 if self.isChecked() else 6, track.y() + 4, 16, 16))
        painter.setPen(QColor(colors['text']))
        painter.drawText(QRectF(58, 0, self.width() - 58, self.height()),
                         Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, self.text())
        if self.hasFocus():
            # Sit the ring outside the track so it is read against the
            # surface behind the switch, not against the green fill.
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(QColor(colors['focus']), FOCUS))
            painter.drawRoundedRect(track.adjusted(-3, -3, 3, 3), 15, 15)


class ThemeSlider(QFrame):
    """Three-position Automatic / Light / Dark control with a sliding thumb."""
    currentChanged = Signal(int)

    def __init__(self, *, compact=False):
        super().__init__()
        self.setObjectName('FusionSegmented')
        self.setAccessibleName(ui_text('fusion.appearance_choices'))
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._index = 0
        self._compact = compact
        self._move = None
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.buttons = []
        layout = QHBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(0)
        self._indicator = QFrame(self)
        self._indicator.setObjectName('FusionThemeThumb')
        self._indicator.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        for index, (icon, title) in enumerate((('auto', ui_text('fusion.automatic')), ('sun', ui_text('fusion.light')), ('moon', ui_text('fusion.dark')))):
            button = QToolButton()
            button.setObjectName('FusionSegment')
            button.setCheckable(True)
            button.setAutoRaise(True)
            button.setText('' if compact else title)
            button.setToolTip(title)
            button.setAccessibleName(title + ui_text('fusion.appearance'))
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setFocusPolicy(Qt.FocusPolicy.TabFocus)
            button.setProperty('fusion_icon', icon)
            button.setToolButtonStyle(
                Qt.ToolButtonStyle.ToolButtonIconOnly if compact
                else Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            button.setMinimumWidth(36 if compact else 96)
            self.group.addButton(button, index)
            self.buttons.append(button)
            layout.addWidget(button, 1)
        self.buttons[0].setChecked(True)
        self.group.idClicked.connect(self._clicked)
        self.setFixedHeight(36 if compact else 42)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        if compact:
            self.setFixedWidth(138)
        else:
            self.setMaximumWidth(420)

    def currentIndex(self):
        return self._index

    def setCurrentIndex(self, index, animate=True):
        if index not in (0, 1, 2):
            return
        block = self.group.blockSignals(True)
        self.buttons[index].setChecked(True)
        self.group.blockSignals(block)
        self._slide(index, animate=animate)
        if index != self._index:
            self._index = index
            self.currentChanged.emit(index)

    def _clicked(self, index):
        self._slide(index, animate=True)
        if index != self._index:
            self._index = index
            self.currentChanged.emit(index)

    def _thumb_rect(self, index):
        return self.buttons[index].geometry().adjusted(2, 2, -2, -2)

    def _slide(self, index, animate=True):
        rect = self._thumb_rect(index)
        if self._move is not None:
            self._move.stop()
            self._move = None
        if not animate or motion_reduced(self):
            self._indicator.setGeometry(rect)
            return
        self._move = slide_geometry(self._indicator, rect, parent=self)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._indicator.setGeometry(self._thumb_rect(self._index))
        self._indicator.lower()
        for button in self.buttons:
            button.raise_()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Home, Qt.Key.Key_End):
            if event.key() == Qt.Key.Key_Left:
                index = max(0, self._index - 1)
            elif event.key() == Qt.Key.Key_Right:
                index = min(2, self._index + 1)
            elif event.key() == Qt.Key.Key_Home:
                index = 0
            else:
                index = 2
            self.setCurrentIndex(index)
            event.accept()
            return
        super().keyPressEvent(event)


class ReadableText(QPlainTextEdit):
    """Selectable exact plaintext with genuine wrap-anywhere; no hidden characters."""
    def __init__(self, text=''):
        super().__init__()
        from PySide6.QtGui import QTextOption, QFontDatabase
        self.setReadOnly(True)
        self.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        families = set(QFontDatabase.families())
        family = next((f for f in ('Menlo', 'Consolas', 'Courier New') if f in families), None)
        self.setFont(QFont(family, 10) if family else QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumWidth(0)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setPlainText(text)
        self._fit()

    def text(self):
        return self.toPlainText()

    def setText(self, text):
        if text != self.toPlainText():
            self.setPlainText(text)
        self._fit()

    def _fit(self):
        import math
        fm = self.fontMetrics()
        width = max(80, self.viewport().width() - 28)
        lines = sum(max(1, math.ceil(fm.horizontalAdvance(line) / width)) for line in self.toPlainText().split('\n'))
        self.setFixedHeight(min(340, max(100, lines * fm.lineSpacing() + 64)))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit()

    def minimumSizeHint(self):
        return QSize(0, 68)


def grow_with_wrapped_text(widget):
    """Let a word-wrapped label take the height its wrapped text needs.

    label() gives wrapped labels a vertical Maximum policy, which keeps them
    at their unwrapped height. Text that wraps to more lines (for example CJK
    at the narrow sidebar width) was then clipped (V0-A1, V0-A4)."""
    policy = widget.sizePolicy()
    policy.setVerticalPolicy(QSizePolicy.Policy.Minimum)
    policy.setHeightForWidth(True)
    widget.setSizePolicy(policy)
    return widget


def label(text='', role='FusionMuted', selectable=False):
    if role == 'ReceiveCode':
        obj = ReadableText(text)
        obj.setObjectName(role)
        return obj
    obj = QLabel(text)
    obj.setObjectName(role)
    obj.setWordWrap(role not in ('FusionKicker', 'FusionBadge'))
    obj.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
    if role in ('FusionCardTitle', 'FusionCardValue', 'FusionMuted', 'FusionBalance', 'BalanceValue'):
        obj.setMinimumWidth(0)
    if role in ('FusionCardTitle', 'FusionCardValue'):
        obj.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        obj.setWordWrap(True)
    if role in ('FusionBalance', 'BalanceValue'):
        obj.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        obj.setMinimumHeight(TYPE['display'])
        obj.setWordWrap(True)
    if role == 'FusionDenom':
        obj.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Minimum)
    if role == 'FusionBadge':
        obj.setFixedHeight(SHELL['badge_h'])
        obj.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
    if selectable:
        obj.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return obj


def present_brand_title(widget, text, width, color):
    """Fit the sidebar brand inside the sidebar column.

    One line when the catalog string fits. Otherwise break on spaces so a
    CJK word is not left as a single character (R-9). The catalog string is
    not changed; a newline here is only the line break.
    """
    widget.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter)
    widget.setWordWrap(False)
    widget.setStyleSheet('')
    size = TYPE['brand']
    display = text
    metrics = None
    while size >= TYPE['caption']:
        font = QFont(widget.font())
        font.setPixelSize(size)
        font.setWeight(QFont.Weight.Bold)
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, TRACKING['brand'])
        metrics = QFontMetrics(font)
        if metrics.horizontalAdvance(text) <= width:
            display = text
            break
        broken = _brand_lines(text, metrics, width)
        if broken is not None:
            display = broken
            break
        size -= 1
    else:
        size = TYPE['caption']
        display = text
        font = QFont(widget.font())
        font.setPixelSize(size)
        font.setWeight(QFont.Weight.Bold)
        metrics = QFontMetrics(font)
    widget.setText(display)
    if size != TYPE['brand']:
        widget.setStyleSheet(
            'font-size:%dpx;font-weight:%d;letter-spacing:%spx;color:%s;'
            'background:transparent;border:0;'
            % (size, WEIGHT['bold'], TRACKING['brand'], color))
    lines = display.count('\n') + 1
    policy = widget.sizePolicy()
    if lines > 1:
        policy.setVerticalPolicy(QSizePolicy.Policy.Minimum)
        widget.setMinimumHeight(metrics.lineSpacing() * lines + SPACING['xs'])
    else:
        policy.setVerticalPolicy(QSizePolicy.Policy.Maximum)
        widget.setMinimumHeight(0)
    widget.setSizePolicy(policy)


def _brand_lines(text, metrics, width):
    words = text.split(' ')
    if len(words) < 2:
        return None
    best = None
    for index in range(1, len(words)):
        head = ' '.join(words[:index])
        tail = ' '.join(words[index:])
        head_w = metrics.horizontalAdvance(head)
        tail_w = metrics.horizontalAdvance(tail)
        if head_w <= width and tail_w <= width:
            score = (max(head_w, tail_w), abs(head_w - tail_w))
            if best is None or score < best[0]:
                best = (score, head + '\n' + tail)
    return None if best is None else best[1]


def panel(title=None, subtitle=None, *, inset=False):
    obj = QFrame()
    obj.setObjectName('FusionInset' if inset else 'FusionPanel')
    layout = QVBoxLayout(obj)
    layout.setContentsMargins(SHELL['panel_x'], SHELL['panel_y'], SHELL['panel_x'], SHELL['panel_y'])
    layout.setSpacing(SHELL['panel_gap'])
    layout.setAlignment(Qt.AlignmentFlag.AlignTop)
    if title:
        layout.addWidget(label(title, 'FusionCardTitle'))
    if subtitle:
        layout.addWidget(label(subtitle))
    return obj, layout


class _FocusFollower(QObject):
    """Scroll a newly focused descendant into view (V0 R-12).

    Applies to any focus change (keyboard, mouse click or programmatic): a
    partly hidden control that receives focus is revealed once with a 16 px
    margin; later manual scrolling is not fought. Parented to its scroll area,
    so Qt disconnects it when the area is destroyed. focusChanged can still
    fire DURING that teardown, so both objects are checked for validity first
    (Codex PEER-092)."""

    def __init__(self, scroll):
        super().__init__(scroll)
        self._scroll = scroll
        app = QApplication.instance()
        if app is not None:
            app.focusChanged.connect(self._follow)

    def _follow(self, _old, new):
        from shiboken6 import isValid
        scroll = self._scroll
        if new is None or not isValid(self) or not isValid(scroll) or not isValid(new):
            return
        inner = scroll.widget()
        if inner is not None and isValid(inner) and inner.isAncestorOf(new):
            scroll.ensureWidgetVisible(new, 16, 16)


def keep_focus_visible(scroll, accessible_name=None):
    """Name a page scroll area for assistive tech (R-11) and keep the focused
    control inside its visible area (R-12)."""
    if accessible_name:
        scroll.setAccessibleName(accessible_name)
    _FocusFollower(scroll)
    return scroll


def keyboard_table(table, accessible_name):
    """Tables: Tab leaves the table (R-10 keyboard trap); arrows move cells."""
    table.setTabKeyNavigation(False)
    table.setAccessibleName(accessible_name)
    return table


def page(title, subtitle, kicker=None):
    if kicker is None:
        kicker = ui_text('fusion.wam_fusion_regtest')
    scroll = QScrollArea()
    scroll.setObjectName('FusionScroll')
    keep_focus_visible(scroll, title)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setWidgetResizable(True)
    root = QWidget()
    root.setObjectName('FusionInner')
    scroll.setWidget(root)
    layout = QVBoxLayout(root)
    layout.setContentsMargins(SHELL['page_side'], SHELL['page_top'], SHELL['page_right'], SHELL['page_bottom'])
    layout.setSpacing(SHELL['page_gap'])
    layout.addWidget(label(kicker, 'FusionKicker'))
    layout.addWidget(label(title, 'PageTitle'))
    layout.addWidget(label(subtitle))
    return scroll, layout


def action(text, icon, primary=False):
    button = QPushButton(text)
    button.setProperty('fusion_icon', icon)
    button.setObjectName('FusionPrimary' if primary else 'FusionSecondary')
    button.setIconSize(QSize(18, 18))
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def quick_action(text, icon):
    button = QToolButton()
    button.setObjectName('FusionQuick')
    button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
    button.setProperty('fusion_icon', icon)
    button.setText(text)
    button.setIconSize(QSize(18, 18))
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    button.setMinimumHeight(48)
    return button


_NAMES = tuple(name for _, name in FUSION_NAV_PAGES)


def vector_icon(name, tone, dpr=2):
    """One original outline geometry family, rasterized at device resolution."""
    color = QColor(tone)
    if not color.isValid():
        raise ValueError('FUSION_ICON_COLOR_DENIED')
    pix = QPixmap(int(24 * dpr), int(24 * dpr))
    pix.setDevicePixelRatio(dpr)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(QPen(color, 1.65, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    p.setBrush(Qt.BrushStyle.NoBrush)

    def line(a, b, c, d):
        p.drawLine(QPointF(a, b), QPointF(c, d))

    if name in ('overview', 'home'):
        p.drawPolygon(QPolygonF([QPointF(12, 3), QPointF(21, 11), QPointF(21, 21), QPointF(3, 21), QPointF(3, 11)]))
        p.drawRect(QRectF(9, 14, 6, 7))
    elif name in ('receive', 'send'):
        if name == 'receive':
            line(12, 3, 12, 16); line(7, 11, 12, 16); line(17, 11, 12, 16); line(4, 20, 20, 20)
        else:
            p.drawPolygon(QPolygonF([QPointF(3, 10), QPointF(21, 3), QPointF(14, 21), QPointF(10, 14)]))
            line(10, 14, 21, 3)
    elif name == 'history':
        p.drawEllipse(QRectF(4, 4, 16, 16)); line(12, 7, 12, 12); line(12, 12, 16, 14)
    elif name in ('security', 'anchor'):
        p.drawPolygon(QPolygonF([QPointF(12, 3), QPointF(20, 7), QPointF(19, 16), QPointF(12, 21), QPointF(5, 16), QPointF(4, 7)]))
        line(8, 12, 11, 15); line(11, 15, 16, 9)
    elif name == 'settings':
        p.drawEllipse(QRectF(6, 6, 12, 12)); p.drawEllipse(QRectF(10, 10, 4, 4))
        for a, b, c, d in ((12, 2, 12, 5), (12, 19, 12, 22), (2, 12, 5, 12), (19, 12, 22, 12),
                           (4, 4, 6, 6), (18, 18, 20, 20), (4, 20, 6, 18), (18, 6, 20, 4)):
            line(a, b, c, d)
    elif name == 'network':
        p.drawEllipse(QRectF(9, 3, 6, 6)); p.drawEllipse(QRectF(3, 15, 6, 6)); p.drawEllipse(QRectF(15, 15, 6, 6))
        line(12, 9, 6, 15); line(12, 9, 18, 15)
    elif name == 'copy':
        p.drawRoundedRect(QRectF(8, 8, 12, 13), 2, 2); line(4, 16, 4, 3); line(4, 3, 16, 3)
    elif name in ('lock', 'unlock'):
        p.drawRoundedRect(QRectF(5, 10, 14, 11), 2, 2)
        p.drawArc(QRectF(8, 3, 8, 12), 0 if name == 'lock' else 20 * 16, 180 * 16)
        line(12, 14, 12, 17)
    elif name == 'backup':
        p.drawRoundedRect(QRectF(4, 4, 16, 17), 2, 2); line(8, 4, 8, 10); line(8, 10, 16, 10); line(16, 10, 16, 4); p.drawRect(QRectF(8, 15, 8, 6))
    elif name == 'sync':
        p.drawArc(QRectF(4, 4, 16, 16), 35 * 16, 260 * 16); line(19, 3, 20, 9); line(20, 9, 14, 8)
    elif name == 'core':
        p.drawRoundedRect(QRectF(6, 6, 12, 12), 2, 2); p.drawRect(QRectF(10, 10, 4, 4))
    elif name == 'wallet':
        p.drawRoundedRect(QRectF(3, 7, 18, 13), 2, 2); p.drawRoundedRect(QRectF(14, 11, 7, 5), 1.5, 1.5)
    elif name == 'chain':
        p.drawRoundedRect(QRectF(3, 8, 9, 6), 2, 2); p.drawRoundedRect(QRectF(12, 10, 9, 6), 2, 2)
    elif name == 'check':
        line(5, 12, 10, 17); line(10, 17, 20, 6)
    elif name == 'sun':
        p.drawEllipse(QRectF(9, 9, 6, 6))
        for a, b, c, d in ((12, 2, 12, 5), (12, 19, 12, 22), (2, 12, 5, 12), (19, 12, 22, 12),
                           (5, 5, 7, 7), (17, 17, 19, 19), (5, 19, 7, 17), (17, 7, 19, 5)):
            line(a, b, c, d)
    elif name == 'moon':
        crescent = QPainterPath()
        crescent.addEllipse(QRectF(5, 4, 14, 16))
        punch = QPainterPath()
        punch.addEllipse(QRectF(10, 5, 13, 14))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(color)
        p.drawPath(crescent.subtracted(punch))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(color, 1.65, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    elif name == 'auto':
        p.drawEllipse(QRectF(4, 4, 16, 16))
        p.setBrush(color)
        p.drawPie(QRectF(4, 4, 16, 16), 90 * 16, 180 * 16)
        p.setBrush(Qt.BrushStyle.NoBrush)
    else:
        p.drawEllipse(QRectF(5, 5, 14, 14)); line(12, 7, 12, 17); line(7, 12, 17, 12)
    p.end()
    return QIcon(pix)


def fusion_nav_icons(tone):
    return tuple(vector_icon(name, tone) for name in _NAMES)


def nav_icon_for(title, tone, dpr=2):
    lookup = dict(fusion_nav_pages())
    return vector_icon(lookup.get(title, 'overview'), tone, dpr)


def activity_by_block(snapshot):
    if snapshot is None:
        return ()
    if type(snapshot) is not WalletReadSnapshot or snapshot.synthetic_rpc or snapshot.chain != 'regtest' or snapshot.mainnet_allowed:
        raise ValueError('FUSION_HISTORY_UNVERIFIED_DENIED')
    blocks = {}
    for row in snapshot.history:
        if (type(row.block_height) is not int or not 1 <= row.block_height <= snapshot.height
                or type(row.confirmations) is not int or row.confirmations <= 0
                or type(row.credit_atoms) is not int or row.credit_atoms < 0
                or type(row.debit_atoms) is not int or row.debit_atoms < 0):
            raise ValueError('FUSION_HISTORY_UNVERIFIED_DENIED')
        agg = blocks.setdefault(row.block_height, [0, 0])
        agg[0] += row.credit_atoms
        agg[1] += row.debit_atoms
    return tuple((h, *blocks[h]) for h in sorted(blocks)[-14:])


def _deny_unverified_snapshot(snapshot):
    if snapshot is None:
        return None
    if (type(snapshot) is not WalletReadSnapshot or snapshot.synthetic_rpc
            or snapshot.chain != 'regtest' or snapshot.mainnet_allowed):
        raise ValueError('FUSION_HISTORY_UNVERIFIED_DENIED')
    if type(snapshot.confirmed_atoms) is not int or snapshot.confirmed_atoms < 0:
        raise ValueError('FUSION_HISTORY_UNVERIFIED_DENIED')
    if type(snapshot.height) is not int or snapshot.height < 0:
        raise ValueError('FUSION_HISTORY_UNVERIFIED_DENIED')
    for row in snapshot.history:
        if (type(row.block_height) is not int or not 1 <= row.block_height <= snapshot.height
                or type(row.confirmations) is not int or row.confirmations <= 0
                or type(row.credit_atoms) is not int or row.credit_atoms < 0
                or type(row.debit_atoms) is not int or row.debit_atoms < 0):
            raise ValueError('FUSION_HISTORY_UNVERIFIED_DENIED')
    return snapshot


def confirmed_balance_history(snapshot):
    """Oldest-to-newest (height, confirmed_atoms) from complete verified history.

    Empty when pagination, missing rows or inconsistent nets would require invention.
    """
    snapshot = _deny_unverified_snapshot(snapshot)
    if snapshot is None:
        return ()
    if snapshot.history_complete is not True or snapshot.history_offset != 0:
        return ()
    if not snapshot.history:
        return ((snapshot.height, 0),) if snapshot.confirmed_atoms == 0 else ()
    net = 0
    blocks = {}
    for row in snapshot.history:
        delta = row.credit_atoms - row.debit_atoms
        net += delta
        blocks[row.block_height] = blocks.get(row.block_height, 0) + delta
    if snapshot.confirmed_atoms - net != 0:
        return ()
    running = 0
    points = []
    first = min(blocks)
    if first > 1:
        points.append((first - 1, 0))
    for height in sorted(blocks):
        running += blocks[height]
        if running < 0:
            return ()
        points.append((height, running))
    if not points or points[-1][1] != snapshot.confirmed_atoms:
        return ()
    if points[-1][0] != snapshot.height:
        points.append((snapshot.height, snapshot.confirmed_atoms))
    return tuple(points)


class AdaptiveButtonRow(QWidget):
    """Buttons side by side when they fit, stacked when they do not.

    Unlike a plain QHBoxLayout, its minimum width is the widest button, not
    the sum, so long translations never force a page to scroll sideways."""

    def __init__(self, *buttons, spacing=12):
        super().__init__()
        self.setObjectName('FusionTransparent')
        self._buttons = buttons
        self._spacing = spacing
        self._box = QBoxLayout(QBoxLayout.Direction.LeftToRight, self)
        self._box.setContentsMargins(0, 0, 0, 0)
        self._box.setSpacing(spacing)
        self._box.setSizeConstraint(QBoxLayout.SizeConstraint.SetNoConstraint)
        for button in buttons:
            self._box.addWidget(button, 0, Qt.AlignmentFlag.AlignLeft)
        self._box.addStretch()

    def _side_by_side_width(self):
        return (sum(b.sizeHint().width() for b in self._buttons)
                + self._spacing * max(0, len(self._buttons) - 1))

    def minimumSizeHint(self):
        widest = max((b.minimumSizeHint().width() for b in self._buttons), default=0)
        return QSize(widest, self._box.minimumSize().height())

    def resizeEvent(self, event):
        direction = (QBoxLayout.Direction.LeftToRight
                     if self.width() >= self._side_by_side_width()
                     else QBoxLayout.Direction.TopToBottom)
        if self._box.direction() != direction:
            self._box.setDirection(direction)
            self.updateGeometry()
        super().resizeEvent(event)


class ResponsiveRow(QWidget):
    def __init__(self, *children, weights=None, breakpoint=760, min_side=0):
        super().__init__()
        self.setObjectName('FusionTransparent')
        self.setMinimumWidth(0)
        self._break = breakpoint
        self._min_side = min_side
        self._children = children
        self._weights = weights or [1] * len(children)
        self._vertical = None
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(18)

    def addWidget(self, widget, row=0, column=0):
        self._grid.addWidget(widget, row, column)
        return widget

    def resizeEvent(self, event):
        needed = self._break
        if self._min_side:
            needed = max(needed, self._min_side)
        vertical = self.width() < needed
        if vertical != self._vertical:
            self._vertical = vertical
            for i, child in enumerate(self._children):
                self._grid.addWidget(child, i if vertical else 0, 0 if vertical else i)
            for i, w in enumerate(self._weights):
                self._grid.setColumnStretch(i, 0 if vertical else w)
                self._grid.setRowStretch(i, w if vertical else 0)
        super().resizeEvent(event)


class FlowGrid(QWidget):
    """1/2/4 columns from actual width vs minimum readable card size."""

    def __init__(self, *children, min_item=220, max_columns=4):
        super().__init__()
        self.setObjectName('FusionTransparent')
        self.setMinimumWidth(0)
        self._children = children
        self._min_item = min_item
        self._max_columns = max_columns
        self._columns = None
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(12)
        for child in children:
            child.setMinimumWidth(0)
            child.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

    def resizeEvent(self, event):
        usable = max(1, self.width())
        raw = max(1, min(self._max_columns, usable // max(1, self._min_item)))
        columns = 4 if raw >= 4 else 2 if raw >= 2 else 1
        if columns != self._columns:
            self._columns = columns
            for i, child in enumerate(self._children):
                self._grid.addWidget(child, i // columns, i % columns)
            for column in range(self._max_columns):
                self._grid.setColumnStretch(column, 1 if column < columns else 0)
        super().resizeEvent(event)


class StatusCard(QFrame):
    def __init__(self, title, caption):
        super().__init__()
        self.setObjectName('FusionPanel')
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SHELL['card_x'], SHELL['card_y'], SHELL['card_x'], SHELL['card_y'])
        layout.setSpacing(SHELL['card_gap'])
        top = QHBoxLayout(); top.setSpacing(SHELL['card_row'])
        self.glyph = StatusGlyph()
        heading = label(title, 'FusionCardTitle')
        heading.setMinimumWidth(0)
        top.addWidget(self.glyph, 0, Qt.AlignmentFlag.AlignTop)
        top.addWidget(heading, 1)
        layout.addLayout(top)
        self.value = label(ui_text('fusion.not_verified'), 'FusionCardValue')
        self.detail = label(caption)
        self.detail.setWordWrap(True)
        self.detail.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        layout.addWidget(self.value)
        layout.addWidget(self.detail)

    def apply(self, state, title, detail, *, animate=True):
        self.glyph.set_state(state, animate=animate)
        self.value.setText(title)
        self.detail.setText(detail)
        self.setToolTip(detail)
        self.detail.setVisible(bool(detail))

    def set_theme(self, mode):
        self.glyph.set_theme(mode)


class Hero(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName('FusionHero')
        self.mode = 'dark'
        self.logo = QPixmap(str(brand_image()))
        self.setMinimumHeight(200)
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._stacked = None

    def resizeEvent(self, event):
        layout = self.layout()
        stacked = self.width() < 880
        self.setMinimumHeight(248 if stacked else 208)
        if layout is not None:
            layout.setContentsMargins(22, 18, 22, 18)
            if isinstance(layout, QGridLayout) and stacked != self._stacked:
                self._stacked = stacked
                copy = self.findChild(QWidget, 'FusionHeroCopy')
                chart = self.findChild(BalanceHistoryChart)
                if copy is not None and chart is not None:
                    chart.setVisible(True)
                    if stacked:
                        layout.addWidget(copy, 0, 0)
                        layout.addWidget(chart, 1, 0)
                        layout.setColumnStretch(0, 1)
                        layout.setColumnStretch(1, 0)
                        chart.setMinimumHeight(120)
                    else:
                        layout.addWidget(copy, 0, 0)
                        layout.addWidget(chart, 0, 1)
                        layout.setColumnStretch(0, 5)
                        layout.setColumnStretch(1, 4)
                        chart.setMinimumHeight(168)
        super().resizeEvent(event)

    def paintEvent(self, event):
        c = fusion_palette(self.mode)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        path = QPainterPath()
        path.addRoundedRect(rect, RADIUS['hero'], RADIUS['hero'])
        p.setClipPath(path)
        gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
        gradient.setColorAt(0, QColor(c['surface']))
        gradient.setColorAt(1, QColor(c['hero_bottom']))
        p.fillPath(path, gradient)
        glow = QRadialGradient(rect.left() + 120, rect.top() + 36, 160)
        gold = QColor(c['accent']); gold.setAlpha(28 if self.mode == 'dark' else 18)
        glow.setColorAt(0, gold); glow.setColorAt(1, QColor(0, 0, 0, 0))
        p.fillRect(rect, glow)
        p.setOpacity(0.95)
        p.setClipping(False)
        p.setPen(QPen(QColor(c['accent']), 1))
        p.drawRoundedRect(rect, RADIUS['hero'], RADIUS['hero'])
        p.end()


class ChainActivity(QWidget):
    """Gross confirmed credits/debits: discrete block columns, exact hover data."""
    def __init__(self):
        super().__init__()
        self._activity = ()
        self._mode = 'dark'
        self._hit = []
        self._hover = -1
        self.setMinimumHeight(196)
        self.setMouseTracking(True)
        self.setAccessibleName(ui_text('fusion.credit_debit_activity'))

    def render_snapshot(self, snapshot):
        self._activity = activity_by_block(snapshot)
        self._hover = -1
        self._hit = []
        QToolTip.hideText()
        self.update()

    def set_theme(self, mode):
        fusion_palette(mode)
        self._mode = mode
        self.update()

    def mouseMoveEvent(self, event):
        index = next((i for i, r in enumerate(self._hit) if r.contains(event.position())), -1)
        if index != self._hover:
            self._hover = index
            self.update()
        if index >= 0:
            h, credit, debit = self._activity[index]
            QToolTip.showText(event.globalPosition().toPoint(),
                              ui_text('fusion.block_credit_debit').format(height=h, credit=format_wam(credit), debit=format_wam(debit)), self)
        else:
            QToolTip.hideText()

    def leaveEvent(self, event):
        self._hover = -1
        QToolTip.hideText()
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = fusion_palette(self._mode)
        p.setFont(QFont(p.font().family(), 10))
        if not self._activity:
            p.setPen(QColor(c['chart_empty']))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                       ui_text('fusion.no_chart_activity'))
            p.end()
            return
        left, top, right, bottom = 66., 20., self.width() - 16., self.height() - 37.
        maximum = max(max(a, b) for _, a, b in self._activity)
        if maximum <= 0:
            p.end()
            return
        quantum = 10 ** max(0, len(str(maximum)) - 1)
        ceiling = ((maximum + quantum - 1) // quantum) * quantum
        for j in range(5):
            value = ceiling * j // 4
            y = bottom - (bottom - top) * j / 4
            p.setPen(QPen(QColor(c['grid']), 1, Qt.PenStyle.DotLine))
            p.drawLine(QPointF(left, y), QPointF(right, y))
            p.setPen(QColor(c['muted']))
            amount = format_wam(value).rstrip('0').rstrip('.')
            p.drawText(QRectF(0, y - 8, left - 12, 18), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, amount)
        count = len(self._activity)
        span = (right - left) / count
        width = min(22., span * .21)
        self._hit = []
        for i, (height, credit, debit) in enumerate(self._activity):
            center = left + span * (i + .5)
            hit = QRectF(left + i * span, top, span, bottom - top)
            self._hit.append(hit)
            if i == self._hover:
                p.fillRect(hit, QColor(c['panel']))
            for x, atoms, color in ((center - width * .62, credit, c['received']), (center + width * .62, debit, c['sent'])):
                if atoms <= 0:
                    continue
                bh = (bottom - top) * atoms / ceiling
                r = QRectF(x - width / 2, bottom - bh, width, bh)
                gradient = QLinearGradient(r.topLeft(), r.bottomLeft())
                gradient.setColorAt(0, QColor(color))
                faded = QColor(color); faded.setAlpha(75)
                gradient.setColorAt(1, faded)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(gradient)
                p.drawRoundedRect(r, 4, 4)
            p.setPen(QColor(c['muted']))
            if count < 9 or i % 2 == 0:
                p.drawText(QRectF(center - span / 2, bottom + 9, span, 20), Qt.AlignmentFlag.AlignHCenter, str(height))
        p.end()


class BalanceHistoryChart(QWidget):
    """Confirmed wallet balance over verified blocks. Never a price series."""

    def __init__(self):
        super().__init__()
        self._points = ()
        self._mode = 'dark'
        self._hover = -1
        self._hit = []
        self._reveal = 1.0
        self._reveal_anim = None
        self.setMinimumHeight(128)
        self.setMinimumWidth(132)
        self.setMouseTracking(True)
        self.setAccessibleName(ui_text('fusion.confirmed_wallet_balance_history'))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def get_reveal(self):
        return self._reveal

    def set_reveal(self, value):
        self._reveal = max(0.0, min(1.0, float(value)))
        self.update()

    reveal = Property(float, get_reveal, set_reveal)

    def render_points(self, points):
        previous = self._points
        self._points = tuple(points)
        self._hover = -1
        QToolTip.hideText()
        if self._reveal_anim is not None:
            self._reveal_anim.stop()
            self._reveal_anim = None
        if self._points and self._points != previous and not motion_reduced(self):
            self._reveal = 0.12
            animation = QPropertyAnimation(self, b'reveal', self)
            animation.setDuration(CHART_MS)
            animation.setStartValue(0.12)
            animation.setEndValue(1.0)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            self._reveal_anim = animation
            animation.start()
        else:
            self._reveal = 1.0
        self.update()

    def set_theme(self, mode):
        fusion_palette(mode)
        self._mode = mode
        self.update()

    def _mapped(self, width, height):
        if not self._points:
            return ()
        left, top, right, bottom = 8.0, 18.0, width - 10.0, height - 22.0
        xs = [h for h, _ in self._points]
        ys = [v for _, v in self._points]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        span_x = max(1, max_x - min_x)
        span_y = max(1, max_y - min_y)
        mapped = []
        for height_value, atoms in self._points:
            x = left + (right - left) * (height_value - min_x) / span_x
            y = bottom - (bottom - top) * (atoms - min_y) / span_y
            mapped.append((x, y, height_value, atoms))
        return mapped

    def _height_rect(self, x, height):
        width = min(float(self.width()), max(72.0,
                    float(self.fontMetrics().horizontalAdvance(str(height)) + 12)))
        left = min(max(0.0, x - width / 2), self.width() - width)
        return QRectF(left, self.height() - 20, width, 16)

    def mouseMoveEvent(self, event):
        mapped = self._mapped(self.width(), self.height())
        index = -1
        nearest = 1e9
        for i, (x, y, _h, _v) in enumerate(mapped):
            distance = abs(event.position().x() - x)
            if distance < nearest and distance < 28:
                nearest, index = distance, i
        if index != self._hover:
            self._hover = index
            self.update()
        if index >= 0:
            _x, _y, height, atoms = mapped[index]
            QToolTip.showText(event.globalPosition().toPoint(),
                              ui_text('fusion.verified_block_amount').format(height=height, amount=format_wam(atoms)), self)
        else:
            QToolTip.hideText()

    def leaveEvent(self, event):
        self._hover = -1
        QToolTip.hideText()
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = fusion_palette(self._mode)
        if not self._points:
            p.setPen(QColor(c['chart_empty']))
            p.drawText(self.rect().adjusted(10, 10, -10, -10),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter | Qt.TextFlag.TextWordWrap,
                       ui_text('fusion.balance_history_unavailable'))
            p.end()
            return
        mapped = self._mapped(self.width(), self.height())
        clip_right = self.width() * self._reveal
        p.setClipRect(QRectF(0, 0, clip_right, self.height()))
        if len(mapped) == 1:
            x, y, height, atoms = mapped[0]
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(c['accent']))
            p.drawEllipse(QPointF(x, y), 5.0, 5.0)
            p.setPen(QColor(c['muted']))
            p.drawText(self.rect().adjusted(8, 8, -8, -8),
                       Qt.AlignmentFlag.AlignCenter,
                       ui_text('fusion.amount_at_block').format(amount=format_wam(atoms), height=height))
            p.end()
            return
        path = QPainterPath()
        path.moveTo(mapped[0][0], mapped[0][1])
        for i in range(1, len(mapped)):
            x0, y0 = mapped[i - 1][0], mapped[i - 1][1]
            x1, y1 = mapped[i][0], mapped[i][1]
            dx = x1 - x0
            path.cubicTo(x0 + dx / 3.0, y0, x1 - dx / 3.0, y1, x1, y1)
        fill = QPainterPath(path)
        fill.lineTo(mapped[-1][0], self.height() - 22)
        fill.lineTo(mapped[0][0], self.height() - 22)
        fill.closeSubpath()
        gradient = QLinearGradient(QPointF(0, 16), QPointF(0, self.height() - 18))
        gold = QColor(c['accent']); gold.setAlpha(90 if self._mode == 'dark' else 70)
        fade = QColor(c['accent']); fade.setAlpha(0)
        gradient.setColorAt(0, gold)
        gradient.setColorAt(1, fade)
        p.fillPath(fill, gradient)
        pen = QPen(QColor(c['accent']), 2.2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(path)
        for i, (x, y, height, atoms) in enumerate(mapped):
            if i == self._hover or len(mapped) == 1:
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor(c['accent']))
                p.drawEllipse(QPointF(x, y), 4.2, 4.2)
                p.setPen(QColor(c['muted']))
                p.drawText(self._height_rect(x, height),
                           Qt.AlignmentFlag.AlignHCenter, str(height))
        p.end()


class FusionOverview(QScrollArea):
    transaction_selected = Signal(str)

    def __init__(self):
        super().__init__()
        self.setObjectName('FusionScroll')
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        root = QWidget(); root.setObjectName('FusionInner'); self.setWidget(root)
        keep_focus_visible(self, ui_text('fusion.overview'))
        root.setMinimumWidth(0)
        whole = QVBoxLayout(root)
        whole.setContentsMargins(4, 4, 8, 36)
        whole.setSpacing(14)
        head = QHBoxLayout()
        titles = QVBoxLayout(); titles.setSpacing(2)
        title_row = QHBoxLayout(); title_row.setSpacing(8)
        home = QLabel(); home.setProperty('fusion_icon_label', 'home'); home.setFixedSize(24, 24)
        title_row.addWidget(home); title_row.addWidget(label(ui_text('fusion.overview'), 'PageTitle')); title_row.addStretch()
        titles.addLayout(title_row)
        titles.addWidget(label(ui_text('fusion.glance')))
        head.addLayout(titles, 1)
        self.live_badge = label(ui_text('fusion.awaiting_verification'), 'FusionBadge')
        self.live_badge.hide()
        head.addWidget(self.live_badge, 0, Qt.AlignmentFlag.AlignTop)
        whole.addLayout(head)

        self.hero = Hero()
        hero_grid = QGridLayout(self.hero)
        hero_grid.setContentsMargins(22, 18, 22, 18)
        hero_grid.setHorizontalSpacing(16)
        hero_grid.setVerticalSpacing(12)
        copy = QWidget(); copy.setObjectName('FusionHeroCopy')
        copy.setMinimumWidth(0)
        hero = QVBoxLayout(copy)
        hero.setContentsMargins(0, 0, 0, 0)
        hero.setSpacing(8)
        kicker_row = QHBoxLayout(); kicker_row.setSpacing(10)
        coin = QLabel()
        coin.setFixedSize(44, 44)
        pixmap = self.hero.logo.scaled(44, 44, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        coin.setPixmap(pixmap)
        coin.setAccessibleName(ui_text('fusion.wam_coin'))
        kicker_row.addWidget(coin, 0, Qt.AlignmentFlag.AlignVCenter)
        kicker_row.addWidget(label(ui_text('fusion.confirmed_balance'), 'FusionKicker'))
        kicker_row.addStretch()
        hero.addLayout(kicker_row)
        self.balance_value = label('—', 'FusionBalance', True)
        self.balance_value.setMinimumWidth(0)
        self.balance_unit = label('WAM', 'FusionDenom')
        self.balance_unit.hide()
        hero.addWidget(self.balance_value)
        hero.addWidget(self.balance_unit)
        self.utxo_details = label(ui_text('fusion.awaiting_verified_core_wsp_state'))
        hero.addWidget(self.utxo_details)
        self.fund_details = label('')
        self.fund_details.hide()
        hero.addWidget(self.fund_details)
        row = QHBoxLayout(); row.setSpacing(10)
        self.go_send = action(ui_text('fusion.send'), 'send', True); self.go_send.setEnabled(False)
        self.go_send.setToolTip(ui_text('fusion.send_disabled'))
        self.go_receive = action(ui_text('fusion.receive'), 'receive')
        row.addWidget(self.go_send); row.addWidget(self.go_receive); row.addStretch()
        hero.addLayout(row)
        hero.addStretch()
        self.balance_chart = BalanceHistoryChart()
        hero_grid.addWidget(copy, 0, 0)
        hero_grid.addWidget(self.balance_chart, 0, 1)
        hero_grid.setColumnStretch(0, 5)
        hero_grid.setColumnStretch(1, 4)

        self.core_card = StatusCard(ui_text('fusion.wam_core'), ui_text('fusion.pinned_binary_identity'))
        self.chain_card = StatusCard(ui_text('fusion.chain'), ui_text('fusion.verified_tip_height'))
        self.security_card = StatusCard(ui_text('fusion.security'), ui_text('fusion.native_custody_state'))
        self.network_card = StatusCard(ui_text('fusion.network'), ui_text('fusion.regtest_connectivity'))
        self.core_status = self.core_card.value
        self.chain_status = self.chain_card.value
        self.vault_status = self.security_card.value
        self.network_status = self.network_card.value
        self.scanner_status = self.chain_status
        self.custody_caption = self.security_card.value
        self.lock_details = self.security_card.detail
        self.status_cards = [self.core_status, self.chain_status, self.vault_status, self.network_status]
        self.status_icons = [self.core_card.glyph, self.chain_card.glyph,
                             self.security_card.glyph, self.network_card.glyph]
        self.status_board = FlowGrid(
            self.core_card, self.chain_card, self.security_card, self.network_card,
            min_item=188, max_columns=4)

        activity, alayout = panel()
        self.activity_panel = activity
        top = QHBoxLayout()
        top.addWidget(label(ui_text('fusion.recent_transactions'), 'FusionCardTitle')); top.addStretch()
        self.open_history = action(ui_text('fusion.view_all'), 'history')
        top.addWidget(self.open_history); alayout.addLayout(top)
        self.activity_table = QTableWidget(0, 3)
        self.activity_table.setObjectName('FusionActivityTable')
        self.activity_table.setHorizontalHeaderLabels((ui_text('fusion.activity'), ui_text('fusion.amount'), ui_text('fusion.status')))
        self.activity_table.verticalHeader().hide()
        self.activity_table.setShowGrid(False)
        self.activity_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.activity_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.activity_table.horizontalHeader().setStretchLastSection(True)
        keyboard_table(self.activity_table, ui_text('fusion.recent_transactions'))
        self.activity_table.setMinimumHeight(168)
        self.activity_table.setMinimumWidth(0)
        self.activity_table.setColumnWidth(0, 200)
        self.activity_table.cellClicked.connect(self._select_tx)
        self._txids = []
        alayout.addWidget(self.activity_table)
        self.empty = label(ui_text('fusion.no_activity_yet'))
        alayout.addWidget(self.empty)

        whole.addWidget(self.hero)
        whole.addWidget(self.status_board)
        whole.addWidget(activity)

        self._compat = QWidget(); self._compat.hide()
        compat = QVBoxLayout(self._compat)
        self.network_summary = label(ui_text('fusion.after_snapshot'))
        self.health_value = label(ui_text('fusion.not_verified'), 'FusionCardValue')
        self.health_details = label(ui_text('fusion.verified_sources_only'))
        self.evidence_text = label(ui_text('fusion.no_verified_blockchain_snapshot'))
        self.manual_sync = action(ui_text('fusion.refresh'), 'sync')
        self.open_security = action(ui_text('fusion.security'), 'security')
        self.open_security.setEnabled(False)
        self.wallet_profile = label(ui_text('fusion.regtest_profile'))
        self.environment_core = label(ui_text('fusion.core_identity_pending'))
        self.environment_stack = label(ui_text('fusion.wsp_1_bip39_12_words'))
        self.custody_switch = StateSwitch(ui_text('fusion.locked'))
        self.custody_switch.setAccessibleName(ui_text('fusion.wallet_lock_unlock_switch'))
        self.custody_switch.setEnabled(False)
        for widget in (self.network_summary, self.health_value, self.health_details,
                       self.evidence_text, self.manual_sync, self.open_security,
                       self.wallet_profile, self.environment_core, self.environment_stack,
                       self.custody_switch):
            compat.addWidget(widget)
        whole.addWidget(self._compat)

        self._confirmed_atoms = None
        self.hero.installEventFilter(self)
        self.render_snapshot(None, locked=True)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._apply_balance_text()

    def eventFilter(self, watched, event):
        # QScrollArea lays out its child after the outer resizeEvent. Use
        # the actual hero resize so compact balance text follows final width.
        if watched is getattr(self, "hero", None) and event.type() == QEvent.Type.Resize:
            self._apply_balance_text()
        return super().eventFilter(watched, event)

    def _apply_balance_text(self):
        if self._confirmed_atoms is None:
            self.balance_value.setText('—')
            self.balance_unit.hide()
            return
        amount = format_wam(self._confirmed_atoms, grouped=True)
        compact = self.hero.width() > 0 and self.hero.width() < 640
        self.balance_unit.setVisible(compact)
        self.balance_value.setText(amount if compact else amount + ' WAM')
        size = TYPE['display_compact'] if compact else TYPE['display']
        self.balance_value.setStyleSheet(
            'font-size:%dpx;font-weight:%d;letter-spacing:%spx;'
            % (size, WEIGHT['bold'], TRACKING['balance']))

    def _select_tx(self, row, column):
        if 0 <= row < len(self._txids):
            self.transaction_selected.emit(self._txids[row])

    def set_theme(self, mode):
        self.hero.mode = mode
        self.hero.update()
        self.balance_chart.set_theme(mode)
        for card in (self.core_card, self.chain_card, self.security_card, self.network_card):
            card.set_theme(mode)
        self.custody_switch.setProperty('fusion_mode', mode)
        self.custody_switch.update()
        for row in range(self.activity_table.rowCount()):
            item = self.activity_table.item(row, 0)
            if item is not None:
                positive = item.data(Qt.ItemDataRole.UserRole) > 0
                item.setIcon(vector_icon('receive' if positive else 'send',
                                         direction_tone(fusion_palette(mode), item.data(Qt.ItemDataRole.UserRole))))

    def render_snapshot(self, snap, *, locked=False, operational=False, network=None,
                        faulted=False, available_atoms=None, reservation_count=None,
                        core_alive=None, busy=False):
        network = network or {}
        facts = dict(snap=None if (snap is None or locked) else snap, locked=locked,
                     operational=operational, faulted=faulted, core_alive=core_alive,
                     busy=busy, network=network)
        self.core_card.apply(*classify('core', **facts), animate=not locked)
        self.chain_card.apply(*classify('chain', **facts), animate=not locked)
        self.security_card.apply(*classify('security', **facts), animate=False)
        self.network_card.apply(*classify('network', **facts), animate=not locked)
        unlocked = not locked and operational and snap is not None
        self.custody_switch.blockSignals(True)
        self.custody_switch.setChecked(unlocked)
        self.custody_switch.setText(ui_text('fusion.unlocked') if unlocked else ui_text('fusion.locked'))
        self.custody_switch.blockSignals(False)
        if snap is None or locked:
            self._confirmed_atoms = None
            self._apply_balance_text()
            self.utxo_details.setText(ui_text('fusion.unlock_to_show_values'))
            self.fund_details.hide()
            self.balance_chart.render_points(())
            self.live_badge.setText(ui_text('fusion.locked') if locked else ui_text('fusion.not_verified'))
            self.evidence_text.setText(ui_text('fusion.no_verified_blockchain_snapshot'))
            self.evidence_text.setToolTip('')
            self.activity_table.setRowCount(0)
            self.activity_table.hide()
            self._txids = []
            self.empty.show()
            self.go_receive.setEnabled(False)
            self.health_value.setText(ui_text('fusion.faulted') if faulted else (ui_text('fusion.locked') if locked else ui_text('fusion.not_verified')))
            self.health_details.setText(ui_text('fusion.values_hidden'))
            self.network_summary.setText(network.get('summary', ui_text('fusion.network_after_snapshot')))
            self.wallet_profile.setText(ui_text('fusion.regtest_profile'))
            self.environment_core.setText(ui_text('fusion.core_identity_pending'))
            return
        activity_by_block(snap)
        self.balance_chart.render_points(confirmed_balance_history(snap))
        self._confirmed_atoms = snap.confirmed_atoms
        self._apply_balance_text()
        self.utxo_details.setText(
            ui_text('fusion.utxo_summary').format(count=snap.confirmed_utxos, height=snap.height)
            + (ui_text('fusion.regtest_shared') if network.get('shared') else ui_text('fusion.regtest_isolated')))
        funds = []
        if type(available_atoms) is int and available_atoms >= 0:
            if available_atoms != snap.confirmed_atoms:
                funds.append(ui_text('fusion.spendable') + format_wam(available_atoms, grouped=True) + ' WAM')
        if type(reservation_count) is int and reservation_count > 0:
            funds.append(str(reservation_count) + ui_text('fusion.reserved_input_s_stay_unavailable'))
        self.fund_details.setText('  ·  '.join(funds))
        self.fund_details.setVisible(bool(funds))
        self.live_badge.setText(ui_text('fusion.regtest_verified'))
        self.go_receive.setEnabled(True)
        self.evidence_text.setText(ui_text('fusion.verified_tip') + snap.tip[:14] + ui_text('fusion.no_real_funds'))
        self.evidence_text.setToolTip(ui_text('fusion.core_sha_256') + snap.core_sha256 + ui_text('fusion.verified_tip_2') + snap.tip)
        self.network_summary.setText(network.get('summary') or (
            ui_text('fusion.mode_height').format(mode=ui_text('fusion.shared_regtest') if network.get('shared') else ui_text('fusion.isolated_regtest'), height=snap.height)))
        self.health_value.setText(ui_text('fusion.operating_normally') if not faulted else ui_text('fusion.faulted'))
        self.health_details.setText(
            ui_text('fusion.snapshot_sources')
            if not faulted else ui_text('fusion.keep_reservations'))
        self.wallet_profile.setText(ui_text('fusion.operational_regtest_wallet') if operational else ui_text('fusion.read_only_regtest_wallet'))
        self.environment_core.setText(core_compat.DISPLAY_NAME + ui_text('fusion.sha_256') + snap.core_sha256[:12] + '…')
        self.environment_core.setToolTip(ui_text('fusion.core_sha_256') + snap.core_sha256)
        rows = snap.history[:4]
        self._txids = [r.txid for r in rows]
        self.activity_table.setRowCount(len(rows))
        self.activity_table.setVisible(bool(rows))
        self.empty.setVisible(not rows)
        if rows:
            self.activity_table.setMinimumHeight(min(220, 48 + 58 * len(rows)))
        mode = self.hero.mode
        for i, tx in enumerate(rows):
            value = tx.credit_atoms - tx.debit_atoms
            direction = ui_text('fusion.received') if value > 0 else ui_text('fusion.sent') if value < 0 else ui_text('fusion.activity_2')
            amount = ('+' if value > 0 else '-' if value < 0 else '') + format_wam(abs(value)) + ' WAM'
            status = ui_text('fusion.confirmed_count_block').format(confirmations=tx.confirmations, height=tx.block_height)
            activity_text = direction + '\n' + tx.txid[:12] + '…'
            for j, text in enumerate((activity_text, amount, status)):
                item = QTableWidgetItem(text)
                item.setForeground(QColor(fusion_palette(mode)['text']))
                item.setToolTip(tx.txid + ui_text('fusion.view_transaction'))
                if j == 0:
                    item.setData(Qt.ItemDataRole.UserRole, value)
                    item.setIcon(vector_icon('receive' if value > 0 else 'send',
                                             direction_tone(fusion_palette(mode), value)))
                if j == 1:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.activity_table.setItem(i, j, item)
            self.activity_table.setRowHeight(i, 58)
