"""Remember catalog keys on widgets and apply them again after a language change.

``t()`` returns a ``Phrase`` so constructors can keep the key. Applying a
language uses the plain catalog string and does not clear the remembered key.
"""
from PySide6.QtWidgets import (
    QAbstractButton, QCheckBox, QLabel, QLineEdit, QPushButton, QTextEdit, QToolButton,
)

_SETTERS = {
    'text': 'setText',
    'tooltip': 'setToolTip',
    'accessible_name': 'setAccessibleName',
    'accessible_description': 'setAccessibleDescription',
    'placeholder': 'setPlaceholderText',
    'window_title': 'setWindowTitle',
}


def phrase_key(value):
    key = getattr(value, 'key', None)
    return key if type(key) is str else None


def _spec(widget):
    spec = getattr(widget, '_fusion_i18n', None)
    if not isinstance(spec, dict):
        spec = {}
        widget._fusion_i18n = spec
    return spec


def capture(widget, slot, value):
    """Remember a catalog key or composed Phrase. Plain strings clear it."""
    from .bip39_locale import Phrase
    if getattr(widget, '_i18n_applying', False):
        return
    spec = _spec(widget)
    key = phrase_key(value)
    if key:
        spec[slot] = key
    elif isinstance(value, Phrase):
        spec[slot] = value
    else:
        spec.pop(slot, None)


def bind(widget, **slots):
    """Remember catalog keys and show the current language."""
    spec = _spec(widget)
    for slot, value in slots.items():
        if slot not in _SETTERS:
            raise ValueError('FUSION_I18N_SLOT_DENIED')
        key = phrase_key(value) or value
        if type(key) is not str:
            raise ValueError('FUSION_I18N_KEY_DENIED')
        spec[slot] = key
    apply_widget(widget)
    return widget


def bind_headers(table, keys):
    table._fusion_i18n_headers = tuple(keys)
    apply_widget(table)
    return table


def bind_items(combo, keys):
    combo._fusion_i18n_items = tuple(keys)
    apply_widget(combo)
    return combo


def apply_widget(widget):
    from .bip39_locale import Phrase, t
    spec = getattr(widget, '_fusion_i18n', None)
    headers = getattr(widget, '_fusion_i18n_headers', None)
    items = getattr(widget, '_fusion_i18n_items', None)
    if not spec and not headers and not items:
        return
    widget._i18n_applying = True
    try:
        if isinstance(spec, dict):
            for slot, key in list(spec.items()):
                setter = getattr(widget, _SETTERS.get(slot, ''), None)
                if setter is not None:
                    if isinstance(key, Phrase):
                        setter(key.translated())
                    elif type(key) is str:
                        setter(str(t(key)))
        if headers:
            widget.setHorizontalHeaderLabels([str(t(key)) for key in headers])
        if items is not None and hasattr(widget, 'setItemText'):
            for index, key in enumerate(items):
                widget.setItemText(index, str(t(key)))
        if isinstance(spec, dict) and 'accessible_name' in spec:
            corner = widget.findChild(QAbstractButton, 'qt_tableview_cornerbutton')
            if corner is not None:
                corner.setAccessibleName(widget.accessibleName())
    finally:
        widget._i18n_applying = False


def retranslate_tree(root):
    from PySide6.QtWidgets import QWidget
    widgets = [root]
    if isinstance(root, QWidget):
        widgets.extend(root.findChildren(QWidget))
    for widget in widgets:
        apply_widget(widget)


class I18nLabel(QLabel):
    def __init__(self, text=''):
        super().__init__()
        if text:
            self.setText(text)

    def setText(self, text):
        capture(self, 'text', text)
        super().setText(text if isinstance(text, str) else '')

    def setToolTip(self, text):
        capture(self, 'tooltip', text)
        super().setToolTip(text if isinstance(text, str) else '')

    def setAccessibleName(self, text):
        capture(self, 'accessible_name', text)
        super().setAccessibleName(text if isinstance(text, str) else '')

    def setAccessibleDescription(self, text):
        capture(self, 'accessible_description', text)
        super().setAccessibleDescription(text if isinstance(text, str) else '')


class I18nButton(QPushButton):
    def __init__(self, text=''):
        super().__init__()
        if text:
            self.setText(text)

    def setText(self, text):
        capture(self, 'text', text)
        super().setText(text if isinstance(text, str) else '')

    def setToolTip(self, text):
        capture(self, 'tooltip', text)
        super().setToolTip(text if isinstance(text, str) else '')

    def setAccessibleName(self, text):
        capture(self, 'accessible_name', text)
        super().setAccessibleName(text if isinstance(text, str) else '')

    def setAccessibleDescription(self, text):
        capture(self, 'accessible_description', text)
        super().setAccessibleDescription(text if isinstance(text, str) else '')


class I18nToolButton(QToolButton):
    def setText(self, text):
        capture(self, 'text', text)
        super().setText(text if isinstance(text, str) else '')

    def setToolTip(self, text):
        capture(self, 'tooltip', text)
        super().setToolTip(text if isinstance(text, str) else '')

    def setAccessibleName(self, text):
        capture(self, 'accessible_name', text)
        super().setAccessibleName(text if isinstance(text, str) else '')


class I18nCheckBox(QCheckBox):
    def __init__(self, text=''):
        super().__init__()
        if text:
            self.setText(text)

    def setText(self, text):
        capture(self, 'text', text)
        super().setText(text if isinstance(text, str) else '')

    def setToolTip(self, text):
        capture(self, 'tooltip', text)
        super().setToolTip(text if isinstance(text, str) else '')

    def setAccessibleName(self, text):
        capture(self, 'accessible_name', text)
        super().setAccessibleName(text if isinstance(text, str) else '')

    def setAccessibleDescription(self, text):
        capture(self, 'accessible_description', text)
        super().setAccessibleDescription(text if isinstance(text, str) else '')


class I18nLineEdit(QLineEdit):
    def setPlaceholderText(self, text):
        capture(self, 'placeholder', text)
        super().setPlaceholderText(text if isinstance(text, str) else '')

    def setToolTip(self, text):
        capture(self, 'tooltip', text)
        super().setToolTip(text if isinstance(text, str) else '')

    def setAccessibleName(self, text):
        capture(self, 'accessible_name', text)
        super().setAccessibleName(text if isinstance(text, str) else '')

    def setAccessibleDescription(self, text):
        capture(self, 'accessible_description', text)
        super().setAccessibleDescription(text if isinstance(text, str) else '')


class I18nTextEdit(QTextEdit):
    def setPlaceholderText(self, text):
        capture(self, 'placeholder', text)
        super().setPlaceholderText(text if isinstance(text, str) else '')

    def setAccessibleName(self, text):
        capture(self, 'accessible_name', text)
        super().setAccessibleName(text if isinstance(text, str) else '')
