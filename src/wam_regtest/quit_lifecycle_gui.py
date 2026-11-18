"""Non-blocking Qt presentation for quit notices, preserved runtime and dead-owner recovery."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

from .bip39_locale import t


def format_unresolved_notice(item):
    """Format one unacknowledged notice record using allowlisted metadata only."""
    kind = item.get('kind') if isinstance(item, dict) else None
    if kind == 'notice':
        notice = item.get('notice') or {}
        codes = ', '.join(notice.get('codes') or ()) or '-'
        return t('quit_lifecycle.item_notice').format(
            seq=notice.get('seq', 0),
            session_kind=notice.get('session_kind', '-'),
            wallet_outcome=notice.get('wallet_outcome', '-'),
            core_stop=notice.get('core_stop', '-'),
            codes=codes,
        )
    if kind == 'failure':
        return t('quit_lifecycle.item_failure').format(
            stage=item.get('stage') or '-',
            code=item.get('code') or '-',
        )
    name = item.get('name') if isinstance(item, dict) else '-'
    size = item.get('size', 0) if isinstance(item, dict) else 0
    return t('quit_lifecycle.item_unreadable').format(name=name or '-', size=size)


def _new_modal(parent, title, body):
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setWindowModality(Qt.WindowModality.WindowModal)
    dialog.setMinimumWidth(460)
    layout = QVBoxLayout(dialog)
    message = QLabel(body)
    message.setWordWrap(True)
    message.setTextFormat(Qt.TextFormat.PlainText)
    layout.addWidget(message)
    return dialog, layout, message


class _MandatoryAckDialog(QDialog):
    """Non-blocking dialog that stays open until its explicit acknowledge button is clicked."""

    def __init__(self, parent, title, body):
        super().__init__(parent)
        self._acknowledged = False
        self.setWindowTitle(title)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        self.message = QLabel(body)
        self.message.setWordWrap(True)
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.message)
        buttons = QHBoxLayout()
        buttons.addStretch()
        self.ack_button = QPushButton(t('quit_lifecycle.runtime_preserved_ack_button'))
        buttons.addWidget(self.ack_button)
        layout.addLayout(buttons)

    def reject(self):
        if self._acknowledged:
            super().reject()

    def closeEvent(self, event):
        if self._acknowledged:
            super().closeEvent(event)
        else:
            event.ignore()


def open_runtime_preserved_dialog(parent, on_ack):
    """Present the non-blocking preserved-runtime acknowledgement after Core stopped."""
    dialog = _MandatoryAckDialog(
        parent,
        t('quit_lifecycle.runtime_preserved_title'),
        t('quit_lifecycle.runtime_preserved_body'),
    )

    def acknowledged():
        dialog._acknowledged = True
        dialog.accept()
        on_ack()

    dialog.ack_button.clicked.connect(acknowledged)
    dialog.open()
    return dialog


def open_unresolved_notices_dialog(parent, notices, on_ack, on_dismiss=None):
    """Present unresolved shutdown/fault notices non-blockingly with explicit acknowledgement."""
    dialog, layout, _ = _new_modal(
        parent,
        t('quit_lifecycle.unresolved_title'),
        t('quit_lifecycle.unresolved_body'),
    )
    summary = QTextEdit()
    summary.setReadOnly(True)
    summary.setPlainText('\n'.join(format_unresolved_notice(item) for item in notices))
    summary.setMinimumHeight(110)
    dialog.summary = summary
    layout.addWidget(summary)
    buttons = QHBoxLayout()
    buttons.addStretch()
    dialog.dismiss_button = QPushButton(t('quit_lifecycle.dismiss_button'))
    dialog.ack_button = QPushButton(t('quit_lifecycle.unresolved_ack_button'))
    buttons.addWidget(dialog.dismiss_button)
    buttons.addWidget(dialog.ack_button)
    layout.addLayout(buttons)

    def accept_ack():
        dialog.accept()
        on_ack()

    def dismiss():
        dialog.reject()
        if on_dismiss is not None:
            on_dismiss()

    dialog.ack_button.clicked.connect(accept_ack)
    dialog.dismiss_button.clicked.connect(dismiss)
    dialog.open()
    return dialog


def open_unrecorded_exit_confirm_dialog(parent, on_confirm):
    """Second explicit non-blocking acknowledgement before `quit_ack_unrecorded`."""
    dialog, layout, _ = _new_modal(
        parent,
        t('quit_lifecycle.exit_unrecorded_confirm_title'),
        t('quit_lifecycle.exit_unrecorded_confirm_body'),
    )
    buttons = QHBoxLayout()
    buttons.addStretch()
    dialog.cancel_button = QPushButton(t('cancel'))
    dialog.confirm_button = QPushButton(t('quit_lifecycle.exit_unrecorded_confirm_button'))
    buttons.addWidget(dialog.cancel_button)
    buttons.addWidget(dialog.confirm_button)
    layout.addLayout(buttons)

    def confirmed():
        dialog.accept()
        on_confirm()

    dialog.cancel_button.clicked.connect(dialog.reject)
    dialog.confirm_button.clicked.connect(confirmed)
    dialog.open()
    return dialog


def open_notice_persist_failed_dialog(parent, *, core_alive, on_retry, on_exit_unrecorded):
    """Non-blocking recovery dialog when Quit failed to persist its notice."""
    body = (
        t('quit_lifecycle.persist_failed_body_live')
        if core_alive
        else t('quit_lifecycle.persist_failed_body_stopped')
    )
    dialog, layout, _ = _new_modal(
        parent,
        t('quit_lifecycle.persist_failed_title'),
        body,
    )
    buttons = QHBoxLayout()
    buttons.addStretch()
    dialog.dismiss_button = QPushButton(t('quit_lifecycle.dismiss_button'))
    dialog.unrecorded_button = QPushButton(t('quit_lifecycle.exit_unrecorded_button'))
    dialog.unrecorded_button.setEnabled(core_alive is False)
    dialog.retry_button = QPushButton(t('quit_lifecycle.retry_record_button'))
    buttons.addWidget(dialog.dismiss_button)
    buttons.addWidget(dialog.unrecorded_button)
    buttons.addWidget(dialog.retry_button)
    layout.addLayout(buttons)

    def retry():
        dialog.accept()
        on_retry()

    def request_unrecorded():
        if core_alive is not False:
            return
        dialog.accept()
        on_exit_unrecorded()

    dialog.dismiss_button.clicked.connect(dialog.reject)
    dialog.retry_button.clicked.connect(retry)
    dialog.unrecorded_button.clicked.connect(request_unrecorded)
    dialog.open()
    return dialog


def open_dead_owner_recovery_dialog(parent, on_recover_restart):
    """Non-blocking explicit original-owner dead-Core recovery prompt (decision l)."""
    dialog, layout, _ = _new_modal(
        parent,
        t('quit_lifecycle.dead_owner_title'),
        t('quit_lifecycle.dead_owner_body'),
    )
    buttons = QHBoxLayout()
    buttons.addStretch()
    dialog.dismiss_button = QPushButton(t('quit_lifecycle.dismiss_button'))
    dialog.recover_button = QPushButton(t('quit_lifecycle.recover_restart_button'))
    buttons.addWidget(dialog.dismiss_button)
    buttons.addWidget(dialog.recover_button)
    layout.addLayout(buttons)

    def recover():
        dialog.accept()
        on_recover_restart()

    dialog.dismiss_button.clicked.connect(dialog.reject)
    dialog.recover_button.clicked.connect(recover)
    dialog.open()
    return dialog


class QuitLifecycleMixin:
    """Shared non-blocking quit-notice, preserved-runtime and dead-owner UI wiring."""

    def _init_quit_lifecycle(self):
        self._runtime_preserved_acknowledged = False
        self._runtime_preserved_dialog = None
        self._quit_notice_dialog = None
        self._notice_persist_dialog = None
        self._unrecorded_confirm_dialog = None
        self._dead_owner_dialog = None
        self._unresolved_quit_notices = ()
        self._notice_persist_failed = False

    def _quit_executor(self):
        return self.executor

    def _submit_quit_action(self, action, *args):
        return self._command(action, *args)

    def _on_runtime_preserved_ack(self):
        self._check_quit()

    def _present_runtime_preserved_ack(self):
        if self._runtime_preserved_acknowledged:
            return
        if hasattr(self, '_invalidate_payment_decision'):
            self._invalidate_payment_decision()
        if self._runtime_preserved_dialog is not None and self._runtime_preserved_dialog.isVisible():
            self._runtime_preserved_dialog.raise_()
            return
        self.status.setText(t('quit_lifecycle.runtime_preserved_title'))

        def on_ack():
            self._runtime_preserved_acknowledged = True
            self._runtime_preserved_dialog = None
            self._on_runtime_preserved_ack()

        self._runtime_preserved_dialog = open_runtime_preserved_dialog(self, on_ack)

    def _present_unresolved_quit_notices(self):
        if not self._unresolved_quit_notices:
            return
        if self._quit_notice_dialog is not None and self._quit_notice_dialog.isVisible():
            self._quit_notice_dialog.raise_()
            return

        def on_ack():
            self._quit_notice_dialog = None
            self._submit_quit_action('acknowledge_quit_notices')

        def on_dismiss():
            self._quit_notice_dialog = None

        self._quit_notice_dialog = open_unresolved_notices_dialog(
            self, self._unresolved_quit_notices, on_ack, on_dismiss=on_dismiss
        )

    def _present_notice_persist_failed(self):
        if self._notice_persist_dialog is not None and self._notice_persist_dialog.isVisible():
            self._notice_persist_dialog.raise_()
            return
        core_alive = self._quit_executor().state.core_alive is not False

        def on_retry():
            self._notice_persist_dialog = None
            self._submit_quit_action('retry_quit_notice')

        def on_exit_unrecorded():
            self._notice_persist_dialog = None

            def on_confirm():
                self._unrecorded_confirm_dialog = None
                self._submit_quit_action('quit_ack_unrecorded')

            self._unrecorded_confirm_dialog = open_unrecorded_exit_confirm_dialog(
                self, on_confirm
            )

        self._notice_persist_dialog = open_notice_persist_failed_dialog(
            self,
            core_alive=core_alive,
            on_retry=on_retry,
            on_exit_unrecorded=on_exit_unrecorded,
        )

    def _present_dead_owner_recovery(self):
        if self._dead_owner_dialog is not None and self._dead_owner_dialog.isVisible():
            self._dead_owner_dialog.raise_()
            return

        def on_recover():
            self._dead_owner_dialog = None
            self._submit_quit_action('core_restart')

        self._dead_owner_dialog = open_dead_owner_recovery_dialog(self, on_recover)

