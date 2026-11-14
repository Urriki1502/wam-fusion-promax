"""Native Qt Q06 12-word REGTEST owner trial, separate from Q05 GUI.

Full REGTEST Send remains disabled until owned-Core/native-checkpoint activation.
No keys leave this local GUI or enter native CI artifacts.
"""
from pathlib import Path

from PySide6.QtCore import Qt,QTimer,QEvent,Signal
from PySide6.QtWidgets import (
    QCheckBox,QDialog,QDialogButtonBox,QHBoxLayout,QGridLayout,QInputDialog,QLabel,
    QLineEdit,QMessageBox,QPushButton,QTextEdit,QVBoxLayout,QWidget,QApplication,
)

from .desktop import qt_application
from .gui_errors import operation_error, public_code, error_text
from .managed_gui import ControlWorker
from .wallet_executor import WalletExecutor
from .bip39_owner_backend import Bip39ReadOnlyBackend
from .bip39_12 import normalize_phrase
from .bip39_locale import t
from .presentation.action_state import ActionInputs, BASE_CONTROLS, available_actions
from .bip39_backup_page import (
    SecretLineEdit, get_secret_multiline_text, get_secret_text,
)
from .domain.payment_state import reservations_need_attention

from .fusion_ui import label, action
from .fusion_pages import owner_approval_text


def reservation_warning(result):
    """Warn about reservations only when one still needs the owner's attention.

    With the verified state set (W-TX-03) a confirmed payment's leftover
    'broadcast' rows no longer warn. Without it (older result shapes) the
    previous count-based rule applies unchanged.
    """
    states = result.get("reservation_states")
    if states is None:
        return result.get("reservation_count", 0) > 0
    return result.get("reservation_count", 0) > 0 and reservations_need_attention(states)


class Bip39RecoveryVerifyDialog(QDialog):
    """Owner-approved Q06 independent 12-word recovery verification modal.

    Scope A of the owner-approved Recovery & Backup Verification UX. Real Qt
    inputs only: sequential focus navigation, user-initiated paste, explicit
    clear, clean inline validation errors and a backend-authority BIP39
    checksum gate. No generic Qt message boxes for ordinary validation
    failures, no automatic clipboard reads/writes and no seed echo.
    """

    WORD_COUNT = 12

    verify_requested = Signal(str)
    cancelled = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("FusionPanel")
        self.setWindowTitle(t("recovery_verify_title"))
        self._fields = []
        self._count_label = None
        self._verify_button = None
        self._verify_error = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)
        layout.addWidget(label(t("recovery_verify_kicker"), "FusionKicker"))
        layout.addWidget(label(t("recovery_verify_title"), "PageTitle"))
        layout.addWidget(label(t("recovery_verify_subtitle")))
        layout.addWidget(label(t("recovery_readonly_notice"), "FusionMuted"))
        grid = QGridLayout()
        grid.setSpacing(12)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)
        self._grid = grid
        for index in range(self.WORD_COUNT):
            field_box = QWidget()
            field_box.setObjectName("FusionInset")
            field_layout = QVBoxLayout(field_box)
            field_layout.setContentsMargins(12, 10, 12, 10)
            field_layout.setSpacing(6)
            position_label = QLabel(t('owner.word_position').format(position=index + 1))
            position_label.setObjectName("FusionMuted")
            position_label.setStyleSheet("font-size:11px;font-weight:600;letter-spacing:0.4px;")
            field = SecretLineEdit()
            field.setObjectName("RecoveryWordField")
            field.setMaxLength(16)
            field.setPlaceholderText(t("word_label"))
            field.setEchoMode(QLineEdit.EchoMode.Password)
            field.setAccessibleName(t('owner.recovery_word').format(position=index + 1))
            field.textChanged.connect(self._refresh_state)
            field.returnPressed.connect(lambda i=index: self._on_field_returned(i))
            field_layout.addWidget(position_label)
            field_layout.addWidget(field)
            grid.addWidget(field_box, index // 3, index % 3)
            self._fields.append(field)
            field.installEventFilter(self)
        layout.addLayout(grid)
        self._verify_error = label("", "FusionGold")
        self._verify_error.hide()
        layout.addWidget(self._verify_error)
        self._count_label = label(t("recovery_word_count").format(entered=0), "FusionMuted")
        self._paste_button = QPushButton(t("recovery_paste_words"))
        self._paste_button.setObjectName("FusionSecondary")
        self._paste_button.clicked.connect(self._on_paste)
        self._clear_button = QPushButton(t("recovery_clear_words"))
        self._clear_button.setObjectName("FusionDestructive")
        self._clear_button.clicked.connect(self._on_clear)
        self._cancel_button = action(t("recovery_cancel"), "backup")
        self._cancel_button.setObjectName("FusionSecondary")
        self._cancel_button.clicked.connect(self._on_cancel)
        self._verify_button = action(t("recovery_verify_phrase"), "check", primary=True)
        self._verify_button.setObjectName("FusionPrimary")
        self._verify_button.setEnabled(False)
        self._verify_button.clicked.connect(self._on_verify_phrase)
        footer = QHBoxLayout()
        footer.addWidget(self._paste_button)
        footer.addWidget(self._clear_button)
        footer.addStretch()
        footer.addWidget(self._count_label)
        footer.addStretch()
        footer.addWidget(self._cancel_button)
        footer.addWidget(self._verify_button)
        layout.addLayout(footer)
        layout.addStretch()

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.KeyPress:
            key = event.key()
            index = -1
            for i, field in enumerate(self._fields):
                if field is obj:
                    index = i
                    break
            if index >= 0:
                handled = False
                if key == Qt.Key_Backspace and not obj.text():
                    if index > 0:
                        self._fields[index - 1].setFocus()
                        handled = True
                elif key in (Qt.Key_Tab, Qt.Key_Backtab):
                    next_index = index + 1 if key == Qt.Key_Tab else index - 1
                    if 0 <= next_index < len(self._fields):
                        self._fields[next_index].setFocus()
                        handled = True
                if handled:
                    event.accept()
                    return True
        return super().eventFilter(obj, event)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self._on_cancel()
            return
        super().keyPressEvent(event)

    def _on_field_returned(self, index):
        if index < len(self._fields) - 1:
            self._fields[index + 1].setFocus()
        else:
            self._on_verify_phrase()

    def _current_phrase(self):
        return " ".join(
            field.text().strip().lower()
            for field in self._fields if field.text().strip())

    def _refresh_state(self):
        words = [field.text().strip().lower() for field in self._fields]
        valid = False
        if len(words) == self.WORD_COUNT and all(words):
            try:
                normalize_phrase(" ".join(words))
                valid = True
            except Exception:
                valid = False
        self._verify_button.setEnabled(valid)
        self._count_label.setText(t("recovery_word_count").format(
            entered=sum(1 for field in self._fields if field.text().strip())))

    def _clear_fields(self):
        for field in self._fields:
            field.clear()
        self._refresh_state()

    def _on_verify_phrase(self):
        phrase = self._current_phrase()
        words = phrase.split()
        valid = False
        if len(words) == self.WORD_COUNT and all(words):
            try:
                normalize_phrase(phrase)
                valid = True
            except Exception:
                valid = False
        if not valid:
            self._verify_error.setText(t("recovery_invalid"))
            self._verify_error.show()
            return
        self.verify_requested.emit(phrase)
        self._clear_fields()
        self.accept()

    def _on_paste(self):
        clipboard = QApplication.clipboard()
        changed = False
        def ownership_changed():
            nonlocal changed
            changed = True
        clipboard.dataChanged.connect(ownership_changed)
        def deny_paste():
            try:
                self._clear_fields()
                self._verify_error.setText(t("recovery_invalid"))
                self._verify_error.show()
            except RuntimeError:
                # A destroyed Qt widget cannot retain visible input. Never
                # forward cleanup exception text through the event loop.
                pass
        text = ""
        try:
            text = clipboard.text()
            self._apply_paste(text)
        except Exception:
            deny_paste()
        finally:
            try:
                # A nested signal may publish newer clipboard content, even
                # the same text. Only clear our unchanged consumed snapshot.
                if text and clipboard.text() == text and not changed:
                    clipboard.clear()
            except Exception:
                # Clipboard access/clear may fail. Do not retry or blindly
                # clear uncertain/newer content; report only a fixed error.
                deny_paste()
            finally:
                try:
                    clipboard.dataChanged.disconnect(ownership_changed)
                except Exception:
                    deny_paste()

    def _apply_paste(self, text):
        tokens = str(text or "").strip().lower().split()
        targets = [field for field in self._fields if not field.text().strip()]
        for token, field in zip(tokens, targets):
            field.setText(token)
        self._refresh_state()

    def _on_clear(self):
        for field in self._fields:
            field.clear()
        self._refresh_state()

    def _on_cancel(self):
        self._clear_fields()
        self.cancelled.emit()
        self.accept()

    def reject(self):
        self._clear_fields()
        self.cancelled.emit()
        super().reject()

    def closeEvent(self, event):
        self._clear_fields()
        super().closeEvent(event)


class Bip39TrialWindow(QWidget):
    def __init__(self, executor):
        super().__init__()
        self.executor = executor
        self._worker = None
        self._worker_action = None
        self._quit_requested = False
        self._closed = False
        self._backup_unacked = False
        self._backup_flow_active = False
        self._backup_verified = False
        self._backup_result = None
        self.setWindowTitle(t('owner.trial_title'))
        self.resize(750, 475)
        box = QVBoxLayout(self)
        title = QLabel(t('owner.trial_heading'))
        title.setStyleSheet("font-size: 19px; font-weight: bold;")
        box.addWidget(title)
        box.addWidget(QLabel(t('owner.trial_notice')))
        self.status = QLabel(t('owner.core_not_opened'))
        box.addWidget(self.status)
        box.addWidget(QLabel(t('owner.receive_caption')))
        self.receive = QLineEdit()
        self.receive.setReadOnly(True)
        self.receive.setPlaceholderText(t('owner.receive_locked'))
        box.addWidget(self.receive)
        box.addWidget(QLabel(t('owner.last_txid')))
        self.last_txid=QLineEdit()
        self.last_txid.setReadOnly(True)
        self.last_txid.setPlaceholderText(
            t('owner.no_session_broadcast'))
        box.addWidget(self.last_txid)
        self.account = QLabel(t('owner.account_locked'))
        self.balance = QLabel(t('owner.balance_unverified'))
        self.tip = QLabel(t('owner.chain_unverified'))
        for item in (self.account,self.balance,self.tip):box.addWidget(item)
        box.addWidget(QLabel(t('owner.history_caption')))
        self.history = QTextEdit()
        self.history.setReadOnly(True)
        self.history.setPlaceholderText(t('owner.history_hint'))
        box.addWidget(self.history)
        bar=QHBoxLayout()
        self.sync=QPushButton(t('owner.sync_core'))
        self.fund=QPushButton(t('owner.fund_receive'))
        self.activate=QPushButton(t('owner.activate_send'))
        self.send=QPushButton(t('owner.prepare_send'))
        self.broadcast=QPushButton(t('owner.broadcast_signed'))
        self.confirm=QPushButton(t('owner.confirm_block'))
        self.recovery=QPushButton(t('owner.verify_recovery'))
        self.inspect=QPushButton(t('owner.inspect_txid'))
        self.intents=QPushButton(t('owner.review_signed'))
        self.resume=QPushButton(t('owner.submit_signed'))
        self.cancel=QPushButton(t('owner.cancel_draft'))
        self.lock=QPushButton(t('owner.lock_q06'))
        self.unlock=QPushButton(t('owner.unlock'))
        self.quit=QPushButton(t('owner.quit'))
        bar.addWidget(self.sync);bar.addWidget(self.fund);bar.addWidget(self.activate)
        box.addLayout(bar)
        payment=QHBoxLayout()
        payment.addWidget(self.send);payment.addWidget(self.broadcast);payment.addWidget(self.cancel)
        box.addLayout(payment)
        box.addWidget(self.confirm)
        box.addWidget(self.recovery)
        box.addWidget(self.inspect)
        box.addWidget(self.intents)
        box.addWidget(self.resume)
        utility=QHBoxLayout()
        utility.addWidget(self.lock);utility.addWidget(self.unlock);utility.addWidget(self.quit)
        box.addLayout(utility)
        self.unlock.clicked.connect(self._unlock_prompt)
        self.sync.clicked.connect(lambda:self._command("snapshot"))
        self.fund.clicked.connect(self._confirm_funding)
        self.activate.clicked.connect(self._confirm_activation)
        self.send.clicked.connect(self._prepare_send)
        self.broadcast.clicked.connect(self._confirm_broadcast)
        self.confirm.clicked.connect(self._confirm_one_block)
        self.recovery.clicked.connect(self._verify_recovery_phrase)
        self.inspect.clicked.connect(self._inspect_past_txid)
        self.intents.clicked.connect(lambda:self._command("intent_status"))
        self.resume.clicked.connect(self._confirm_resume_intent)
        self.cancel.clicked.connect(lambda:self._command("cancel"))
        self.lock.clicked.connect(lambda:self._command("lock"))
        self.quit.clicked.connect(self.request_quit)
        self._poll=QTimer(self);self._poll.timeout.connect(self._check_quit)
        self._poll.setInterval(100);self._poll.start()
        self._ready=False
        self._unlock_allowed=False
        self._test_funded=False
        self._spend_enabled=False
        self._signed_ready=False
        self._approved_commitment=None
        self._pending_confirm_txid=None
        self._pending_action=None
        self._completed_result=None
        self._delivering_result=False
        self._last_error_code=None
        self._recovery_dialog=None
        self._recovered_unsigned_cancel=False
        self._resumable_intent=None
        self.resume.setToolTip(t('owner.resume_tooltip'))
        self.cancel.setToolTip(t('owner.cancel_tooltip'))
        self._set_actions()

    def _action_inputs(self):
        """Explicit inputs for presentation.action_state (no authority; F-08)."""
        state = self.executor.state
        return ActionInputs(
            ready=self._ready, spend_enabled=self._spend_enabled,
            signed_ready=self._signed_ready,
            pending_confirm=self._pending_confirm_txid is not None,
            approved_commitment=self._approved_commitment is not None,
            recovered_unsigned_cancel=self._recovered_unsigned_cancel,
            resumable_intent=self._resumable_intent is not None,
            unlock_allowed=self._unlock_allowed, test_funded=self._test_funded,
            quit_requested=self._quit_requested,
            busy=(self._worker is not None or self.executor.busy
                  or self._delivering_result),
            executor_closed=self.executor.closed, faulted=state.faulted,
            locked=state.locked,
            reauthentication_required=state.reauthentication_required,
            core_alive=state.core_alive)

    def _apply_actions(self, actions):
        for name in BASE_CONTROLS:
            getattr(self, name).setEnabled(actions[name])

    def _set_actions(self):
        self._apply_actions(available_actions(self._action_inputs()))

    def _command(self, action, *args):
        if (self._worker is not None or self.executor.busy or self.executor.closed
                or self._delivering_result):
            return False
        worker=ControlWorker(self.executor, action, args,
                             kwargs={"timeout":240} if action in ("mine","snapshot","activate","prepare","prepare_auto","sign","broadcast","confirm","recovery_verify","inspect_confirmed","intent_status","resume_intent") else None,
                             parent=self)
        # The executor publishes one generation per completed operation.
        # An authenticated control request may finish after this Future but
        # before Qt delivery, even though GUI commands cannot overlap.
        worker.verification_generation = self.executor.state.generation + 1
        self._worker=worker
        self._worker_action = action
        self._completed_result = None
        self._last_error_code = None
        worker.ready.connect(self._receive_result, Qt.ConnectionType.QueuedConnection)
        worker.denied.connect(self._receive_denial, Qt.ConnectionType.QueuedConnection)
        worker.pending.connect(lambda _: self.status.setText(
            t('owner.operation_pending')),
            Qt.ConnectionType.QueuedConnection)
        worker.finished.connect(self._finished)
        worker.finished.connect(worker.deleteLater)
        self._set_actions()
        worker.start()
        return True

    def _passphrase(self, label):
        password, ok = get_secret_text(self, t('owner.password_title'), label)
        return password.encode("utf-8") if ok and password else None

    def _unlock_prompt(self):
        # In-session reauthentication of the SAME original owned REGTEST
        # profile. The backend revalidates owner identity, native Keychain,
        # anchored checkpoint and backup acknowledgement on the live Core.
        # No retry, mining, rebroadcast, reservation release or Core adoption.
        if self._worker is not None or self.executor.busy or self._quit_requested:
            return
        password = self._passphrase(
            t('owner.password_prompt'))
        if password is None:
            return
        self.status.setText(t('owner.unlocking'))
        self._command("unlock", password, False)

    def _remember_profile(self, folder):
        # Remember ONLY the wallet profile PATH. Never password, mnemonic,
        # private keys or native anchor secrets cross this boundary.
        try:
            from .ui_settings import ui_settings
            if folder:
                ui_settings().setValue(
                    "last_shared_bip39_profile" if getattr(self,'shared_profile',None) else "last_bip39_profile", str(folder))
        except Exception:
            pass

    def start(self, password, mode, phrase):
        self.status.setText(t('owner.verifying_profile'))
        self._command("open", password, mode, phrase)

    def _confirm_funding(self):
        if not self._ready or self._worker is not None or self.executor.busy:
            return
        answer=QMessageBox.question(
            self, t('owner.fund_title'),
            t('owner.fund_consent'),
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer==QMessageBox.StandardButton.Yes:
            self.status.setText(t('owner.funding'))
            self._command("mine")

    def _confirm_activation(self):
        if not self._ready or self._spend_enabled:
            return
        choice=QMessageBox.question(
            self,t('owner.activation_title'),
            t('owner.activation_consent'),
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if choice==QMessageBox.StandardButton.Yes:
            self._command("activate")

    def _prepare_send(self):
        if not self._spend_enabled or self._approved_commitment is not None:
            return
        code,ok=QInputDialog.getText(
            self,t('owner.prepare_title'),t('owner.recipient_prompt'))
        if not ok:
            return
        amount,ok=QInputDialog.getText(
            self,t('owner.prepare_title'),
            t('owner.amount_prompt'))
        if not ok:
            return
        if (not code.startswith("wamrtsp1") or len(amount)>19
                or not amount.isascii() or not amount.isdecimal()):
            QMessageBox.warning(self,t('owner.invalid_input_title'),t('owner.invalid_input'))
            return
        atoms_value=int(amount)
        if not 330<=atoms_value<=22_000_000*100_000_000:
            QMessageBox.warning(self,t('owner.invalid_input_title'),t('owner.policy_amount'))
            return
        self._command("prepare_auto",code,atoms_value)

    def _confirm_broadcast(self):
        if not self._signed_ready or self._approved_commitment is None:
            return
        choice=QMessageBox.question(
            self,t('owner.broadcast_title'),
            t('owner.broadcast_consent'),
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if choice==QMessageBox.StandardButton.Yes:
            self._command("broadcast",self._approved_commitment)

    def _confirm_one_block(self):
        txid = self._pending_confirm_txid
        if not self._spend_enabled or txid is None:
            return
        choice=QMessageBox.question(
            self,t('owner.confirm_title'),
            t('owner.confirm_consent').format(txid=txid),
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if choice==QMessageBox.StandardButton.Yes:
            self._command("confirm",txid)

    def _verify_recovery_phrase(self):
        if not self._spend_enabled or self._worker is not None or self.executor.busy:
            return
        dialog = Bip39RecoveryVerifyDialog(self)
        dialog.verify_requested.connect(self._on_recovery_verify_requested)
        dialog.cancelled.connect(self._on_recovery_verify_cancelled)
        self._recovery_dialog = dialog
        dialog.exec()

    def _on_recovery_verify_requested(self, phrase):
        self._recovery_dialog = None
        self.status.setText(t('owner.rescanning'))
        self._command("recovery_verify", phrase)

    def _on_recovery_verify_cancelled(self):
        self._recovery_dialog = None

    def _confirm_resume_intent(self):
        item=self._resumable_intent
        if item is None or not self._spend_enabled or self.executor.state.faulted:
            return
        answer=QMessageBox.question(
            self,t('owner.resume_title'),
            t('owner.resume_consent').format(txid=item['txid'], recipient=item['recipient'], atoms=item['atoms'], fee=item['fee'], state=item['state']),
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer==QMessageBox.StandardButton.Yes and self._resumable_intent is item:
            self._command("resume_intent",item["token"],item["txid"],True)

    def _inspect_past_txid(self):
        if not self._spend_enabled or self.executor.state.faulted:
            return
        txid,ok=QInputDialog.getText(
            self,t('owner.inspect_title'),
            t('owner.inspect_prompt'))
        if ok:
            self._command("inspect_confirmed",txid)

    def _on_ready(self, action, result):
        if action in ('open', 'lock', 'quit', 'unlock'):
            self._resumable_intent = None
        if action in ('open', 'lock', 'quit'):
            self._recovered_unsigned_cancel = False
        elif action in ('snapshot', 'activate', 'unlock') and isinstance(result, dict):
            self._recovered_unsigned_cancel = result.get('recovered_unsigned_cancel_available') is True
        if action=="open":
            self._backup_unacked=False
            # Start from a locked UI state; the backup flow (if required) will
            # promote to ready via _backup_flow_completed.
            self._ready=False
            self.receive.clear()
            self.account.setText(t('owner.account_locked'))
            self.balance.setText(t('owner.balance_unverified'))
            self.tip.setText(t('owner.chain_unverified'))
            backup_status = result.get("backup_status", "verified")
            seed_folder = result.get("seed_folder")
            if backup_status in ("required", "deferred"):
                if backup_status == "required" and seed_folder:
                    try:
                        self.executor.request(
                            "acknowledge_create_pending", seed_folder, timeout=30)
                    except Exception as error:
                        self.status.setText(
                            t('owner.backup_state_unavailable') + operation_error(
                                "acknowledge_create_pending", error))
                        self._backup_unacked=True
                        self._set_actions()
                        return
                self._backup_result = result
                self._backup_flow_active = True
                self._backup_verified = False
                self._present_backup_ack(result)
                return
            self._ready=True
            self.receive.setText(result["receive_code"])
            self.account.setText(t('owner.account_prefix')+result["account_id"])
            self.balance.setText(t('owner.balance_unsynced'))
            self.tip.setText(t('owner.chain_unchecked'))
            self.status.setText(t('owner.seed_opened'))
            self._pending_action = None if result.get('checkpoint_present') else ("snapshot",)
            if result.get('checkpoint_present'):
                self.status.setText(t('owner.checkpoint_retained'))
            self._remember_profile(result.get("seed_folder"))
        elif action=="mine":
            self._test_funded=True
            self.status.setText(t('owner.receive_confirmed').format(height=result['height']))
        elif action in ("snapshot","activate"):
            if result.get("signer_allowed") is True:
                self._spend_enabled=True
            if 'payment_review' in result:
                review = result['payment_review']
                self._approved_commitment = review.commitment if review is not None else None
                self._signed_ready = result.get('payment_signed') is True
                pending = result.get('pending_confirm_txid')
                # A post-broadcast snapshot must not erase the GUI's exact TXID
                # when the session has not yet published pending_confirm_txid.
                # Confirm/lock still clear this field explicitly.
                if pending is not None:
                    self._pending_confirm_txid = pending
                    # After a reopen the session re-identifies its unconfirmed
                    # broadcast from anchored evidence; show that exact TXID.
                    if not self.last_txid.text().strip():
                        self.last_txid.setText(pending)
                if hasattr(self, '_last_review'):
                    self._last_review = review
            self.receive.setText(result["receive_code"])
            self.balance.setText(t('owner.balance_verified').format(confirmed_atoms=result['confirmed_atoms'], available_atoms=result['available_atoms']))
            self.tip.setText(t('owner.chain_verified').format(height=result['height'], tip=result['tip']))
            self._test_funded = result["height"] > 0
            rows=result["history"]
            self.history.setPlainText(
                "\n".join(t('owner.history_row').format(txid=row['txid'], height=row['height'], atoms=row['atoms']) for row in rows)
                if rows else t('owner.no_history'))
            if self._recovered_unsigned_cancel:
                self.status.setText(
                    t('owner.draft_retained'))
            elif self._spend_enabled and self._pending_confirm_txid is not None:
                self.status.setText(
                    t('owner.awaiting_confirmation').format(txid=self._pending_confirm_txid))
            elif (self._spend_enabled and self._pending_confirm_txid is None
                    and reservation_warning(result)):
                self.status.setText(
                    t('owner.reservations_warning'))
            else:
                self.status.setText(
                    t('owner.send_verified')
                    if self._spend_enabled else
                    t('owner.scan_verified'))
        elif action in ("prepare", "prepare_auto"):
            self._approved_commitment=result.commitment
            self._signed_ready=False
            choice=QMessageBox.question(
                self,t('owner.approval_title'),
                owner_approval_text(result),
                QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            self._pending_action=(
                ("sign",result.commitment)
                if choice==QMessageBox.StandardButton.Yes else ("cancel",))
            self.status.setText(t('owner.approval_received'))
        elif action=="sign":
            if result.commitment!=self._approved_commitment:
                self._signed_ready=False
                self.status.setText(t('owner.commitment_mismatch'))
            else:
                self._signed_ready=True
                self.status.setText(t('owner.signed_ready'))
        elif action=="broadcast":
            self._approved_commitment=None
            self._signed_ready=False
            self._pending_confirm_txid=result
            self.last_txid.setText(result)
            self.status.setText(
                t('owner.broadcast_submitted').format(txid=result))
            self._pending_action=("snapshot",)
        elif action=="confirm":
            if result.get("txid")!=self._pending_confirm_txid:
                self.status.setText(t('owner.confirmation_mismatch'))
            else:
                self._pending_confirm_txid=None
                self.status.setText(t('owner.confirmed'))
                self._pending_action=("snapshot",)
        elif action=="recovery_verify":
            self.status.setText(
                t('owner.recovery_result').format(history_count=result['history_count'], confirmed_atoms=result['confirmed_atoms']))
        elif action=="inspect_confirmed":
            if result["status"]=="Q06_CONFIRMED_IN_VERIFIED_HISTORY":
                self.status.setText(t('owner.txid_confirmed'))
            elif result.get("in_mempool") is True:
                self.status.setText(
                    t('owner.txid_pending'))
            else:
                self.status.setText(
                    t('owner.txid_unknown'))
        elif action=="intent_status":
            intents=result["intents"]
            resumable=[i for i in intents if i["classification"] in
                       ("SIGNED_NOT_SUBMITTED_RESUMABLE","UNCERTAIN_NOT_OBSERVED_RESUMABLE")]
            self._resumable_intent=resumable[0] if len(resumable)==1 else None
            counts={}
            for item in intents:
                counts[item["classification"]]=counts.get(item["classification"],0)+1
            summary="; ".join(t('owner.intent_count').format(classification=k, count=v) for k,v in sorted(counts.items())) or t('owner.no_intents')
            self.status.setText(
                t('owner.intent_summary').format(summary=summary)
                +(t('owner.intent_resumable')
                  if self._resumable_intent is not None else
                  t('owner.intent_protected')))
        elif action=="resume_intent":
            self._resumable_intent=None
            self._pending_confirm_txid=result["txid"]
            self.last_txid.setText(result["txid"])
            self.status.setText(
                t('owner.resumed').format(txid=result['txid']))
            self._pending_action=("snapshot",)
        elif action=="cancel":
            self._recovered_unsigned_cancel=False
            if isinstance(result, dict) and result.get('recovered_unsigned_cancelled') is True:
                self._pending_action=('snapshot',)  # Read only, never a write retry.
            self._approved_commitment=None
            self._signed_ready=False
            self.status.setText(t('owner.draft_cancelled'))
        elif action=="lock":
            self._backup_unacked=False
            self._backup_flow_active=False
            self._backup_verified=False
            self._backup_result=None
            self._ready=False
            self._unlock_allowed=True
            self._spend_enabled=False
            self._signed_ready=False
            self._approved_commitment=None
            self._pending_confirm_txid=None
            self.last_txid.clear()
            self.receive.clear()
            self.account.setText(t('owner.account_locked'))
            self.balance.setText(t('owner.balance_unverified'))
            self.tip.setText(t('owner.chain_unverified'))
            self.history.clear()
            self.status.setText(t('owner.locked_status'))
        elif action=="unlock":
            # In-session reauthentication of the SAME original owned REGTEST
            # BIP39 profile. Only a genuinely verified acknowledgement promotes
            # the wallet back to a usable (ready) session; deferred or refused
            # backups return to the fail-closed backup flow.
            backup_status = result.get("backup_status", "verified") if isinstance(result, dict) else None
            if backup_status == "verified":
                self._unlock_allowed = True
                self._ready = True
                self.receive.setText(result["receive_code"])
                self.account.setText(t('owner.account_prefix') + result["account_id"])
                self.balance.setText(t('owner.balance_unsynced'))
                self.tip.setText(t('owner.chain_unchecked'))
                self.status.setText(
                    t('owner.seed_unlocked'))
                # Seed authentication alone cannot scan over an existing
                # native checkpoint. Match the normal Open route: retain
                # explicit Enable sending/reconciliation consent first.
                self._pending_action = (
                    ("snapshot",) if not result.get('checkpoint_present')
                    or result.get('signer_allowed') is True else None)
                if result.get('signer_allowed') is True:
                    self._spend_enabled = True
            elif backup_status == "deferred":
                self._backup_unacked = False
                self._backup_flow_active = True
                self._backup_verified = False
                self._backup_result = result
                self._unlock_allowed = False
                self._present_backup_ack(result)
            else:
                self._backup_unacked = True
                self._backup_flow_active = False
                self._backup_result = None
                self._unlock_allowed = False
                self.status.setText(
                    t('owner.unlock_backup_refused'))
        elif action=="quit":
            self._ready=False
            self._closed=True
        self._set_actions()

    def _present_backup_ack(self, result):
        """Subclasses override to show the production backup UI.

        The base implementation has no UI, so it fails closed: the wallet is
        deferred/locked and the flow completes as unsuccessful."""
        self._defer_active_backup()

    def _backup_flow_completed(self, success):
        """Called by the subclass UI when backup is acknowledged or deferred."""
        self._backup_flow_active = False
        result = self._backup_result
        self._backup_result = None
        if not success or result is None:
            self._backup_unacked = True
            self._unlock_allowed = False
            self.status.setText(
                t('owner.backup_unacknowledged'))
            self._set_actions()
            self._check_quit()
            return
        self._ready = True
        self._unlock_allowed = True
        self.receive.setText(result["receive_code"])
        self.account.setText(t('owner.account_prefix') + result["account_id"])
        self.balance.setText(t('owner.balance_unsynced'))
        self.tip.setText(t('owner.chain_unchecked'))
        self.status.setText(
            t('owner.seed_opened'))
        self._set_actions()
        if self._quit_requested:
            self._check_quit()
            return
        self._pending_action = ("snapshot",)
        self._finished()

    def _defer_active_backup(self):
        """Fail-safe helper used on quit/close when the backup UI is open."""
        if not self._backup_flow_active:
            return
        self._backup_flow_active = False
        if self._backup_verified:
            # The backend already recorded the verified acknowledgement.
            # Leaving the success page must never downgrade it to deferred.
            self._backup_flow_completed(True)
            return
        try:
            self.executor.request("backup_defer", timeout=30)
        except Exception:
            pass
        self._backup_flow_completed(False)

    def _on_denied(self, code):
        code = public_code(code)
        self._last_error_code = code
        if (code == 'WALLET_UNLOCK_REFUSED' and self.executor.state.locked
                and not self.executor.state.faulted
                and not self.executor.state.reauthentication_required
                and self.executor.state.core_alive is True):
            # A failed initial Open has no earlier Lock event to expose this
            # existing control. Allow another EXPLICIT password attempt on
            # the same owner; this grants neither keys nor spending scope.
            self._unlock_allowed = True
            self._ready = False
        if self.executor.state.faulted:
            self._signed_ready=False
        if code == 'WALLET_BROADCAST_REJECTED_LOCK_RETAINED':
            # The backend forgot the in-memory payment; the signed reservation
            # stays locked and is listed by "Review signed payments".
            self._signed_ready=False
            self._approved_commitment=None
        self.status.setText(
            t('owner.faulted')
            if self.executor.state.faulted else
            t('owner.refused_prefix') + error_text(code))
        self._set_actions()

    def _receive_result(self, action, result):
        self._completed_result = (action, result)

    def _receive_denial(self, code):
        self._completed_result = (None, code)

    def _finished(self):
        # Backup Continue also drains pending work after Open's worker has
        # finished. Only worker-delivered results carry a generation to check.
        verification_generation = (self._worker.verification_generation
                                   if self._worker is not None else None)
        self._worker=None
        finished_action, self._worker_action = self._worker_action, None
        # Deliver only AFTER thread completion. A signature approval runs a
        # nested Qt event loop; finished must not drain the next command before
        # the operator has decided. No operation is retried or resubmitted.
        completed, self._completed_result = self._completed_result, None
        if finished_action == "quit" and completed is not None and completed[0] is None:
            # W-QUIT-02: a refused owner shutdown is NOT retried automatically.
            # Without this, _check_quit resubmitted "quit" after every refusal,
            # without bound (a refused stop or a dead owned Core spun the GUI
            # and re-ran the stop path). The refusal is shown; each further
            # explicit Quit (button, Cmd+Q, window close) makes exactly one
            # new attempt. The owner stays open and app.exec() keeps running.
            self._quit_requested = False
        if completed is not None:
            self._delivering_result = True
            try:
                action, result = completed
                if action is None:
                    self._on_denied(result)
                elif (action in ('snapshot', 'activate', 'unlock', 'open')
                      and verification_generation != self.executor.state.generation):
                    # Reject before either compatibility labels or Fusion
                    # pages can render an invalidated verification result.
                    self._on_denied('WALLET_CORE_UNVERIFIED')
                else:
                    self._on_ready(action, result)
            finally:
                self._delivering_result = False
                completed = None
        pending,self._pending_action=self._pending_action,None
        if pending is not None and not self._quit_requested:
            self._command(*pending)
        self._set_actions()
        self._check_quit()

    def _check_quit(self):
        if self.executor.closed and self.executor.join(0):
            self._poll.stop()
            self._closed=True
            qt_application().quit()
        elif (self._quit_requested and self._worker is None and not self.executor.busy
              and not self._delivering_result):
            self._command("quit")

    def request_quit(self):
        self._quit_requested=True
        self._defer_active_backup()
        self.status.setText(t('owner.stopping'))
        self._check_quit()

    def closeEvent(self,event):
        if self.executor.closed:
            event.accept()
        else:
            event.ignore()
            self.request_quit()


def _last_remembered_profile():
    # Remember ONLY the last successfully opened wallet profile PATH. Never
    # password, mnemonic, private keys or native anchor secrets cross here.
    from .ui_settings import ui_settings
    try:
        value = ui_settings().value("last_bip39_profile", type=str)
        return str(value) if value else ""
    except Exception:
        return ""


def _onboarding_password(parent, mode):
    """Recoverable input validation before any executor request creates custody."""
    while True:
        password, ok = get_secret_text(
            parent, t('owner.onboarding_title'),
            t('owner.new_password'))
        if not ok:
            return "", False
        if not 12 <= len(password.encode("utf-8")) <= 1024:
            password = ""
            QMessageBox.warning(parent, t('owner.password_warning_title'),
                                t('owner.password_length'))
            continue
        if mode in ("create", "restore"):
            confirmation, confirmed = get_secret_text(
                parent, t('owner.confirm_password_title'), t('owner.confirm_password_prompt'))
            if not confirmed:
                password = confirmation = ""
                return "", False
            matches = password == confirmation
            confirmation = ""
            if not matches:
                password = ""
                QMessageBox.warning(parent, t('owner.password_warning_title'),
                                    t('owner.password_mismatch'))
                continue
        return password, True


def launch_bip39_trial(root,core,source,*,mode,authorized=False,shared_profile=None):
    if authorized is not True or mode not in ("create","restore","reopen"):
        raise ValueError("Q06_GUI_EXPLICIT_REGTEST_CONSENT_REQUIRED")
    # The caller already obtained explicit selection of the supervisor root.
    # A remembered seed-container path is only a GUI hint, never authority to
    # redirect Core or select a different profile after the user's choice.
    app=qt_application()
    app.setQuitOnLastWindowClosed(False)
    executor=WalletExecutor(lambda:Bip39ReadOnlyBackend(root,core,source,shared_profile=shared_profile))
    # Normal application: use the pre-existing WAM Fusion navigation,
    # Overview, QR Receive, History, Send and Security components. Frozen
    # diagnostic Q06 probes retain their independent owner/spend contracts.
    from .bip39_fusion_gui import Bip39FusionWindow
    window=Bip39FusionWindow(executor,shared_profile=shared_profile)
    window.show()
    password, ok = _onboarding_password(window, mode)
    phrase=""
    if ok and mode=="restore":
        phrase,ok=get_secret_multiline_text(
            window,t('owner.restore_title'),
            t('owner.restore_prompt'))
    if ok:
        window.start(password.encode("utf-8"),mode,phrase)
    else:
        window.request_quit()
    password=phrase=""
    result=app.exec() if not executor.closed else 0
    if not executor.closed:
        raise ValueError("Q06_GUI_ORIGINAL_OWNER_STILL_ACTIVE")
    executor.join()
    return result
