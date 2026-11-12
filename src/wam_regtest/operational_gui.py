"""Native disposable test-wallet Send/Sign/Broadcast and Security/Settings UI."""
import sys
from . import custody
from decimal import Decimal, InvalidOperation
from pathlib import Path
import secrets
import re
from PySide6.QtCore import QThread, Signal, QTimer, Qt
from PySide6.QtWidgets import (
    QApplication,QFrame,QVBoxLayout,QLabel,QLineEdit,QPushButton,QHBoxLayout,QDialog,
    QFileDialog,QMessageBox,QInputDialog,QComboBox,QCheckBox,QScrollArea,
)
from wam_regtest.desktop import RegtestWalletWindow, qt_application
from wam_regtest.wallet_session import WalletSession, PaymentReview
from wam_regtest.wallet_read import format_wam
from .fusion_ui import panel,page,label,action,ResponsiveRow,ReadableText
from .fusion_pages import PaymentSteps,PaymentApproval
from .amounts import _parse_atoms,parse_amount
from .gui_errors import operation_error,error_text,public_code,INPUT_ERRORS
from .infrastructure import core_compat
from .bip39_locale import t


class OperationWorker(QThread):
    ready=Signal(str,object)
    denied=Signal(str)
    def __init__(self, session, action, args):
        super().__init__()
        self.session,self.action,self.args=session,action,args
    def disclose(self,txid,fields,password):
        return self.session.disclose_record(txid,fields,password,approved=True)
    def run(self):
        try:
            methods={"prepare":self.session.prepare,"sign":self.session.sign,
                     "broadcast":self.session.broadcast,"cancel":self.session.cancel,
                     "lock":self.session.lock,"unlock":self.session.unlock,
                     "backup":self.session.backup,"recover":self.session.recover_backup,
                     "mine":self.session.mine,"network":self.session.network_diagnostics,"disclose":self.disclose}
            result=methods[self.action](*self.args)
            self.ready.emit(self.action,result)
        except Exception as error:
            self.denied.emit(operation_error(self.action,error))
        finally:
            self.args=()  # Release temporary GUI passphrase copies, best effort.


class OperationalWalletWindow(RegtestWalletWindow):
    operation_completed=Signal(str,object)
    operation_failed=Signal(str)
    def __init__(self,session):
        self.session=session
        self.review=None
        self.signed=False
        self._submitted_txid=None
        self._approval_open=False
        super().__init__(session.core_dir,session.datadir,session.source,session=session)
        self.setWindowTitle(t("operational.window_title"))
        self.warning.setText(t("operational.warning"))
        self.navigation.addItems([t("fusion.send"),t("fusion.security"),t("fusion.settings")])
        send,layout=page(t("operational.send_title"),t("operational.send_subtitle"),t("operational.send_kicker"))
        self.steps=PaymentSteps();layout.addWidget(self.steps)
        form,fl=panel(t("operational.payment_details"),t("operational.payment_details_subtitle"))
        self.recipient=QLineEdit();self.recipient.setMaxLength(256);self.recipient.setPlaceholderText(t("operational.recipient_placeholder"));self.recipient.setAccessibleName(t("operational.recipient_accessible"))
        self.amount=QLineEdit();self.amount.setMaxLength(32);self.amount.setPlaceholderText('0.00000000');self.amount.setAccessibleName(t("operational.amount_accessible"))
        self.fee=QLineEdit('0.00010000');self.fee.setMaxLength(32);self.fee.setAccessibleName(t("operational.fee_accessible"))
        fl.addWidget(label(t("operational.recipient_caption"),'FusionKicker'));fl.addWidget(self.recipient)
        numbers=QHBoxLayout()
        for title,widget in ((t("operational.amount_kicker"),self.amount),(t("operational.fee_kicker"),self.fee)):
            col=QVBoxLayout();col.addWidget(label(title,'FusionKicker'));col.addWidget(widget);numbers.addLayout(col,1)
        fl.addLayout(numbers);fl.addWidget(label(t("operational.atom_arithmetic")))
        self.prepare_button=action(t("operational.prepare_payment"),'send',True);fl.addWidget(self.prepare_button)
        review,rl=panel(t("operational.review_panel"),t("operational.review_panel_subtitle"))
        self.review_text=ReadableText(t("operational.no_active_review_hint"));rl.addWidget(self.review_text,1)
        self.sign_button=action(t("operational.approve_sign"),'security',True);self.broadcast_button=action(t("operational.broadcast"),'send');self.cancel_button=action(t("operational.cancel_draft"),'history');rl.addWidget(self.sign_button);rl.addWidget(self.broadcast_button);rl.addWidget(self.cancel_button)
        layout.addWidget(ResponsiveRow(form,review,weights=[3,2]));layout.addWidget(label(t("operational.signing_warning"),'FusionGold'));layout.addStretch();self.stack.addWidget(send)
        self.prepare_button.clicked.connect(self.prepare_payment);self.sign_button.clicked.connect(lambda:self.approve_payment('sign'));self.broadcast_button.clicked.connect(lambda:self.approve_payment('broadcast'));self.cancel_button.clicked.connect(lambda:self.start_operation('cancel'))

        security,layout=page(t('operational.security_title'),t('operational.security_subtitle'),t('operational.security_kicker'))
        vault,vl=panel(t('operational.encrypted_wallet'),t('operational.encrypted_wallet_subtitle'))
        self.vault_state=label(t('operational.awaiting_state'),'FusionCardValue');vl.addWidget(self.vault_state);vl.addWidget(label(t('operational.sqlite_plaintext')))
        row=QHBoxLayout();self.lock_button=action(t('operational.lock_wallet'),'lock');self.lock_button.setObjectName('FusionDestructive');self.unlock_button=action(t('operational.unlock'),'unlock',True);row.addWidget(self.lock_button);row.addWidget(self.unlock_button);vl.addLayout(row)
        anchor,al=panel(t('operational.checkpoint_anchor'),custody.anchor_label())
        self.anchor_state=label(t('operational.not_attested'),'FusionCardValue');al.addWidget(self.anchor_state);al.addWidget(label(t('operational.anchor_guard')))
        layout.addWidget(ResponsiveRow(vault,anchor))
        backup,bl=panel(t('operational.encrypted_backup'),t('operational.encrypted_backup_subtitle'))
        self.backup_button=action(t('operational.save_backup'),'backup',True);bl.addWidget(self.backup_button);bl.addWidget(label(t('operational.backup_contents')))
        recovery,rl=panel(t('operational.verified_recovery'),t('operational.verified_recovery_subtitle'))
        self.recover_button=action(t('operational.recover_backup'),'sync');rl.addWidget(self.recover_button);rl.addWidget(label(t('operational.recovery_generations')))
        layout.addWidget(ResponsiveRow(backup,recovery))
        disclosure,dl=panel(t('operational.disclosure_panel'),t('operational.disclosure_panel_subtitle'))
        self.disclosure_record=QComboBox();self.disclosure_record.setAccessibleName(t('operational.disclosure_accessible'));dl.addWidget(self.disclosure_record)
        self.disclosure_fields={};fields_row=QHBoxLayout()
        for field in ('txid','block_height','credit_atoms','debit_atoms'):
            check=QCheckBox(t({'txid':'operational.field_txid','block_height':'operational.field_block_height','credit_atoms':'operational.field_credit_atoms','debit_atoms':'operational.field_debit_atoms'}[field]));fields_row.addWidget(check);self.disclosure_fields[field]=check
        dl.addLayout(fields_row);self.disclosure_button=action(t('operational.review_disclosure'),'security');dl.addWidget(self.disclosure_button);self.disclosure_text=label(t('operational.no_disclosure'),'FusionMuted',True);dl.addWidget(self.disclosure_text);layout.addWidget(disclosure);layout.addStretch();self.stack.addWidget(security)
        self.lock_button.clicked.connect(lambda:self.start_operation('lock'));self.unlock_button.clicked.connect(self.unlock_wallet);self.backup_button.clicked.connect(self.backup_wallet);self.recover_button.clicked.connect(self.recover_wallet);self.disclosure_button.clicked.connect(self.disclose_selected)

        settings,layout=page(t('fusion.settings'),t('operational.settings_subtitle'),t('operational.settings_kicker'))
        appearance,apl=panel(t('operational.appearance'),t('operational.appearance_subtitle'))
        self.settings_appearance=QComboBox()
        for text,value in ((t('desktop.appearance_auto'),'auto'),(t('desktop.appearance_light'),'light'),(t('desktop.appearance_dark'),'dark')):self.settings_appearance.addItem(text,value)
        self.settings_appearance.currentIndexChanged.connect(self.appearance.setCurrentIndex)
        self.appearance.currentIndexChanged.connect(self.settings_appearance.setCurrentIndex)
        apl.addWidget(self.settings_appearance);apl.addWidget(label(t('operational.appearance_auto_note')))
        build,bl=panel(t('operational.application'),t('operational.application_subtitle'))
        import PySide6
        bl.addWidget(label(t('operational.platform_qt').format(platform={'darwin':t('operational.platform_macos_arm64'),'win32':t('operational.platform_windows_x64'),'linux':t('operational.platform_linux_x64')}.get(sys.platform,t('operational.platform_unsupported')),version=PySide6.__version__)))
        bl.addWidget(label(t('operational.linux_experimental')))
        layout.addWidget(ResponsiveRow(appearance,build))
        node,nl=panel(t('operational.developer_core') if sys.platform=='linux' else t('operational.official_core'),
            t('operational.linux_core_subtitle').format(release=core_compat.CORE_RELEASE) if sys.platform=='linux' else t('operational.core_subtitle').format(release=core_compat.CORE_RELEASE))
        self.core_identity=label(t('operational.no_core_identity'),'ReceiveCode',True);nl.addWidget(self.core_identity);layout.addWidget(node)
        privacy,pl=panel(t('operational.network_policy'),t('operational.network_policy_subtitle'))
        self.network_button=action(t('operational.verify_privacy'),'security');pl.addWidget(self.network_button);self.network_text=label(t('operational.network_unavailable'));pl.addWidget(self.network_text);layout.addWidget(privacy)
        sync,sl=panel(t('operational.sync_panel'),t('operational.sync_panel_subtitle'))
        self.settings_sync=action(t('operational.sync_chain'),'sync');self.settings_sync.clicked.connect(self.request_sync);sl.addWidget(self.settings_sync)
        self.mine_button=action(t('operational.mine_block'),'core');sl.addWidget(self.mine_button);self.mine_notice=label(t('operational.mine_notice'),'FusionGold');sl.addWidget(self.mine_notice);layout.addWidget(sync);layout.addStretch();self.stack.addWidget(settings)
        self.mine_button.clicked.connect(lambda:self.start_operation('mine'));self.network_button.clicked.connect(lambda:self.start_operation('network'))
        self.appearance.setItemText(0,t('desktop.auto_platform').format(platform={'win32':t('desktop.platform_windows'),'darwin':t('desktop.platform_macos'),'linux':t('desktop.platform_linux')}.get(sys.platform,t('desktop.platform_system'))))
        self.dashboard.go_send.clicked.connect(lambda:self.navigation.setCurrentRow(3));self.dashboard.open_security.clicked.connect(lambda:self.navigation.setCurrentRow(4))
        self._actions=(self.prepare_button,self.sign_button,self.broadcast_button,self.cancel_button,self.lock_button,self.unlock_button,self.backup_button,self.recover_button,self.mine_button,self.network_button,self.disclosure_button)
        self._update_controls();self.apply_theme()

    def approve_payment(self,kind):
        if self._approval_open or self.review is None or self._worker is not None or self.session.locked or self.session.faulted:return
        if kind=='sign' and self.signed or kind=='broadcast' and not self.signed:return
        review=self.review
        dialog=PaymentApproval(review,kind,self)
        self._approval_open=True
        self._update_controls()
        try:
            approved=dialog.exec()==QDialog.DialogCode.Accepted
        finally:
            self._approval_open=False
            dialog.deleteLater()
            self._update_controls()
        if approved and self.review is review:self.start_operation(kind,review.commitment)

    def _update_controls(self):
        if not hasattr(self,"_actions"):
            return
        busy=self._worker is not None or self._approval_open
        unlocked=not self.session.locked and not self.session.faulted
        self.dashboard.go_send.setEnabled(not busy and unlocked)
        # A locked user must still be able to reach recovery/security.
        self.dashboard.open_security.setEnabled(not busy)
        for button in self._actions:
            button.setEnabled(not busy and unlocked)
        self.prepare_button.setEnabled(not busy and unlocked and self.review is None)
        self.sign_button.setEnabled(not busy and unlocked and self.review is not None and not self.signed)
        self.broadcast_button.setEnabled(not busy and unlocked and self.review is not None and self.signed)
        self.cancel_button.setEnabled(not busy and unlocked and self.review is not None and not self.signed)
        self.unlock_button.setEnabled(not busy and self.session.locked)
        self.recover_button.setEnabled(not busy and self.session.locked)
        self.lock_button.setEnabled(not busy and not self.session.locked)
        self.disclosure_record.setEnabled(not busy and unlocked)
        for field in self.disclosure_fields.values(): field.setEnabled(not busy and unlocked)
        self.disclosure_button.setEnabled(not busy and unlocked and self.disclosure_record.count()>0)
        if hasattr(self,"vault_state"):
            self.vault_state.setText(t("fusion.locked") if self.session.locked else t("operational.faulted_retained") if self.session.faulted else t("operational.unlocked_test"))
            self.anchor_state.setText(t("operational.anchor_checked") if self._snapshot is not None and unlocked else t("operational.anchor_reverify"))
            self.settings_sync.setEnabled(not busy and unlocked)
            self.steps.set_stage(2 if busy and getattr(self._worker,"action",None)=="sign" else 3 if self.signed else 1 if self.review is not None else 0)
        editable=not busy and unlocked and self.review is None
        for field in (self.recipient,self.amount,self.fee):
            field.setEnabled(editable)

    def start_operation(self,action,*args):
        if self._worker is not None:
            return
        worker=OperationWorker(self.session,action,args)
        self._worker=worker
        self.refresh_button.setEnabled(False)
        labels={"prepare":t("operational.preparing_review"), "sign":t("operational.signing_payment"),
                "broadcast":t("operational.submitting"), "cancel":t("operational.canceling_draft"),
                "lock":t("operational.locking"), "unlock":t("operational.verifying_passphrase"),
                "backup":t("operational.saving_backup"), "recover":t("operational.verifying_recovery"),
                "mine":t("operational.mining"),"network":t("operational.verifying_privacy"),"disclose":t("operational.verifying_disclosure")}
        self.status.setText(labels[action]+"…")
        worker.ready.connect(self._operation_ready)
        worker.denied.connect(self._operation_denied)
        worker.finished.connect(self._worker_finished)
        worker.finished.connect(worker.deleteLater)
        self._update_controls()
        worker.start()

    def _worker_finished(self):
        super()._worker_finished()
        self._update_controls()

    def prepare_payment(self):
        try:
            atoms=parse_amount(self.amount.text())
        except (ValueError,InvalidOperation,OverflowError):
            self._operation_denied("WALLET_INPUT_AMOUNT_INVALID")
            return
        try:
            # Fee has a lower dust-independent floor and explicit WSP limit.
            fee=_parse_atoms(self.fee.text(),1,1_000_000)
        except (ValueError,InvalidOperation,OverflowError):
            self._operation_denied("WALLET_INPUT_FEE_INVALID")
            return
        self.start_operation("prepare",self.recipient.text().strip(),atoms,fee)

    def _operation_ready(self,action,result):
        if action in ("prepare","sign"):
            self.review=result
            self.recipient.setCursorPosition(0)
            self.signed=action=="sign"
            self.review_text.setText(
                t('operational.payment_review').format(
                    heading=t('operational.heading_signed') if self.signed else t('operational.heading_review'),
                    code=result.code,
                    amount=format_wam(result.atoms),
                    atoms=result.atoms,
                    fee_amount=format_wam(result.fee),
                    fee_atoms=result.fee,
                    change_amount=format_wam(result.change_atoms),
                    change_atoms=result.change_atoms,
                    inputs=result.input_count))
        elif action in ("cancel","broadcast","lock"):
            self.review=None
            self.signed=False
            if action=="broadcast":
                self._submitted_txid=result
            elif action=="lock":
                self._submitted_txid=None
            self.review_text.setText(t('operational.submitted_review').format(txid=result) if action=="broadcast" else t('operational.no_active_review'))
        if action=="disclose":
            import json
            self.disclosure_text.setText(json.dumps(result,sort_keys=True))
        if action=="network":
            self.network_text.setText(t('operational.network_verified'))
        if action=="lock":
            self._clear_balance()
            self.status.setText(t('operational.locked_anchored').format(anchor=custody.anchor_label()))
        else:
            message = (t('operational.backup_saved') if action=="backup" else
                       t('operational.broadcast_submitted') if action=="broadcast" else
                       t('operational.signed_retained') if action=="sign" else
                       t('operational.review_ready_status') if action=="prepare" else
                       t('operational.operation_completed'))
            self.status.setText(message)
            if action in ("unlock","recover","mine"):
                self.apply_snapshot(result)
        self._update_controls()
        self.operation_completed.emit(action,result)

    def apply_snapshot(self,snap):
        super().apply_snapshot(snap)
        if self._snapshot is not None and self._submitted_txid is not None:
            confirmed=next((r for r in snap.history if r.txid==self._submitted_txid and r.confirmations>0),None)
            if confirmed is not None:
                if self.review is None:
                    self.review_text.setText(t('operational.confirmed_tx').format(height=str(confirmed.block_height), txid=self._submitted_txid))
                self._submitted_txid=None
            else:
                # This is a local submission receipt, not a synthetic mempool
                # balance or evidence the node still holds the transaction.
                self.status.setText(self.status.text()+t('operational.submitted_pending'))
        if hasattr(self,"core_identity"):
            self.core_identity.setText(t('operational.core_sha').format(digest=snap.core_sha256) if self._snapshot is not None else t('operational.core_identity_unverified'))
        if hasattr(self,"disclosure_record"):
            self.disclosure_record.clear()
            if self._snapshot is not None:
                for row in snap.history:
                    self.disclosure_record.addItem(t('operational.disclosure_item').format(prefix=row.txid[:16], height=str(row.block_height)),row.txid)
            self._update_controls()

    def _clear_balance(self):
        super()._clear_balance()
        if hasattr(self,'disclosure_record'):
            self.disclosure_record.clear();self.disclosure_text.setText(t('operational.no_disclosure_short'))
            self.core_identity.setText(t('operational.no_core_identity'))
            if self.session.locked or self.session.faulted:
                self._submitted_txid=None
                self.recipient.clear();self.amount.clear();self.review_text.setText(t('operational.locked_payment_hidden'))
            self._update_controls()

    def disclose_selected(self):
        fields=tuple(sorted(k for k,v in self.disclosure_fields.items() if v.isChecked()))
        txid=self.disclosure_record.currentData()
        if not fields or txid is None:
            return
        if QMessageBox.question(self,t('operational.disclosure_title'),
                t('operational.disclosure_question').format(fields=", ".join(fields)),
                QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes:
            return
        password=self._passphrase(t('operational.disclosure_passphrase'))
        if password is not None:
            self.start_operation("disclose",txid,fields,password)

    def _operation_denied(self,reason):
        reason=public_code(reason)
        if reason=='WALLET_BROADCAST_REJECTED_LOCK_RETAINED':
            # Session forgot the in-memory payment; reservation stays signed.
            self.review=None;self.signed=False
        if (reason in INPUT_ERRORS and self._snapshot is not None
                and not self.session.locked and not self.session.faulted):
            # Only known pre-mutation input/coin-selection refusals retain a
            # previously live-verified snapshot. Never label it fresh/current.
            self.verification_badge.setText(t('operational.last_verified').format(height=str(self._snapshot.height)))
        else:
            self.network_text.setText(t('operational.network_unverified'))
            self._clear_balance()
        self.status.setText(error_text(reason))
        self.operation_failed.emit(reason)
        self._update_controls()

    def request_sync(self):
        # Timer/manual refresh must not occupy the worker inside the modal
        # approval loop. The signer still reattests the live chain and intent.
        if self._approval_open:return
        if self.session.locked or self.session.faulted:
            return
        super().request_sync()
        self._update_controls()

    def _passphrase(self,label):
        password,ok=QInputDialog.getText(self,t('operational.disposable_title'),label,QLineEdit.EchoMode.Password)
        return password.encode() if ok else None

    def unlock_wallet(self):
        password=self._passphrase(t('operational.unlock_prompt'))
        if password is not None:
            approved=self._core_reauthentication_consent()
            if approved is None:return
            self.start_operation("unlock",password,approved)

    def _core_reauthentication_consent(self):
        if not self.session._core_reauthentication_required:return False
        answer=QMessageBox.question(self,t('operational.reauth_title'),
            t('operational.reauth_body'),
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)
        return True if answer==QMessageBox.StandardButton.Yes else None

    def backup_wallet(self):
        parent=QFileDialog.getExistingDirectory(self,t('operational.backup_parent'))
        if parent:
            directory=Path(parent).resolve()/("wam-regtest-backup-"+secrets.token_hex(6))
            try:
                custody.create_directory(directory)
                self.start_operation("backup",directory,"wallet-backup.enc")
            except (OSError,ValueError):
                self._operation_denied("WALLET_BACKUP_DIRECTORY_DENIED")

    def recover_wallet(self):
        name,_=QFileDialog.getOpenFileName(self,t('operational.backup_file'),filter=t('operational.backup_filter'))
        if name:
            password=self._passphrase(t('operational.backup_passphrase'))
            if password is not None:
                approved=self._core_reauthentication_consent()
                if approved is None:return
                path=Path(name).absolute()
                self.start_operation("recover",path.parent,path.name,password,approved)

    def closeEvent(self,event):
        if self._worker is not None:
            super().closeEvent(event)
            return
        try:
            self.session.close()
        except Exception:
            event.ignore()
            self.status.setText(t('operational.shutdown_denied'))
            return
        if self._appearance_connected:
            QApplication.styleHints().colorSchemeChanged.disconnect(self.apply_theme)
            self._appearance_connected=False
        super().closeEvent(event)


def launch_disposable_wallet(core_dir,datadir,source,mining_address):
    app=qt_application()
    choice,ok=QInputDialog.getItem(None,t('operational.disposable_title'),
        t('operational.fresh_chain'),
        [t('operational.create_keys'),t('operational.recover_choice')],0,False)
    if not ok:
        return 0
    backup=None
    if choice==t('operational.recover_choice'):
        name,_=QFileDialog.getOpenFileName(None,t('operational.backup_file'),filter=t('operational.backup_filter'))
        if not name:
            return 0
        backup=Path(name).absolute()
    while True:
        password,ok=QInputDialog.getText(None,t('operational.disposable_title'),
            t('operational.backup_passphrase_prompt'),QLineEdit.EchoMode.Password)
        if not ok:
            return 0
        encoded=password.encode()
        if len(password)>=12 and len(encoded)<=1024:
            break
        QMessageBox.warning(None,t('operational.passphrase_length_title'),t('operational.passphrase_length'))
    if backup is None:
        session=WalletSession.create(core_dir,datadir,source,encoded,mining_address,authorized=True)
    else:
        session=WalletSession.from_backup(core_dir,datadir,source,backup.parent,backup.name,
                                           encoded,mining_address,authorized=True)
    encoded=None
    password=""
    window=OperationalWalletWindow(session)
    window.show()
    QTimer.singleShot(0,window.request_sync)
    return app.exec()
