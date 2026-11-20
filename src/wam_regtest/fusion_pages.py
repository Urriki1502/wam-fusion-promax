"""Fusion 2.0 reusable screen components; no RPC, keys or signing authority."""
from __future__ import annotations
from .bip39_locale import t as ui_text
from PySide6.QtCore import Qt, Signal, QRectF, QTimer, QEvent
from PySide6.QtGui import QColor,QPainter,QFont,QFontDatabase
from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QGridLayout,QLabel,QLineEdit,QComboBox,QCheckBox,QTableWidget,QTableWidgetItem,QHeaderView,QApplication,QDialog,QDialogButtonBox,QFrame,QToolButton,QButtonGroup,QScrollArea
from .fusion_ui import SHELL,label,panel,page,action,ResponsiveRow,AdaptiveButtonRow,keyboard_table,vector_icon,fusion_palette,activity_by_block,grow_with_wrapped_text,direction_tone,QR,pending_amount_text
from .fusion_i18n import bind, bind_headers, bind_items, retranslate_tree
from .presentation.strings import text as catalog_text
from .wallet_read import format_wam

_REC1_KEYS = {
    'CONFIRMED': 'rec1.CONFIRMED',
    'IN_LOCAL_MEMPOOL': 'rec1.IN_LOCAL_MEMPOOL',
    'NOT_OBSERVED_LOCALLY': 'rec1.NOT_OBSERVED_LOCALLY',
    'CONFLICTED': 'rec1.CONFLICTED',
    'REJECTED_BY_POLICY': 'rec1.REJECTED_BY_POLICY',
    'BROADCAST_OUTCOME_UNCERTAIN': 'rec1.BROADCAST_OUTCOME_UNCERTAIN',
    'CORRUPTED_EVIDENCE': 'rec1.CORRUPTED_EVIDENCE',
}
_SIGNED_NEVER_SUBMITTED = 'SIGNED_NOT_SUBMITTED_RESUMABLE'


def _rec1_read(key, language, lookup):
    if lookup is not None:
        return lookup(key)
    return catalog_text(key, language)


def rec1_status_line(state, language=None, *, lookup=None):
    """One localized line. An unknown state stays unclassified, never a raw code."""
    key = _REC1_KEYS.get(state) if type(state) is str else None
    if key is None:
        return _rec1_read('rec1.UNCLASSIFIED', language, lookup)
    line = _rec1_read(key, language, lookup)
    if state == 'BROADCAST_OUTCOME_UNCERTAIN':
        # PM-082 already says the inputs stay locked and nothing is released.
        line += _rec1_read('pages.no_retry_until_confirmed', language, lookup)
    return line


def sole_signed_never_submitted(intents):
    """The one intent the GUI may offer for a first submission, or None.

    Offered only when exactly one intent is classified
    SIGNED_NOT_SUBMITTED_RESUMABLE and its reservation state is signed.
    Uncertain, mixed, unknown, and any other state are not offered.
    """
    if type(intents) not in (list, tuple):
        return None
    chosen = None
    for item in intents:
        if not isinstance(item, dict):
            return None
        if (item.get('classification') == _SIGNED_NEVER_SUBMITTED
                and item.get('state') == 'signed'
                and type(item.get('token')) is str
                and type(item.get('txid')) is str):
            if chosen is not None:
                return None
            chosen = item
    return chosen


def reveal(widget, visible):
    """Show or hide a control and move keyboard focus if it was on the hidden one."""
    visible = bool(visible)
    if (not widget.isHidden()) == visible:
        return
    if not visible and widget.hasFocus():
        widget.focusNextPrevChild(True)
    widget.setVisible(visible)


def _name_line_clear(edit, name):
    from PySide6.QtWidgets import QToolButton
    from .fusion_i18n import phrase_key
    key = phrase_key(name)
    if key:
        edit._line_clear_key = key
        from .bip39_locale import t as catalog
        shown = str(catalog(key))
    else:
        shown = name if isinstance(name, str) else ''
    for button in edit.findChildren(QToolButton):
        if key or not button.accessibleName():
            button.setAccessibleName(shown)


def rec1_states_by_txid(intents):
    """txid -> rec1_state for the History detail. Missing states stay missing."""
    found = {}
    if type(intents) not in (list, tuple):
        return found
    for item in intents:
        if not isinstance(item, dict):
            continue
        txid = item.get('txid')
        if type(txid) is not str or not txid:
            continue
        state = item.get('rec1_state')
        found[txid] = state if type(state) is str else None
    return found


class PaymentQR(QWidget):
    def __init__(self):
        super().__init__();self.matrix=None;self.setMinimumSize(220,220);self.setMaximumSize(300,300);self.setAccessibleName(ui_text('pages.qr_accessible'))
    def set_code(self,code):
        self.matrix=None;self.update()
        if not code:return
        from wam_sp.core import decode_address
        if not code.startswith('wamrtsp1'):raise ValueError('FUSION_RECEIVE_NAMESPACE_DENIED')
        decode_address(code)
        import qrcode
        qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,border=4,box_size=1)
        qr.add_data(code,optimize=0);qr.make(fit=True);self.matrix=qr.get_matrix();self.update()
    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.RenderHint.Antialiasing);r=QRectF(self.rect()).adjusted(1,1,-1,-1);p.setPen(Qt.PenStyle.NoPen);p.setBrush(QColor(QR['paper']));p.drawRoundedRect(r,12,12)
        if self.matrix:
            n=len(self.matrix);unit=max(1,int(min(self.width()-18,self.height()-18)/n));size=unit*n;left=(self.width()-size)//2;top=(self.height()-size)//2
            p.setRenderHint(QPainter.RenderHint.Antialiasing,False);p.setBrush(QColor(QR['ink']))
            for y,row in enumerate(self.matrix):
                for x,dark in enumerate(row):
                    if dark:p.drawRect(left+x*unit,top+y*unit,unit,unit)
        else:p.setPen(QColor(QR['caption']));p.drawText(self.rect(),Qt.AlignmentFlag.AlignCenter,ui_text('pages.address_unavailable'))
        p.end()


class ReceivePage(QWidget):
    def __init__(self):
        super().__init__();self.code=None;self.setObjectName('FusionInner');root=QVBoxLayout(self);root.setContentsMargins(0,0,0,0)
        header=QWidget();header_layout=QVBoxLayout(header);header_layout.setContentsMargins(SHELL['page_side'],SHELL['page_top'],SHELL['page_right'],0);header_layout.setSpacing(SHELL['page_gap']);header_layout.addWidget(label(ui_text('pages.receive'),'PageTitle'));header_layout.addWidget(grow_with_wrapped_text(label(ui_text('pages.silent_payments_note'))));header_layout.addWidget(grow_with_wrapped_text(label(ui_text('pages.disposable_funds'),'FusionGold')));root.addWidget(header)
        self.scroll,layout=page(ui_text('pages.receive'),ui_text('pages.receive_subtitle'), '',header=False)
        root.addWidget(self.scroll)
        card,cl=panel(ui_text('pages.your_silent_payment_address'),ui_text('pages.receive_scope'))
        self.qr=PaymentQR();qrbox=QWidget();ql=QVBoxLayout(qrbox);ql.setContentsMargins(0,0,0,0);ql.addWidget(self.qr,alignment=Qt.AlignmentFlag.AlignCenter);ql.addWidget(label(ui_text('pages.exact_address_qr'),'FusionKicker'),alignment=Qt.AlignmentFlag.AlignCenter)
        address=QWidget();al=QVBoxLayout(address);al.setContentsMargins(0,0,0,0);al.addWidget(label(ui_text('pages.bip352_regtest'),'FusionBadge'));self.receive_code=label('—','ReceiveCode',True);self.receive_code.setMinimumWidth(0);al.addWidget(self.receive_code)
        self.copy_button=action(ui_text('pages.copy_full_address'),'copy',True);self.copy_button.setEnabled(False);self.copy_button.setAccessibleName(ui_text('pages.copy_full_address'));self.copy_button.setAccessibleDescription(ui_text('pages.copy_full_address_description'));self.copy_button.clicked.connect(self.copy_address);al.addWidget(self.copy_button);self.copy_status=label(ui_text('pages.copy_full_value'));al.addWidget(self.copy_status);al.addStretch()
        self._copy_timer=QTimer(self);self._copy_timer.setSingleShot(True)
        self._copy_timer.timeout.connect(lambda: self.copy_status.setText(ui_text('pages.copy_complete') if self.code else ui_text('pages.address_locked')))
        cl.addWidget(ResponsiveRow(qrbox,address,weights=[2,3],breakpoint=610));layout.addWidget(card)
        self.received=label(ui_text('pages.no_verified_receiving_activity'));layout.addWidget(self.received);layout.addStretch()
    def retranslate(self):
        retranslate_tree(self)
        self.qr.update()
        if hasattr(self, '_rendered_snap'):
            self.render_snapshot(self._rendered_snap)
    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.Type.LanguageChange:
            self.retranslate()
    def render_snapshot(self,snap):
        self._rendered_snap = snap
        self.code=None;self.copy_button.setEnabled(False);self.receive_code.setText('—');self.qr.set_code(None)
        candidate=snap.receive_code if snap else None;self.qr.set_code(candidate);self.code=candidate;self.receive_code.setText(self.code or '—');self.copy_button.setEnabled(bool(self.code));self._show_copy_state()
        if snap is None:
            self.received.setText(ui_text('pages.no_verified_receiving_activity'))
        elif type(snap.receive_count) is int:
            self.received.setText(ui_text('pages.receive_count').format(count=snap.receive_count))
        else:
            self.received.setText(ui_text('pages.receive_stats_unavailable'))
    def _show_copy_state(self):
        if self.code:
            self.copy_status.setText(ui_text('pages.copy_full_value'))
            self.copy_status.show()
        else:
            self.copy_status.setText(ui_text('pages.address_locked'))
            self.copy_status.show()
    def copy_address(self):
        if self.code:
            QApplication.clipboard().setText(self.code)
            self.copy_status.setText(ui_text('pages.full_address_copied'))
            self.copy_status.show()
            self._copy_timer.start(2200)


class HistoryPage(QWidget):
    page_requested=Signal(int)
    def __init__(self):
        super().__init__();self.setObjectName('FusionInner');self.rows=();self.mode='dark';self._offset=0;self._total=0;self._has_snapshot=False;root=QVBoxLayout(self);root.setContentsMargins(0,0,0,0)
        self.scroll,layout=page(ui_text('pages.history'),ui_text('pages.history_subtitle') + ' ' + ui_text('pending.history_subtitle'),'');root.addWidget(self.scroll)
        card,cl=panel();toolbar=QHBoxLayout();self.search=QLineEdit();self.search.setPlaceholderText(ui_text('pages.search_placeholder'));self.search.setClearButtonEnabled(True);self.search.setAccessibleName(ui_text('pages.search_confirmed_transactions'));self.filter=QComboBox();self.filter.setAccessibleName(ui_text('pages.history_type_filter'));self.filter.view().setAccessibleName(ui_text('pages.history_type_filter'));self.filter.addItems((ui_text('pages.all_activity'),ui_text('pages.credits'),ui_text('pages.debits')));toolbar.addWidget(self.search,1);self.filter.setParent(card);self.filter.hide();_name_line_clear(self.search,ui_text('pages.search_confirmed_transactions'));cl.addLayout(toolbar)
        self._filter_chips = []
        self._filter_group = QButtonGroup(self)
        self._filter_group.setExclusive(True)
        for index in range(self.filter.count()):
            chip = QToolButton()
            chip.setObjectName('FusionCategory')
            chip.setCheckable(True)
            key = ('pages.all_activity', 'pages.credits', 'pages.debits')[index]
            bind(chip, text=key, accessible_name=key)
            self._filter_group.addButton(chip, index)
            toolbar.addWidget(chip)
            self._filter_chips.append(chip)
        self._filter_chips[0].setChecked(True)
        self._filter_group.idClicked.connect(self.filter.setCurrentIndex)
        self.table=QTableWidget(0,6);self.table.setObjectName('FusionActivityTable');self.table.setHorizontalHeaderLabels((ui_text('pages.direction'),ui_text('pages.transaction'),ui_text('pages.block'),ui_text('pages.confirmed'),ui_text('pages.credit_wam'),ui_text('pages.debit_wam')));self.table.verticalHeader().hide();self.table.setShowGrid(False);self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers);self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows);keyboard_table(self.table,ui_text('pages.history'));self.table.setMinimumHeight(220);self._size_columns();cl.addWidget(self.table);self.table.viewport().installEventFilter(self)
        self.newer=action(ui_text('pages.newer_confirmed_history'),'chevron_left');self.older=action(ui_text('pages.older_confirmed_history'),'chevron_right');self.newer.setAccessibleName(ui_text('pages.newer_confirmed_history'));self.older.setAccessibleName(ui_text('pages.older_confirmed_history'));self.newer.setEnabled(False);self.older.setEnabled(False);self.newer.hide();self.older.hide();self.newer.clicked.connect(self._newer);self.older.clicked.connect(self._older);cl.addWidget(AdaptiveButtonRow(self.newer,self.older))
        self.scope=label('');cl.addWidget(self.scope)
        self.empty=label(ui_text('history.unavailable'));cl.addWidget(self.empty);layout.addWidget(card)
        detail,dl=panel(ui_text('pages.transaction_details'),ui_text('pages.select_row'));self.detail_id=label(ui_text('pages.no_transaction_selected'),'ReceiveCode',True);dl.addWidget(self.detail_id);self.detail_values=grow_with_wrapped_text(label(''));dl.addWidget(self.detail_values);self.copy_button=action(ui_text('pages.copy_full_transaction_id'),'copy');self.copy_button.setAccessibleName(ui_text('pages.copy_full_transaction_id'));self.copy_button.setEnabled(False);self.copy_button.hide();self.copy_button.clicked.connect(self.copy_txid);dl.addWidget(self.copy_button);layout.addWidget(detail);layout.addStretch()
        self.table.itemSelectionChanged.connect(self.show_details);self.search.textChanged.connect(self.apply_filter);self.filter.currentIndexChanged.connect(self.apply_filter)
        bind(self.search, placeholder='pages.search_placeholder', accessible_name='pages.search_confirmed_transactions')
        bind(self.filter, accessible_name='pages.history_type_filter')
        bind(self.filter.view(), accessible_name='pages.history_type_filter')
        bind_items(self.filter, ('pages.all_activity', 'pages.credits', 'pages.debits'))
        bind_headers(self.table, ('pages.direction', 'pages.transaction', 'pages.block', 'pages.confirmed', 'pages.credit_wam', 'pages.debit_wam'))
    def retranslate(self):
        query = self.search.text()
        choice = self.filter.currentIndex()
        retranslate_tree(self)
        for index, chip in enumerate(self._filter_chips):
            key = ('pages.all_activity', 'pages.credits', 'pages.debits')[index]
            bind(chip, text=key, accessible_name=key)
        if hasattr(self, '_rendered_snap'):
            self._render_history(self._rendered_snap)
            self.search.setText(query)
            if self._rendered_snap is not None:
                self.filter.setCurrentIndex(choice)
        _name_line_clear(self.search, ui_text('pages.search_confirmed_transactions'))
    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.Type.LanguageChange:
            self.retranslate()
    # Narrow windows (R-5): columns size to their content, the transaction
    # column stretches, and when everything cannot fit, Block and Confirmed
    # are hidden first (the detail panel always shows both). Amounts and the
    # direction are never hidden.
    _NARROW_HIDDEN = (2, 3)
    def _size_columns(self):
        header=self.table.horizontalHeader()
        for column in range(self.table.columnCount()):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch if column==1 else QHeaderView.ResizeMode.ResizeToContents)
    def _measure_full_width(self):
        # Qt reports no content width for a HIDDEN column, so the full width
        # is measured once per render with every column shown, then cached;
        # measuring while hidden made the columns flip back and forth.
        for column in self._NARROW_HIDDEN:self.table.setColumnHidden(column,False)
        header=self.table.horizontalHeader()
        self._full_width=sum(max(header.sectionSizeHint(c),self.table.sizeHintForColumn(c)) for c in range(self.table.columnCount()))
    def _fit_columns(self):
        if getattr(self,'_full_width',None) is None:self._measure_full_width()
        narrow=self._full_width>self.table.viewport().width()
        for column in self._NARROW_HIDDEN:
            if self.table.isColumnHidden(column)!=narrow:self.table.setColumnHidden(column,narrow)
    def eventFilter(self,watched,event):
        from PySide6.QtCore import QEvent
        if watched is self.table.viewport() and event.type()==QEvent.Type.Resize:self._fit_columns()
        return super().eventFilter(watched,event)
    def _selected_txid(self):
        row = self.table.currentRow()
        if (0 <= row < len(self.rows)
                and not self.table.isRowHidden(row)
                and self.table.selectionModel().hasSelection()):
            return self.rows[row].txid
        return None
    def _clear_selection(self):
        self.table.clearSelection()
        self.table.setCurrentCell(-1, -1)
    def render_snapshot(self,snap):
        # A fresh chain snapshot drops a previous REC-1 annotation so a
        # later confirmation is not still described by an older state.
        self._rec1_by_txid = {}
        self._render_history(snap)
    def _render_history(self, snap):
        """Render current facts; only a new snapshot invalidates REC-1 notes."""
        self._rendered_snap = snap
        selected_txid = self._selected_txid() if snap is not None else None
        self._has_snapshot = snap is not None
        self.rows=(snap.pending_history + snap.history) if snap else ()
        self.search.blockSignals(True)
        try:
            self.search.clear()
        finally:
            self.search.blockSignals(False)
        if snap is None:
            self.filter.blockSignals(True)
            try:
                self.filter.setCurrentIndex(0)
            finally:
                self.filter.blockSignals(False)
        self._offset=snap.history_offset if snap and type(snap.history_offset) is int else 0
        self._total=snap.history_count if snap and type(snap.history_count) is int else len(snap.history) if snap else 0
        shown=len(snap.history) if snap else 0
        newer_page = bool(snap) and self._offset>0
        older_page = bool(snap) and self._offset+shown<self._total
        self.newer.setEnabled(newer_page)
        self.older.setEnabled(older_page)
        reveal(self.newer, newer_page)
        reveal(self.older, older_page)
        if snap is None:
            self.scope.setText('')
        elif snap.history_complete:
            self.scope.setText(ui_text('pages.record_count').format(count=shown))
        else:
            start=self._offset+1 if shown else 0
            end=self._offset+shown
            proof = (ui_text('pages.history_fingerprinted')
                     if snap.history_sha256 is not None else
                     ui_text('pages.history_paged'))
            self.scope.setText(
                ui_text('pages.history_window').format(offset=self._offset, start=start, end=end, records=self._total, proof=proof))
        if snap and snap.pending_atoms is None:
            self.scope.setText(self.scope.text() + ' · ' + ui_text('pending.unverified'))
        c=fusion_palette(self.mode)
        self.table.blockSignals(True)
        try:
            self._clear_selection()
            self.table.setRowCount(len(self.rows))
            reselect_row = None
            for i,row in enumerate(self.rows):
                net=row.credit_atoms-row.debit_atoms;direction=ui_text('pages.received') if net>0 else ui_text('pages.sent') if net<0 else ui_text('pages.activity')
                pending = getattr(row, 'state', None) == 'pending'
                if pending:
                    direction += ' · ' + ui_text('pending.state')
                values=(direction,row.txid[:12]+'…','—' if pending else str(row.block_height),ui_text('pending.state') if pending else str(row.confirmations),format_wam(row.credit_atoms),format_wam(row.debit_atoms))
                for j,value in enumerate(values):
                    item=QTableWidgetItem(value);item.setToolTip(row.txid);item.setData(Qt.ItemDataRole.UserRole,row.txid)
                    if j==0:item.setIcon(vector_icon('receive' if net>0 else 'send',direction_tone(c, net)))
                    if j in (1,4,5):item.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
                    if j>=2:item.setTextAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                    self.table.setItem(i,j,item)
                self.table.setRowHeight(i,48)
                if selected_txid is not None and row.txid == selected_txid:
                    reselect_row = i
            if reselect_row is not None:
                self.table.selectRow(reselect_row)
        finally:
            self.table.blockSignals(False)
        self.apply_filter();self._measure_full_width();self._fit_columns()
    def set_theme(self,mode):
        self.mode=mode;c=fusion_palette(mode)
        for i,row in enumerate(self.rows):
            item=self.table.item(i,0)
            if item is not None:
                net=row.credit_atoms-row.debit_atoms
                item.setIcon(vector_icon('receive' if net>0 else 'send',direction_tone(c, net)))
    def apply_filter(self,*_):
        self._filter_chips[self.filter.currentIndex()].setChecked(True)
        term=self.search.text().strip().lower();choice=self.filter.currentIndex();shown=0
        for i,row in enumerate(self.rows):
            visible=(not term or term in row.txid.lower() or term in str(row.block_height)) and (choice==0 or choice==1 and row.credit_atoms>0 or choice==2 and row.debit_atoms>0)
            self.table.setRowHidden(i,not visible);shown+=visible
        self.empty.setVisible(shown==0)
        self.empty.setText(
            ui_text('history.no_matching_activity') if self.rows else
            ui_text('history.empty_verified') if self._has_snapshot else
            ui_text('history.unavailable'))
        row=self.table.currentRow()
        if 0<=row<len(self.rows) and self.table.isRowHidden(row):
            self.table.blockSignals(True)
            try:
                self._clear_selection()
            finally:
                self.table.blockSignals(False)
        self.show_details()
    def show_details(self):
        row=self.table.currentRow()
        if (not 0<=row<len(self.rows)
                or self.table.isRowHidden(row)
                or not self.table.selectionModel().hasSelection()):
            self.detail_id.setText(ui_text('pages.no_transaction_selected'));self.detail_values.setText('');self.copy_button.setEnabled(False);self.copy_button.hide();return
        tx=self.rows[row];self.detail_id.setText(tx.txid)
        if getattr(tx, 'state', None) == 'pending':
            text = ui_text('pending.state')
            text += ' · ' + ui_text('pages.credit_wam') + ': ' + format_wam(tx.credit_atoms)
            text += ' · ' + ui_text('pages.debit_wam') + ': ' + format_wam(tx.debit_atoms)
            if tx.debit_atoms:
                text += '\n' + ui_text('pending.details_value').format(
                    fee=pending_amount_text(tx.fee_atoms),
                    change=pending_amount_text(tx.pending_change_atoms))
            self.detail_values.setText(self._with_rec1(text, tx.txid))
        else:
            self.detail_values.setText(self._with_rec1(ui_text('pages.block_amounts').format(height=tx.block_height, confirmations=tx.confirmations, credit=format_wam(tx.credit_atoms), debit=format_wam(tx.debit_atoms)), tx.txid))
        self.copy_button.setEnabled(True)
        self.copy_button.show()
    def set_rec1_states(self, by_txid):
        """Show one REC-1 line in the History detail for a reviewed txid."""
        clean = {}
        if isinstance(by_txid, dict):
            for txid, state in by_txid.items():
                if type(txid) is str and txid:
                    clean[txid] = state if type(state) is str else None
        self._rec1_by_txid = clean
        self.show_details()
    def _with_rec1(self, text, txid):
        notes = getattr(self, '_rec1_by_txid', None)
        if isinstance(notes, dict) and txid in notes:
            return text + '\n' + rec1_status_line(notes[txid], lookup=ui_text)
        return text
    def select_txid(self,txid):
        self.search.clear();self.filter.setCurrentIndex(0)
        for i,tx in enumerate(self.rows):
            if tx.txid==txid:self.table.selectRow(i);self.show_details();return
        self.table.blockSignals(True)
        try:
            self._clear_selection()
        finally:
            self.table.blockSignals(False)
        self.show_details()
        self.detail_id.setText(ui_text('history.txid_not_displayed'))
    def copy_txid(self):
        row=self.table.currentRow()
        if (self.copy_button.isEnabled()
                and 0<=row<len(self.rows)
                and not self.table.isRowHidden(row)
                and self.table.selectionModel().hasSelection()):
            QApplication.clipboard().setText(self.rows[row].txid)
    def _older(self):
        from .history_pages import GUI_HISTORY_LIMIT
        if self.older.isEnabled():self.page_requested.emit(self._offset+GUI_HISTORY_LIMIT)
    def _newer(self):
        from .history_pages import GUI_HISTORY_LIMIT
        if self.newer.isEnabled():self.page_requested.emit(max(0,self._offset-GUI_HISTORY_LIMIT))


class PaymentSteps(QFrame):
    def __init__(self):
        super().__init__();self.setObjectName('FusionInset');layout=QHBoxLayout(self);layout.setContentsMargins(16,13,16,13);self.labels=[]
        self._step_keys = ('pages.review','pages.approve_signature','pages.broadcast')
        for i, name in enumerate(self._step_titles()):
            item=grow_with_wrapped_text(label(f'{i+1}  {name}','FusionMuted'));item.setAlignment(Qt.AlignmentFlag.AlignCenter);layout.addWidget(item,1);self.labels.append(item)
    def _step_titles(self):
        return (ui_text('pages.review'), ui_text('pages.approve_signature'), ui_text('pages.broadcast'))
    def retranslate(self):
        for index, (item, name) in enumerate(zip(self.labels, self._step_titles())):
            item.setText(f'{index + 1}  {name}')
    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.Type.LanguageChange:
            self.retranslate()
    def set_stage(self,stage):
        # Preserve callers' five-stage lifecycle while presenting three short steps.
        stage = (0, 1, 1, 2, 3)[max(0, min(stage, 4))]
        for i,item in enumerate(self.labels):
            if i<stage:item.setObjectName('FusionVerified')
            elif i==stage:item.setObjectName('FusionGold')
            else:item.setObjectName('FusionMuted')
            item.style().unpolish(item);item.style().polish(item)


class WalletConsent(QDialog):
    """Fusion-styled explicit consent; default Cancel grants no authority."""
    def __init__(self, title, message, parent, *, password=False, accept_text=None):
        super().__init__(parent)
        self.setObjectName('FusionApproval')
        self.setWindowTitle(title)
        self.resize(540, 260)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        for text, role in ((title, 'PageTitle'), (message, 'FusionMuted')):
            # Wrapped consent text must grow with its wrapped height; the shared
            # Maximum policy clipped long titles/explanations (V19 Reconcile).
            wrapped = grow_with_wrapped_text(label(text, role))
            policy = wrapped.sizePolicy()
            policy.setVerticalPolicy(policy.Policy.Minimum)
            policy.setHeightForWidth(True)
            wrapped.setSizePolicy(policy)
            layout.addWidget(wrapped)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setAccessibleName(ui_text('pages.original_wallet_password'))
        self.password_input.setVisible(password)
        layout.addWidget(self.password_input)
        buttons = QDialogButtonBox()
        cancel = buttons.addButton(ui_text('pages.cancel'), QDialogButtonBox.ButtonRole.RejectRole)
        approve = buttons.addButton(accept_text or (ui_text('pages.unlock') if password else ui_text('pages.approve')), QDialogButtonBox.ButtonRole.AcceptRole)
        cancel.setDefault(True)
        approve.setAutoDefault(False)
        approve.setObjectName('FusionPrimary')
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def showEvent(self, event):
        super().showEvent(event)
        self.layout().activate()
        needed = self.layout().totalHeightForWidth(self.width())
        self.resize(self.width(), max(self.height(), needed, self.sizeHint().height()))
        self.layout().activate()


def _quoted(review):
    source = getattr(review, 'rate_source', None)
    rate = getattr(review, 'rate_atoms_per_kvb', None)
    classification = getattr(review, 'rate_classification', None)
    before = getattr(review, 'available_before', None)
    after = getattr(review, 'available_after', None)
    total = getattr(review, 'total_debit', None)
    if (source in ('NETWORK_FLOOR', 'NETWORK_FLOOR_2X', 'ESTIMATOR') and type(rate) is int
            and type(classification) is str and type(before) is int
            and type(after) is int and type(total) is int):
        if source == 'NETWORK_FLOOR_2X':
            source_label = ui_text('fee.source.NETWORK_FLOOR_2X')
        elif source == 'NETWORK_FLOOR':
            source_label = ui_text('fee.source.NETWORK_FLOOR')
        else:
            source_label = ui_text('fee.source.ESTIMATOR')
        return dict(amount=format_wam(review.atoms), fee=format_wam(review.fee),
                    source=source_label, rate=format_wam(rate),
                    classification=classification, total=format_wam(total),
                    available_before=format_wam(before), available_after=format_wam(after),
                    change=format_wam(review.change_atoms), inputs=review.input_count,
                    input_count=review.input_count,
                    code=review.code, atoms=review.atoms, fee_atoms=review.fee,
                    change_atoms=review.change_atoms,
                    commitment=getattr(review, 'commitment', ''))
    return None


def _replaceability_text(review):
    return ('\n' + ui_text('payment.replaceable_yes')
            if getattr(review, 'replaceable', False) is True else '')


def approval_amount_text(review):
    """Sign/Broadcast dialog facts, including PSBT-derived replaceability."""
    quoted = _quoted(review)
    if quoted is not None:
        return ui_text('pages.payment_review_auto').format(**quoted) + _replaceability_text(review)
    return ui_text('pages.payment_amounts').format(
        amount=format_wam(review.atoms), fee=format_wam(review.fee),
        change=format_wam(review.change_atoms), inputs=review.input_count) + _replaceability_text(review)


def fusion_review_text(review):
    quoted = _quoted(review)
    if quoted is not None:
        return ui_text('wallet.review_details_auto').format(**quoted) + _replaceability_text(review)
    return ui_text('wallet.review_details').format(
        code=review.code, amount=format_wam(review.atoms),
        fee=format_wam(review.fee), change=format_wam(review.change_atoms)) + _replaceability_text(review)


def owner_approval_text(review):
    quoted = _quoted(review)
    if quoted is not None:
        return ui_text('owner.approval_details_auto').format(**quoted) + _replaceability_text(review)
    return ui_text('owner.approval_details').format(
        code=review.code, atoms=review.atoms, fee=review.fee,
        change_atoms=review.change_atoms, input_count=review.input_count,
        commitment=review.commitment) + _replaceability_text(review)


def operational_review_text(review, *, signed=False, heading=None):
    if heading is None:
        heading = ui_text('operational.heading_signed') if signed else ui_text('operational.heading_review')
    quoted = _quoted(review)
    if quoted is not None:
        quoted = dict(quoted, heading=heading, fee_amount=format_wam(review.fee),
                      change_amount=format_wam(review.change_atoms))
        return ui_text('operational.payment_review_auto').format(**quoted) + _replaceability_text(review)
    return ui_text('operational.payment_review').format(
        heading=heading, code=review.code, amount=format_wam(review.atoms),
        atoms=review.atoms, fee_amount=format_wam(review.fee), fee_atoms=review.fee,
        change_amount=format_wam(review.change_atoms), change_atoms=review.change_atoms,
        inputs=review.input_count) + _replaceability_text(review)


class PaymentApproval(QDialog):
    """UI-only explicit approval, default Cancel; no session operation inside."""
    def __init__(self,review,kind,parent):
        super().__init__(parent);self.setWindowTitle(ui_text('pages.approve_signature') if kind=='sign' else ui_text('pages.approve_broadcast'));self.setObjectName('FusionApproval');self.setWindowModality(Qt.WindowModality.ApplicationModal);self.resize(580,440)
        layout=QVBoxLayout(self);layout.setContentsMargins(28,24,28,24);layout.setSpacing(16)
        layout.addWidget(label(ui_text('pages.explicit_transaction_approval'),'FusionKicker'));layout.addWidget(label(ui_text('pages.approve_signature') if kind=='sign' else ui_text('pages.submit_to_regtest'),'PageTitle'))
        layout.addWidget(label(ui_text('pages.sign_irreversible') if kind=='sign' else ui_text('pages.broadcast_reply_uncertain'),'FusionGold'))
        card,cl=panel(ui_text('pages.exact_payment'));cl.addWidget(label(ui_text('pages.recipient'),'FusionKicker'));cl.addWidget(label(review.code,'ReceiveCode',True));cl.addWidget(grow_with_wrapped_text(label(approval_amount_text(review))));self.review_scroll=QScrollArea();self.review_scroll.setWidgetResizable(True);self.review_scroll.setFrameShape(QFrame.Shape.NoFrame);self.review_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff);self.review_scroll.setWidget(card);card.setAutoFillBackground(False);self.review_scroll.viewport().setAutoFillBackground(False);bind(self.review_scroll,accessible_name='pages.exact_payment');layout.addWidget(self.review_scroll,1)
        buttons=QDialogButtonBox();self.cancel=buttons.addButton(ui_text('pages.cancel'),QDialogButtonBox.ButtonRole.RejectRole);self.approve=buttons.addButton(ui_text('pages.approve_sign') if kind=='sign' else ui_text('pages.approve_broadcast_2'),QDialogButtonBox.ButtonRole.AcceptRole);self.approve.setObjectName('FusionPrimary');self.cancel.setDefault(True);self.approve.setAutoDefault(False);buttons.rejected.connect(self.reject);buttons.accepted.connect(self.accept);layout.addWidget(buttons)
        self._fit_height()

    def _fit_height(self):
        parent = self.parentWidget()
        screen = self.screen().availableGeometry()
        ceiling = min(screen.height() - 64, parent.height() - 32 if parent else screen.height() - 64)
        self.resize(min(640, screen.width() - 64), min(max(440, self.sizeHint().height() + 8), max(440, ceiling)))

    def _sync_layouts(self):
        if self.layout() is not None:
            self.layout().invalidate()
            self.layout().activate()
        for child in self.findChildren(QWidget):
            if child.layout() is not None:
                child.layout().invalidate()
                child.layout().activate()

    def showEvent(self,event):
        super().showEvent(event)
        # Polish and lay out synchronously before approval can receive input.
        # All exact facts remain in the scrollable card; consent and Cancel
        # stay outside it, within the available parent/screen height.
        self._fit_height()
        self._sync_layouts()
        self._fit_height()
        self._sync_layouts()


def _lock_counts(summary):
    counts = summary.get('counts') if isinstance(summary, dict) else None
    if not isinstance(counts, dict):
        return {}
    return counts


def describe_broadcast_result(txid, inspect=None, *, lock_summary=None):
    """Map verified Core inspect/history facts to Result copy. Never infers failure.

    An evicted, conflicted, unknown or unverified lock summary never keeps
    "Confirmation is pending." Inspect facts still win when they are present.
    """
    import re
    valid = type(txid) is str and re.fullmatch(r'[0-9a-f]{64}', txid) is not None
    status = inspect.get('status') if isinstance(inspect, dict) else None
    mempool = inspect.get('in_mempool') if isinstance(inspect, dict) else None
    if valid and status == 'Q06_CONFIRMED_IN_VERIFIED_HISTORY':
        return ui_text('pages.confirmed_on_this_regtest_chain') + txid
    if valid and mempool is True:
        return (ui_text('pages.mempool_pending')
                + txid + ui_text('pages.no_retry_reserved'))
    if valid and mempool is False and status == 'Q06_TX_NOT_IN_CONFIRMED_HISTORY':
        return (ui_text('pages.txid_uncertain') + txid
                + ui_text('pages.no_retry_or_release'))
    if isinstance(lock_summary, dict) and mempool not in (True, False) and status != 'Q06_CONFIRMED_IN_VERIFIED_HISTORY':
        counts = _lock_counts(lock_summary)
        evicted = counts.get('evicted', 0)
        conflicted = counts.get('conflicted', 0)
        unknown = counts.get('unknown', 0)
        unverified = (lock_summary.get('verified') is not True or evicted > 0
                      or conflicted > 0 or unknown > 0)
        if unverified:
            if valid:
                return (ui_text('pages.txid_uncertain') + txid
                        + ui_text('pages.no_retry_or_release'))
            return ui_text('pages.broadcast_uncertain')
        if (lock_summary.get('verified') is True and counts.get('mempool', 0) > 0
                and evicted == 0 and conflicted == 0 and unknown == 0 and valid):
            return (ui_text('pages.mempool_pending')
                    + txid + ui_text('pages.no_retry_reserved'))
    if not valid:
        return ui_text('pages.broadcast_uncertain')
    return (ui_text('pages.submitted_pending') + txid
            + ui_text('pages.no_retry_until_confirmed'))


class NetworkPage(QWidget):
    """V1-NET status surface. Never invents peers, height or connectivity."""

    def __init__(self):
        super().__init__()
        self.setObjectName('FusionInner')
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        self.scroll, layout = page(
            ui_text('pages.network'),
            ui_text('pages.network_subtitle'), '')
        root.addWidget(self.scroll)
        status, sl = panel(ui_text('pages.network_status'), ui_text('pages.unknown_until_verified'))
        self.mode_value = label(ui_text('pages.not_verified'), 'FusionCardValue')
        self.connection_value = label(ui_text('pages.core_connectivity_is_not_verified'))
        self.peer_value = label(ui_text('pages.peers_after_check'))
        self.height_value = label(ui_text('pages.height_after_snapshot'))
        self.sync_value = label(ui_text('pages.sync_unknown'))
        self.identity_value = label(ui_text('pages.shared_identity_scope'))
        self.identity_value.hide()
        for widget in (self.mode_value, self.connection_value, self.peer_value,
                       self.height_value, self.sync_value, self.identity_value):
            widget.setMinimumWidth(0)
            sl.addWidget(widget)
        self.attention_host = QVBoxLayout()
        sl.addLayout(self.attention_host)
        layout.addWidget(status)
        controls, cl = panel(ui_text('wallet.advanced_title'), ui_text('pages.v1_net_commands'))
        self.controls_card = controls
        self.controls_toggle = QToolButton()
        self.controls_toggle.setObjectName('FusionAdvanced')
        bind(self.controls_toggle, text='wallet.advanced_title', accessible_name='wallet.advanced_title')
        self.controls_toggle.setCheckable(True)
        cl.addWidget(self.controls_toggle)
        self.controls_body = QWidget()
        body_layout = QVBoxLayout(self.controls_body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        self.controls_note = label(ui_text('pages.manual_peer'))
        body_layout.addWidget(self.controls_note)
        self.controls_host = QVBoxLayout()
        body_layout.addLayout(self.controls_host)
        cl.addWidget(self.controls_body)
        self.controls_body.hide()
        self.controls_toggle.toggled.connect(self.controls_body.setVisible)
        controls.hide()
        layout.addWidget(controls)
        layout.addStretch()

    def retranslate(self):
        retranslate_tree(self)
        saved = getattr(self, '_last_render', None)
        if saved is not None:
            self.render(**saved)

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.Type.LanguageChange:
            self.retranslate()

    def render(self, *, shared=False, connected=None, peer_count=None, height=None,
               tip=None, coordinator=None, core_alive=None, identity=None):
        self.controls_card.setVisible(shared)
        self._last_render = dict(
            shared=shared, connected=connected, peer_count=peer_count, height=height,
            tip=tip, coordinator=coordinator, core_alive=core_alive, identity=identity)
        self.mode_value.setText(ui_text('pages.shared_regtest') if shared else ui_text('pages.isolated_regtest'))
        if core_alive is True:
            self.connection_value.setText(ui_text('pages.owned_core_is_alive'))
        elif core_alive is False:
            self.connection_value.setText(ui_text('pages.owned_core_is_not_running'))
        else:
            self.connection_value.setText(ui_text('pages.core_connectivity_is_not_verified'))
        if type(peer_count) is int:
            self.peer_value.setText(
                ui_text('pages.peer_count').format(count=peer_count)
                + ('' if connected is None else (ui_text('pages.connected') if connected else ui_text('pages.disconnected'))))
        else:
            self.peer_value.setText(ui_text('pages.peers_after_check'))
        if type(height) is int:
            self.height_value.setText(ui_text('pages.chain_height') + str(height))
        else:
            self.height_value.setText(ui_text('pages.height_after_snapshot'))
        if type(tip) is str and len(tip) >= 14:
            self.sync_value.setText(ui_text('pages.verified_tip') + tip[:14] + '…')
        else:
            self.sync_value.setText(ui_text('pages.sync_unknown'))
        if identity:
            self.identity_value.setText(identity)
        elif coordinator is True:
            self.identity_value.setText(ui_text('pages.mining_coordinator'))
        elif coordinator is False:
            self.identity_value.setText(ui_text('pages.participant'))
        else:
            self.identity_value.setText('')
        self.identity_value.setVisible(bool(identity or coordinator is not None))
        self.controls_note.setText(
            ui_text('pages.manual_peer')
            if shared else ui_text('pages.isolated_zero_peer'))
