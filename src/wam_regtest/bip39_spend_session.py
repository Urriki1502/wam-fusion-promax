"""Q06 REGTEST BIP39 spend-session integration with the existing Q05 engine.

Reuse WalletSession's intent/UTXO verified Prepare->Sign->Broadcast engine.
Only native authenticated scanner generations are authoritative. No mainnet,
no seed migration and no automatic uncertain-reservation repair.

This module is not a release/owner-acceptance grant. Activation requires an
explicit owned-Core caller and must be separately tested on frozen macOS.
"""
import os
from pathlib import Path
import secrets
import stat
import sys

from . import custody
from .domain.payment_evidence import PaymentEvidenceStore
from .foundation import diagnostics
from .managed_wallet_checkpoint import _owned, _runtime
from .managed_wallet_session import RuntimeGuard
from .wallet_session import (
    WalletSession, WalletSessionError, WalletCoreCli, _verify_session_preflight,
    _psbt_replaceable,
)
from .bip39_seed_vault import (
    _owned_password, _owner_binding, open_owned_seed_container,
)
from .bip39_native_checkpoint import (
    _directory, _native, _scanner_anchor_record, _require_confirmed_descendant,
    advance_owned_candidate, publish_owned_candidate, read_owned_candidate,
)
from .bip39_scanner_checkpoint import (
    decode_candidate, require_irreversible_preserved,
)
from wam_sp.scanner import Scanner


class Q06SpendSessionError(ValueError):
    """Public bounded error. Never interpolate secrets, paths or RPC details."""


def _reservation_map(scanner):
    rows = scanner.store.db.execute(
        "SELECT txid,vout,token,state,created FROM reservations").fetchall()
    if len(rows) != len({(v[0], v[1]) for v in rows}):
        raise Q06SpendSessionError("Q06_SPEND_RESERVATION_DUPLICATE")
    return {(v[0], v[1]): (v[2], v[3], v[4]) for v in rows}


def _remove_known_scanner_lock(path):
    lock = path.with_name(path.name + ".scan.lock")
    if lock.exists() or lock.is_symlink():
        info = lock.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or lock.is_symlink()
                or (sys.platform != "win32"
                    and (info.st_uid != os.geteuid()
                         or stat.S_IMODE(info.st_mode) != 0o600))):
            raise Q06SpendSessionError("Q06_SPEND_SCAN_LOCK_UNCERTAIN")
        lock.unlink()


class _Q06NativeScannerVault:
    """Persist only BIP39 scanner state, never Q05's 32-byte Keyring format."""

    def __init__(self, owner, seed_folder, source, password, keychain):
        seed_id, folder = _directory(owner, seed_folder)
        _, self.anchor = _native(folder, seed_id, source, keychain)
        self.directory = folder
        self._expected = _scanner_anchor_record(self.anchor.read())
        self.owner, self.seed_folder, self.source = owner, seed_folder, source
        self.password, self.keychain = password, keychain

    def save(self, keys, scanner, password):
        if (password != self.password
                or keys.accounts() != scanner.accounts
                or self.anchor.read() != self._expected):
            raise Q06SpendSessionError("Q06_SPEND_STALE_ANCHOR_OR_ACCOUNT")
        receipt = advance_owned_candidate(
            self.owner, self.seed_folder, scanner, self.source, password,
            authorized=True, keychain=self.keychain,
            anchor_override=self.anchor)
        updated = _scanner_anchor_record(self.anchor.read())
        if (updated[0] != self._expected[0] + 1
                or receipt["generation"] != updated[0]
                or receipt["signer_allowed"] is not False):
            raise Q06SpendSessionError("Q06_SPEND_CHECKPOINT_AUTHORITY_DENIED")
        self._expected = updated


class Q06OwnedSpendSession(WalletSession):
    """Use Q05's transaction methods but Q06's independent native checkpoint."""

    def __init__(self, owner, source, keys, scanner, guard, vault, password):
        super().__init__(
            owner.core, owner.directory, source, keys, scanner, vault, password,
            mining_address=None, core_cli=owner.cli, core_receipt=owner.receipt)
        self._q06_owner = owner
        self._q06_guard = guard
        self._q06_uncertain = False
        self._q06_pending_confirm = None
        self._evidence = PaymentEvidenceStore(owner.directory, custody)

    @property
    def payment_review(self):
        return self._review

    @property
    def payment_signed(self):
        return self._signed is not None

    @property
    def pending_confirm_txid(self):
        return self._q06_pending_confirm

    def _rpc(self):
        if self._q06_uncertain:
            raise WalletSessionError("Q06_SPEND_UNCERTAIN_LOCK_RETAINED")
        _owned(self._q06_owner)
        self._q06_guard.check()
        return super()._rpc()

    def _save(self):
        try:
            _owned(self._q06_owner)
            self._q06_guard.check()
            self.vault.save(self.ring, self.scanner, self._password)
        except Exception:
            # An irreversible action may precede the failed publication.
            # Never discard this SQLite, recreate the Core, or unlock drafts.
            self._q06_uncertain = self.faulted = True
            raise WalletSessionError("Q06_SPEND_ANCHORED_SAVE_DENIED") from None

    def _evidence_store(self):
        """The composed store. An object.__new__ fixture gets one on first use."""
        store = getattr(self, '_evidence', None)
        if store is None:
            store = PaymentEvidenceStore(self._q06_owner.directory, custody)
            self._evidence = store
        return store

    def _retain_signed_payment(self, stage, *, signed=None, review=None, token=None, txid=None,
                               legacy_unrecorded=False):
        """Create-only encrypted evidence; NEVER a replay/release authority.

        Native scanner reservations remain authoritative even if this
        supplemental evidence is absent. Existing vault formats are unchanged.
        When to write, and the preserved-no-retry latch, stay here.
        """
        try:
            _owned(self._q06_owner)
            self._q06_guard.check()
            signed = self._signed if signed is None else signed
            review = self._review if review is None else review
            token = self._prepared.proposal.token if token is None else token
            self._evidence_store().write(
                stage, signed=signed, review=review, token=token, txid=txid,
                password=self._password,
                owner_binding=lambda: _owner_binding(self._q06_owner),
                account_id=lambda: self.ring.public_metadata()['account_id'],
                legacy_unrecorded=legacy_unrecorded)
        except Exception:
            self.faulted = self._q06_uncertain = True
            raise Q06SpendSessionError('Q06_PAYMENT_EVIDENCE_PRESERVED_NO_RETRY') from None

    def sign(self, commitment):
        result = super().sign(commitment)
        self._retain_signed_payment('signed')
        return result

    def broadcast(self, commitment):
        """Retain the exact owned REGTEST txid for one explicitly approved block."""
        if (self._review is None or self._signed is None
                or commitment != self._review.commitment):
            raise WalletSessionError('WALLET_BROADCAST_APPROVAL_REQUIRED')
        signed, review, token = self._signed, self._review, self._prepared.proposal.token
        txid = super().broadcast(commitment)
        self._retain_signed_payment('broadcast', signed=signed, review=review,
                                    token=token, txid=txid)
        self._q06_pending_confirm = txid
        return txid

    # ---- TX-03 signed-intent recovery (Stage A read-only, Stage B resume) ----
    # Authority stays with the native-anchored reservation rows; the encrypted
    # create-only evidence only supplies the EXACT previously signed bytes.
    # Nothing here re-signs, retries automatically, or releases a reservation.
    # There is deliberately no abandon/release path (TX-03 Stage C is blocked
    # on a security proof: the native checkpoint forbids losing these rows).

    def _read_payment_evidence(self, token, stage):
        return self._evidence_store().read(
            token, stage, password=self._password,
            owner_binding=lambda: _owner_binding(self._q06_owner),
            account_id=lambda: self.ring.public_metadata()['account_id'])

    def _intent_status_unlocked(self):
        from wam_sp.psbt import PSBT
        snapshot = self.snapshot()  # Original owner, native generation, live tip.
        rpc = self._rpc()
        with self.scanner.store.transaction():
            rows = self.scanner.store.db.execute(
                "SELECT txid,vout,token,state FROM reservations "
                "WHERE state IN ('signed','uncertain') ORDER BY token,txid,vout").fetchall()
        groups = {}
        for txid, vout, token, state in rows:
            groups.setdefault(token, []).append(((txid, vout), state))
        items = []
        eligible = {}
        for token, members in groups.items():
            states = {state for _, state in members}
            outpoints = {coin for coin, _ in members}
            item = {'token': token, 'state': states.pop() if len(states) == 1 else 'mixed',
                    'input_count': len(outpoints), 'txid': None, 'evidence': 'missing',
                    'observation': None}
            try:
                body = self._read_payment_evidence(token, 'signed')
            except Exception:
                body, item['evidence'] = None, 'invalid'
            # The per-item branches run FIRST and unchanged; tokens decided
            # here never reach observation (OBS-01a Contract I scope).
            if item['state'] == 'mixed':
                item['classification'] = 'OPERATOR_REVIEW_MIXED_STATE'
            elif body is None:
                item['classification'] = ('OPERATOR_REVIEW_EVIDENCE_INVALID'
                                          if item['evidence'] == 'invalid'
                                          else 'OPERATOR_REVIEW_SIGNED_EVIDENCE_MISSING')
            else:
                item['evidence'] = 'verified'
                item['txid'] = body['txid']
                item.update(recipient=body['recipient'], atoms=body['atoms'], fee=body['fee'])
                if set(PSBT.decode(bytes.fromhex(body['signed_psbt'])).tx.inputs) != outpoints:
                    item['classification'] = 'OPERATOR_REVIEW_EVIDENCE_INPUT_MISMATCH'
                else:
                    eligible[token] = (body['txid'], outpoints, item)
            items.append(item)
        if eligible:
            # One read-only observation for every remaining token. A
            # whole-acquisition UNKNOWN refuses the status call; transport
            # exceptions from the RPC propagate unchanged.
            from .tx_observation import ObservationRefused, observe_intents
            try:
                observations = observe_intents(
                    self.scanner, rpc,
                    {txid: outpoints for txid, outpoints, _item in eligible.values()})
            except ObservationRefused:
                raise Q06SpendSessionError('Q06_INTENT_STATUS_UNVERIFIED') from None
            for token, (txid, _outpoints, item) in eligible.items():
                observed = observations[txid]
                item['observation'] = {
                    'state': observed['state'], 'h': observed['height'],
                    'height': observed['height'],
                    'block_hash': observed['block_hash'],
                    'conflict_heights': observed['conflict_heights'],
                    'depth': observed['depth'], 'core_ibd': observed['core_ibd']}
                state = observed['state']
                if state == 'CONFIRMED':
                    item['classification'] = 'CONFIRMED_IN_VERIFIED_HISTORY'
                elif state == 'IN_MEMPOOL':
                    item['classification'] = 'IN_MEMPOOL_AWAITING_CONFIRMATION'
                elif state in ('BLOCK_CONFLICTED', 'INPUT_UNAVAILABLE'):
                    # Spent by another (or a reorged) transaction: never resumable.
                    item['classification'] = 'OPERATOR_REVIEW_INPUT_SPENT_OR_CONFLICTED'
                elif state == 'NOT_SEEN_LOCALLY':
                    item['classification'] = (
                        'SIGNED_NOT_SUBMITTED_RESUMABLE' if item['state'] == 'signed'
                        else 'UNCERTAIN_NOT_OBSERVED_RESUMABLE')
                else:  # UNKNOWN: CONTRADICTION or INPUTS_UNVERIFIED
                    item['classification'] = 'OPERATOR_REVIEW_OBSERVATION_CONTRADICTION'
        return {'status': 'Q06_SIGNED_INTENT_STATUS', 'height': snapshot.height,
                'tip': snapshot.tip, 'intents': items, 'write_attempted': False,
                'automatic_resume': False, 'abandon_available': False,
                'mainnet_allowed': False}

    def signed_intent_status(self):
        """Stage A: read-only reconstruction of every irreversible intent."""
        with self._lock:
            if self._q06_uncertain or self.faulted:
                raise Q06SpendSessionError('Q06_INTENT_STATUS_SESSION_FAULTED')
            return self._intent_status_unlocked()

    def resume_signed_intent(self, token, txid, *, approved=False):
        """Stage B: owner-approved submission of the EXACT previously signed tx.

        Eligible only for a verified-evidence intent whose inputs are still
        unspent and which is neither confirmed nor in the mempool. Both 'signed'
        and 'uncertain' intents require BIP125 replaceability signalling and run
        the same exact-byte read-only preflight before submission; a 'signed'
        intent also takes its durable 'uncertain' write-ahead before broadcast.
        No re-signing or fee rewrite.
        """
        import re
        from types import SimpleNamespace
        from wam_sp.wallet import Wallet
        if (approved is not True or type(token) is not str or type(txid) is not str
                or re.fullmatch('[0-9a-f]{32}', token) is None
                or re.fullmatch('[0-9a-f]{64}', txid) is None):
            raise Q06SpendSessionError('Q06_RESUME_EXPLICIT_APPROVAL_REQUIRED')
        with self._lock, self.vault.anchor.lease():
            if (self._q06_uncertain or self.faulted
                    or any(v is not None for v in (self._prepared, self._signed,
                                                   self._review, self._q06_pending_confirm))):
                raise Q06SpendSessionError('Q06_RESUME_SESSION_NOT_IDLE')
            item = next((i for i in self._intent_status_unlocked()['intents']
                         if i['token'] == token), None)
            if (item is None or item['txid'] != txid or item['classification'] not in
                    ('SIGNED_NOT_SUBMITTED_RESUMABLE', 'UNCERTAIN_NOT_OBSERVED_RESUMABLE')):
                raise Q06SpendSessionError('Q06_RESUME_NOT_ELIGIBLE')
            body = self._read_payment_evidence(token, 'signed')
            signed = bytes.fromhex(body['signed_psbt'])
            fee_basis = body.get('fee_basis')
            fee_quote = None
            legacy_unrecorded = False
            if isinstance(fee_basis, dict):
                kind = fee_basis.get('kind')
                if kind == 'quote':
                    from .domain.fee_policy import FeeQuote
                    quote_data = fee_basis['quote']
                    fee_quote = FeeQuote(
                        network=quote_data['network'],
                        rate_atoms_per_kvb=quote_data['rate_atoms_per_kvb'],
                        floor_atoms_per_kvb=quote_data['floor_atoms_per_kvb'],
                        source=quote_data['source'],
                        estimator=quote_data['estimator'],
                        reasons=tuple(quote_data['reasons']),
                        inputs_digest=quote_data['inputs_digest'],
                    )
                elif kind == 'legacy-unrecorded':
                    legacy_unrecorded = True
            # Evidence-only display/provenance: NEVER set rate_atoms_per_kvb
            # or vsize on the resumed review (would arm preflight rate/vsize checks).
            review = SimpleNamespace(commitment=body['commitment'], code=body['recipient'],
                                     atoms=body['atoms'], fee=body['fee'],
                                     fee_quote=fee_quote)
            # RBF-RESUME-01: no resubmission without explicit BIP125 signalling
            # on the stored PSBT. This local check precedes any preflight or
            # submission; a missing signal keeps the durable state, locks,
            # bytes and provenance exactly as they are and sends nothing.
            if not _psbt_replaceable(signed):
                raise WalletSessionError('RBF_SIGNALLING_MISSING')
            rpc = self._rpc()
            try:
                # REC-2 (SPEC §5 bullet 1): the SAME exact-byte preflight
                # contract for a 'signed' AND an 'uncertain' intent, before
                # any submission attempt.
                rejection = _verify_session_preflight(rpc, signed, review)
            except Exception:
                # Malformed acceptance, bad identity, untrusted Core or a
                # transport failure latches (Core trust is in doubt) exactly
                # as on the signed path. Nothing was submitted in this
                # attempt; the original uncertainty is never relabelled.
                self.faulted = True
                raise WalletSessionError(
                    'WALLET_BROADCAST_NOT_SUBMITTED_LOCK_RETAINED') from None
            if rejection is not None:
                # Definitive typed policy rejection before this attempt's send:
                # no new session fault, no new uncertainty latch, no send, no
                # re-sign and no fee rewrite. The ORIGINAL state, locks, bytes
                # and provenance are kept; historical uncertainty is NOT
                # cleared by a clean refusal.
                error = WalletSessionError("WALLET_BROADCAST_REJECTED_LOCK_RETAINED")
                error.preflight_rejection = rejection  # fixed diagnostic token only
                raise error
            if item['state'] == 'signed':
                existing = self._read_payment_evidence(token, 'uncertain')
                if existing is None:
                    self._retain_signed_payment('uncertain', signed=signed, review=review,
                                                token=token, txid=txid,
                                                legacy_unrecorded=legacy_unrecorded)
                elif existing['txid'] != txid:
                    self.faulted = self._q06_uncertain = True
                    raise Q06SpendSessionError('Q06_PAYMENT_EVIDENCE_PRESERVED_NO_RETRY')
                from wam_regtest.domain.payment_state import (
                    mark_reservations_uncertain_before_submission)
                # Only rows still 'signed': that is the historical resume statement.
                mark_reservations_uncertain_before_submission(
                    self.scanner.store.db, token, signed_rows_only=True)
                self._save()
            try:
                actual = Wallet(self.scanner).broadcast(signed, token, rpc)
                self._save()
            except Exception:
                self.faulted = self._q06_uncertain = True
                raise WalletSessionError('WALLET_BROADCAST_UNCERTAIN_LOCK_RETAINED') from None
            self._retain_signed_payment('broadcast', signed=signed, review=review,
                                        token=token, txid=actual,
                                        legacy_unrecorded=legacy_unrecorded)
            self._q06_pending_confirm = actual
            return {'status': 'Q06_SIGNED_INTENT_RESUBMITTED', 'txid': actual,
                    'resigned': False, 'automatic': False, 'mainnet_allowed': False}

    def _recover_pending_broadcast(self):
        """Read-only: re-identify this profile's one unconfirmed broadcast after reopen.

        A broadcast TXID was kept only in memory, so after a restart the wallet
        showed no TXID and the exact-TXID confirmation was unavailable although
        the transaction was still in Core's mempool (Jeeves J-TX-01/J-TX-02).
        Authority stays with the native-anchored 'broadcast' reservation rows
        and the create-only encrypted 'broadcast' evidence of the same token.
        This only restores the existing confirm_pending precondition. It never
        re-signs, resubmits, releases a reservation or mines. Any ambiguity
        (several tokens, unreadable or mismatched evidence, already confirmed,
        absent from the mempool) leaves nothing pending.
        """
        import re
        from wam_sp.psbt import PSBT
        with self._lock:
            if (self._q06_uncertain or self.faulted
                    or self._q06_pending_confirm is not None):
                return None
            with self.scanner.store.transaction():
                rows = self.scanner.store.db.execute(
                    "SELECT txid,vout,token FROM reservations "
                    "WHERE state='broadcast' ORDER BY token,txid,vout").fetchall()
                confirmed = {r[0] for r in self.scanner.store.db.execute(
                    'SELECT txid FROM history WHERE height>0')}
            groups = {}
            for txid, vout, token in rows:
                groups.setdefault(token, set()).add((txid, vout))
            pending = []
            for token, outpoints in groups.items():
                try:
                    body = self._read_payment_evidence(token, 'broadcast')
                    inputs = (None if body is None else
                              set(PSBT.decode(bytes.fromhex(body['signed_psbt'])).tx.inputs))
                except Exception:
                    return None
                if body is None or inputs != outpoints:
                    return None
                if body['txid'] not in confirmed:
                    pending.append((body['txid'], outpoints))
            if len(pending) != 1:
                return None
            # Contract I for the one candidate. A whole-acquisition UNKNOWN
            # raises (inside open_owned_spend_session this runs before
            # transferred=True, so the open's cleanup runs); transport
            # exceptions propagate unchanged. Any other state is the
            # existing absent-from-the-mempool None path.
            from .tx_observation import ObservationRefused, observe_intents
            try:
                observed = observe_intents(
                    self.scanner, self._rpc(), {pending[0][0]: pending[0][1]})
            except ObservationRefused:
                raise Q06SpendSessionError(
                    'Q06_PENDING_BROADCAST_UNVERIFIED') from None
            if observed[pending[0][0]]['state'] != 'IN_MEMPOOL':
                return None
            self._q06_pending_confirm = pending[0][0]
            return pending[0][0]

    def _before_broadcast_submission(self):
        # Called only after the read-only preflight accepted, and BEFORE the
        # durable 'uncertain' checkpoint and sendrawtransaction. A rejected
        # transaction therefore never receives 'uncertain' evidence.
        self._retain_signed_payment('uncertain')

    def _recovered_unsigned_token(self):
        """Only a singleton all-draft native ledger can be canceled sans review.

        Never reconstruct an approval, signature or transaction from this row.
        Even an unrelated irreversible row makes this narrow recovery refuse.
        """
        import re
        if any(value is not None for value in
               (self._prepared, self._signed, self._review, self._q06_pending_confirm)):
            return None
        with self.scanner.store.transaction():
            groups = self.scanner.store.db.execute(
                'SELECT DISTINCT token,state FROM reservations LIMIT 2').fetchall()
        if (len(groups) != 1 or groups[0][1] != 'draft'
                or type(groups[0][0]) is not str
                or re.fullmatch('[0-9a-f]{32}', groups[0][0]) is None):
            return None
        return groups[0][0]

    def recovered_unsigned_cancel_available(self):
        """Presentation only; explicit Cancel rechecks under the native lease."""
        with self._lock:
            self._rpc()
            self.scanner.assert_current()
            return self._recovered_unsigned_token() is not None

    def cancel(self):
        with self._lock:
            if self._prepared is not None:
                return super().cancel()  # Existing exact active-draft contract.
            with self.vault.anchor.lease():
                self._rpc()  # Original owner, native generation and Core scope.
                self.snapshot()  # Refuse an unauthenticated/stale chain view.
                token = self._recovered_unsigned_token()
                if token is None:
                    raise WalletSessionError('WALLET_ONLY_UNSIGNED_DRAFT_CAN_CANCEL')
                from wam_sp.wallet import Wallet
                Wallet(self.scanner).release_draft(token)  # Rechecks every row.
                self._save()  # Existing native CAS; failure latches/preserves.
                return {'recovered_unsigned_cancelled': True,
                        'signer_allowed': False, 'broadcast_allowed': False}

    def confirm_pending(self, txid):
        """Mine ONE block only for this session's just-broadcast REGTEST tx.

        Not a general miner. If Core write outcome is ambiguous, fail closed:
        neither the GUI nor the backend may retry automatically.
        """
        import re
        from .wsp_live import public_regtest_mining_address
        with self._lock:
            if (type(txid) is not str or re.fullmatch(r"[0-9a-f]{64}", txid) is None
                    or self._q06_pending_confirm != txid
                    or self._q06_uncertain or self.faulted):
                raise Q06SpendSessionError("Q06_CONFIRM_EXACT_PENDING_TX_REQUIRED")
            rpc = self._rpc()  # Original owner, attested Core and native guard.
            try:
                rpc.attest()
                before = rpc.call("getblockcount")
                if type(before) is not int or before < 0 or before >= 1_000_000:
                    raise Q06SpendSessionError("Q06_CONFIRM_CHAIN_HEIGHT_DENIED")
                rpc._call("generatetoaddress", ["1", public_regtest_mining_address(self.source)])
                _owned(self._q06_owner)
                after = rpc.call("getblockcount")
                if after != before + 1:
                    raise Q06SpendSessionError("Q06_CONFIRM_BLOCK_UNVERIFIED")
                snapshot = self.snapshot()
                if (snapshot.height != after
                        or not any(row.txid == txid and row.confirmations > 0
                                   for row in snapshot.history)):
                    raise Q06SpendSessionError("Q06_CONFIRM_TX_UNVERIFIED")
                self._q06_pending_confirm = None
                return {"status": "Q06_REGTEST_EXACT_SEND_CONFIRMED",
                        "height": after, "txid": txid,
                        "mainnet_allowed": False}
            except Exception as error:
                diagnostics.record('CONFIRM_PENDING', error)
                self._q06_uncertain = self.faulted = True
                raise Q06SpendSessionError("Q06_CONFIRM_UNCERTAIN_NO_RETRY") from None

    def inspect_confirmed(self, txid):
        """Bounded read-only lookup across ALL native-anchored local history.

        A missing record does NOT mean broadcast failed. Mempool membership is
        observed read-only via getrawmempool and never implied as confirmation.
        No RPC mutations, key derivation, signing or reservation-state
        modification are allowed.
        """
        import re
        with self._lock:
            if (type(txid) is not str or re.fullmatch(r"[0-9a-f]{64}", txid) is None
                    or self._q06_uncertain or self.faulted):
                raise Q06SpendSessionError("Q06_INSPECT_EXACT_TXID_REQUIRED")
            snapshot = self.snapshot()  # Full history integrity and Core tip.
            # Contract G via the one observation policy. A whole-acquisition
            # UNKNOWN (including a contradictory history row) refuses the
            # inspection; transport exceptions propagate unchanged.
            from .tx_observation import ObservationRefused, observe_generic
            try:
                observed = observe_generic(self.scanner, self._rpc(), txid)
            except ObservationRefused:
                raise Q06SpendSessionError(
                    "Q06_INSPECT_HISTORY_UNVERIFIED") from None
            found = observed['state'] == 'CONFIRMED'
            return {
                "status": ("Q06_CONFIRMED_IN_VERIFIED_HISTORY" if found
                           else "Q06_TX_NOT_IN_CONFIRMED_HISTORY"),
                "txid": txid, "height": snapshot.height,
                "tx_height": observed['height'] if found else None,
                "tx_block_hash": observed['block_hash'] if found else None,
                "in_mempool": observed['state'] == 'IN_MEMPOOL',
                "complete_anchored_history": True,
                "write_attempted": False,
                "signer_allowed": False, "broadcast_allowed": False,
                "mainnet_allowed": False,
            }

    def lock(self):
        if self.locked:
            return
        failed = False
        try:
            # Each secret/resource close is independent: a transport or
            # SQLite failure must not prevent best-effort key invalidation.
            for close in (self._close_rpc, self.scanner.close, self.ring.close):
                try:
                    close()
                except Exception:
                    failed = True
            if failed:
                raise Q06SpendSessionError("Q06_SPEND_RUNTIME_UNCERTAIN")
            if (self._q06_uncertain or self.faulted
                    or self.vault.anchor.read() != self.vault._expected):
                raise Q06SpendSessionError("Q06_SPEND_RUNTIME_UNCERTAIN")
            self._q06_guard.check()
            _remove_known_scanner_lock(self.runtime)
            self._q06_guard.remove_owned()
        except Exception:
            failed = True
        finally:
            # Secrets close even if the guarded SQLite must remain for review.
            try:
                self._q06_guard.close()
            except Exception:
                failed = True
            finally:
                self.ring = self.scanner = self._password = None
                self._prepared = self._signed = self._review = self._tip = None
        if failed:
            self._q06_uncertain = self.faulted = True
            raise Q06SpendSessionError("Q06_SPEND_RUNTIME_PRESERVED") from None

    def backup(self, *args, **kwargs):
        raise Q06SpendSessionError("Q06_SPEND_Q05_BACKUP_FORMAT_DENIED")

    def recover_backup(self, *args, **kwargs):
        raise Q06SpendSessionError("Q06_SPEND_Q05_BACKUP_FORMAT_DENIED")

    def unlock(self, *args, **kwargs):
        raise Q06SpendSessionError("Q06_SPEND_EXPLICIT_OWNED_REOPEN_REQUIRED")


def open_owned_spend_session(owner, seed_folder, source, password, *,
                             authorized=False, keychain=None):
    """Authenticate owned Core + seed + anchored scanner before any signer.

    A new profile may publish its first checkpoint only when its native
    namespace has no scanner history. An existing checkpoint MUST be restored
    into a fresh protected runtime and resynced with the same-chain Core.
    """
    _owned_password(owner, source, password, authorized)
    _owned(owner)
    keys = scanner = guard = rpc = None
    transferred = False
    phase = 'SEED_AUTH'
    try:
        keys = open_owned_seed_container(
            owner, seed_folder, source, password,
            authorized=authorized, keychain=keychain)
        phase = 'RUNTIME_PREFLIGHT'
        # Any leftover prior native runtime is ambiguous after a crash.
        # Deny implicit replay/recovery rather than creating a parallel signer.
        import re
        prior = [p for p in owner.directory.iterdir() if re.fullmatch(
                r"wallet-runtime-recovery-[0-9a-f]{16}\.sqlite"
                r"(?:-journal|-wal|-shm|\.scan\.lock)?", p.name)]
        if prior:
            from .bip39_reconciliation import require_reconciled_runtimes,RUNTIME
            bases=[p for p in prior if RUNTIME.fullmatch(p.name)]
            expected={p.name for p in bases}|{p.name+'.scan.lock' for p in bases}
            if not bases or any(p.name not in expected for p in prior):
                raise Q06SpendSessionError("Q06_SPEND_PRIOR_RUNTIME_UNCERTAIN")
            require_reconciled_runtimes(owner,seed_folder,source,password,bases,keychain=keychain)
        name = "wallet-runtime-recovery-" + secrets.token_hex(8) + ".sqlite"
        target = _runtime(owner, name)
        if sys.platform == "win32":
            from .windows_private_storage import create_managed_runtime
            create_managed_runtime(target)
        phase = 'SCANNER_CREATE'
        scanner = Scanner(target, keys.accounts())
        phase = 'SCANNER_GUARD'
        guard = RuntimeGuard(target)
        phase = 'RPC_ATTEST'
        rpc = WalletCoreCli(owner.cli, owner.directory)
        rpc.attest()
        phase = 'CHECKPOINT_DIRECTORY'
        seed_id, folder = _directory(owner, seed_folder)
        if folder.exists() or folder.is_symlink():
            phase = 'CHECKPOINT_RESTORE'
            previous, receipt = read_owned_candidate(
                owner, seed_folder, source, password,
                authorized=authorized, keychain=keychain,
                allow_descendant=True)
            before = (receipt["height"], receipt["tip"])
            _require_confirmed_descendant(owner, before, (
                rpc.call("getblockcount"), rpc.call("getbestblockhash")))
            decoded = decode_candidate(
                keys, scanner, previous, password.decode("utf-8"),
                owner_binding=_owner_binding(owner))
            if ((decoded["claimed_height"], decoded["claimed_tip"]) != before
                    or decoded["account_id"] != keys.public_metadata()["account_id"]):
                raise Q06SpendSessionError("Q06_SPEND_RESTORE_PROFILE_DENIED")
            locked = _reservation_map(scanner)
            scanner.sync(rpc)
            scanner.assert_current()
            require_irreversible_preserved(locked, _reservation_map(scanner))
            _require_confirmed_descendant(owner, before, scanner.store.tip())
            if scanner.store.tip() != (
                    rpc.call("getblockcount"), rpc.call("getbestblockhash")):
                raise Q06SpendSessionError("Q06_SPEND_CORE_CHANGED")
            # Resync to descendant was never an authorization to drop locks.
            if scanner.store.tip() != before:
                advance_owned_candidate(
                    owner, seed_folder, scanner, source, password,
                    authorized=True, keychain=keychain)
        else:
            phase = 'INITIAL_SCANNER_SYNC'
            scanner.sync(rpc)
            scanner.assert_current()
            if scanner.store.tip() != (
                    rpc.call("getblockcount"), rpc.call("getbestblockhash")):
                raise Q06SpendSessionError("Q06_SPEND_CORE_CHANGED")
            phase = 'INITIAL_NATIVE_PUBLISH'
            publish_owned_candidate(
                owner, seed_folder, scanner, source, password,
                authorized=True, keychain=keychain)
        phase = 'NATIVE_VAULT_OPEN'
        vault = _Q06NativeScannerVault(
            owner, seed_folder, source, password, keychain)
        guard.check()
        _owned(owner)
        phase = 'SESSION_CONSTRUCTION'
        session = Q06OwnedSpendSession(
            owner, source, keys, scanner, guard, vault, password)
        # Require both the source and Q05 transaction engine to re-observe
        # the exact native checkpoint before passing this to any GUI.
        phase = 'OWNED_SESSION_RPC'
        session._rpc()
        phase = 'PENDING_BROADCAST_RECOVERY'
        session._recover_pending_broadcast()
        transferred = True
        return session
    except Exception as error:
        # Fixed tokens only: no exception payloads, keys or paths (F-05).
        diagnostics.record('SPEND_OPEN', error, open_stage=phase)
        diagnostics.q06_spend_marker('MACOS_Q06_SPEND_OPEN_DENIED_STAGE=' + phase)
        denied = Q06SpendSessionError("Q06_SPEND_OPEN_DENIED")
        denied.open_stage = phase  # fixed public stage token only
        raise denied from None
    finally:
        if rpc is not None and getattr(rpc, "_transport", None) is not None:
            rpc._transport.close()
        if not transferred:
            if scanner is not None:
                scanner.close()
            if keys is not None:
                keys.close()
            if guard is not None:
                guard.close()
            # Uncertain runtime/anchor is intentionally never auto-removed.
