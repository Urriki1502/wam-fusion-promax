"""Fresh disposable REGTEST wallet coordinator with intent-verified signing.

Pinned WSP owns derivation/PSBT/signatures/coin reservations. Every operation
is serialized; encrypted reservation state is anchored before signed bytes or
network submission. No external seed import or production keys are accepted.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import threading
from .history_pages import GUI_HISTORY_LIMIT,HISTORY_OFFSET_MAX,complete_history
from .linux_anchor_witness import LinuxWitnessError
from wam_regtest import custody
from wam_regtest.core import verified_core_paths
from wam_regtest.telemetry import increment
from wam_regtest.wsp_live import LiveCoreReadOnlyCli, RealWspScanError, _pinned_source, _public_fixture_payment
from wam_regtest.vault import CheckpointVault, KeychainAnchor
from wam_regtest.wallet_read import HistoryRow, WalletReadSnapshot


class WalletSessionError(ValueError):
    pass


def _fee_code(error):
    """Public fee-policy token, or one generic refusal. Never a message string."""
    code = error.args[0] if error.args and type(error.args[0]) is str else ""
    if re.fullmatch(r"FEE_[A-Z0-9_]{3,64}", code):
        return code
    return "FEE_POLICY_UNVERIFIED"


class _SessionHistoryDenied(WalletSessionError):
    def __init__(self,code):super().__init__('WALLET_'+code)


@dataclass(frozen=True)
class PaymentReview:
    code: str
    atoms: int
    fee: int
    change_atoms: int
    input_count: int
    commitment: str
    # FEE-2 quote facts. None when prepare() was given an explicit test fee.
    rate_atoms_per_kvb: int | None = None
    rate_source: str | None = None
    rate_classification: str | None = None
    vsize: int | None = None
    total_debit: int | None = None
    available_before: int | None = None
    available_after: int | None = None
    overpay_atoms: int | None = None
    fee_quote: object | None = None


class WalletCoreCli(LiveCoreReadOnlyCli):
    """Write capabilities granted only to this disposable session coordinator."""
    def __init__(self,binary,datadir,*,on_trust_failure=None):
        super().__init__(binary,datadir)
        self._on_trust_failure=on_trust_failure

    def _failed(self,error):
        if self._on_trust_failure is None:raise error
        code=error.args[0] if len(error.args)==1 and type(error.args[0]) is str else None
        category='WALLET_CORE_UNVERIFIED'
        if code=='WSP_LIVE_RPC_AUTHENTICATION_DENIED':category='WALLET_CORE_AUTHENTICATION_DENIED'
        elif code=='WSP_LIVE_RPC_UNAVAILABLE':category='WALLET_CORE_UNAVAILABLE'
        elif code in ('WSP_LIVE_CHAIN_DENIED','WSP_LIVE_GENESIS_DENIED','WSP_LIVE_PEERS_DENIED',
                      'WSP_LIVE_VERSION_DENIED','WSP_LIVE_RPC_IDENTITY_DENIED'):
            category='WALLET_CORE_IDENTITY_DENIED'
        self._on_trust_failure()
        raise WalletSessionError(category) from None

    def _call(self,method,args):
        try:return super()._call(method,args)
        except RealWspScanError as error:self._failed(error)

    def attest(self):
        try:return super().attest()
        except RealWspScanError as error:self._failed(error)

    # Automatic-fee policy reads (FEE-1): read-only, attested, strict params.
    FEE_POLICY_READS = ("getnetworkinfo", "getmempoolinfo", "estimatesmartfee", "estimaterawfee")

    def _fee_policy_read(self, method, params):
        if type(params) is not list:
            raise WalletSessionError("WALLET_RPC_PARAMS_DENIED")
        target = lambda v: type(v) is int and 1 <= v <= 1008
        if method in ("getnetworkinfo", "getmempoolinfo"):
            valid = params == []
        elif method == "estimatesmartfee":
            valid = (len(params) == 2 and target(params[0])
                     and params[1] in ("conservative", "economical"))
        else:
            valid = len(params) == 1 and target(params[0])
        if not valid:
            raise WalletSessionError("WALLET_RPC_PARAMS_DENIED")
        self.attest()
        reply = self._call(method, [str(p) for p in params])
        if type(reply) is not dict:
            raise WalletSessionError("WALLET_FEE_POLICY_REPLY_DENIED")
        return reply

    @property
    def verified_network(self):
        """Chain name recorded by the last successful attest, or refuse."""
        network = getattr(self, "_verified_network", None)
        if network != "regtest":
            raise WalletSessionError("FEE_POLICY_NETWORK")
        return network

    def call(self, method, params=None):
        if method in self.FEE_POLICY_READS:
            return self._fee_policy_read(method, params)
        if method not in ("gettxout", "testmempoolaccept", "sendrawtransaction"):
            return super().call(method, params)
        self.attest()
        def raw(value):
            return (type(value) is str and 1 <= len(value) <= 800000
                    and len(value) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", value))
        if type(params) is not list:
            raise WalletSessionError("WALLET_RPC_PARAMS_DENIED")
        if method == "gettxout":
            if (len(params) != 3 or type(params[0]) is not str
                    or not re.fullmatch(r"[0-9a-f]{64}", params[0])
                    or type(params[1]) is not int or not 0 <= params[1] < 2**32
                    or params[2] is not True):
                raise WalletSessionError("WALLET_RPC_PARAMS_DENIED")
            return self._call(method, [params[0], str(params[1]), "true"])
        if method == "testmempoolaccept":
            if (len(params) != 1 or type(params[0]) is not list
                    or len(params[0]) != 1 or not raw(params[0][0])):
                raise WalletSessionError("WALLET_RPC_PARAMS_DENIED")
            reply = self._call(method, [json.dumps(params[0], separators=(",", ":"))])
            if (type(reply) is not list or len(reply) != 1
                    or type(reply[0]) is not dict or type(reply[0].get("allowed")) is not bool):
                raise WalletSessionError("WALLET_MEMPOOL_REPLY_DENIED")
            return reply
        if len(params) != 1 or not raw(params[0]):
            raise WalletSessionError("WALLET_RPC_PARAMS_DENIED")
        reply = self._call(method, params)
        if type(reply) is not str or not re.fullmatch(r"[0-9a-f]{64}", reply):
            raise WalletSessionError("WALLET_BROADCAST_UNCERTAIN")
        return reply


class WalletSession:
    @classmethod
    def open_owned(cls,owner,source,password,*,authorized=False,keychain=None,create=False,mining_address=None):
        from .managed_wallet_session import open_owned
        return open_owned(cls,owner,source,password,authorized=authorized,keychain=keychain,
                          create=create,mining_address=mining_address)

    def __init__(self, core_dir, datadir, source, ring, scanner, vault, password, mining_address,
                 *, core_cli=None, core_receipt=None):
        self.core_dir, self.datadir, self.source = core_dir, datadir, source
        self.ring, self.scanner, self.vault = ring, scanner, vault
        self._password = password
        self.mining_address = mining_address
        self._lock = threading.RLock()
        self._prepared = self._signed = self._review = self._tip = None
        self.faulted = False
        self._core_reauthentication_required=False
        self._disclosure_gate = None
        self.runtime = scanner.store.path
        self._core_cli = core_cli
        self._core_receipt = core_receipt
        self._rpc_client = None

    def _ensure_core_identity(self):
        """One-time verified Core path/receipt; subsequent reads avoid full rehash."""
        if self._core_cli is None or self._core_receipt is None:
            _, cli, receipt = verified_core_paths(self.core_dir)
            if receipt["platform"] != custody.platform_name():
                raise WalletSessionError("WALLET_MACOS_CORE_DENIED")
            self._core_cli, self._core_receipt = cli, receipt
        return self._core_cli, self._core_receipt

    @classmethod
    def create(cls, core_dir, datadir, source, password, mining_address, *, authorized, keychain=None):
        if authorized is not True:
            raise WalletSessionError("WALLET_DISPOSABLE_CONSENT_DENIED")
        _pinned_source(source)
        from wam_sp.keystore import Keyring
        from wam_sp.scanner import Scanner
        _, cli, receipt = verified_core_paths(core_dir)
        if receipt["platform"] != custody.platform_name():
            raise WalletSessionError("WALLET_MACOS_CORE_DENIED")
        rpc = WalletCoreCli(cli, datadir)
        rpc.attest()
        height = rpc.call("getblockcount")
        if height not in (102, 103):
            raise WalletSessionError("WALLET_FRESH_TEST_CHAIN_REQUIRED")
        folder = datadir / "wallet-vault"
        custody.create_directory(folder)
        ring = Keyring()
        scanner = None
        try:
            # Validate passphrase before any funding or signing.
            ring.backup(password)
            _public_fixture_payment(rpc, ring.accounts()[0], mining_address,
                                    funding_height=height-100, expected_before_height=height)
            scanner = Scanner(datadir / "wallet-runtime.sqlite", ring.accounts())
            scanner.sync(rpc)
            anchor = custody.anchor(secrets.token_hex(16), keychain)
            vault = CheckpointVault(folder, anchor, source)
            session = cls(core_dir,datadir,source,ring,scanner,vault,password,mining_address,
                          core_cli=cli,core_receipt=receipt)
            vault.save(ring,scanner,password)
            return session
        except Exception:
            if scanner is not None:
                scanner.close()
            ring.close()
            raise WalletSessionError("WALLET_CREATE_DENIED") from None

    @classmethod
    def from_backup(cls, core_dir, datadir, source, directory, name, password,
                    mining_address, *, authorized, keychain=None):
        """Recover test keys on a fresh real chain against the existing anchor.

        Keep all old irreversible reservations. Rotate a new testing epoch for
        fresh-chain funding rather than guessing that old signed locks expired.
        """
        if authorized is not True:
            raise WalletSessionError("WALLET_DISPOSABLE_CONSENT_DENIED")
        _pinned_source(source)
        storage=custody.storage()
        read,publish=storage.read,storage.publish
        from wam_sp.keystore import unseal
        from wam_sp.watcher import GENESIS
        ring=scanner=None
        stage="START"
        try:
            stage="READ"
            ciphertext=read(directory,name)
            payload=json.loads(unseal(ciphertext,password,b"recovery"))
            if (type(payload) is not dict or payload.get("disposable_regtest") is not True
                    or any(type(payload.get(k)) is not type(v) or payload.get(k)!=v for k,v in custody.envelope_profile().items()) or payload.get("network")!=GENESIS
                    or type(payload.get("generation")) is not int):
                raise WalletSessionError("WALLET_BACKUP_PROFILE_DENIED")
            stage="ANCHOR"
            anchor=custody.anchor(payload["wallet_id"],keychain)
            record=payload["generation"],sha256(ciphertext).hexdigest()
            if anchor.read()!=record:
                raise WalletSessionError("WALLET_BACKUP_STALE_OR_TAMPERED")
            stage="PUBLISH"
            folder=datadir/"wallet-vault"
            custody.create_directory(folder)
            publish(folder,CheckpointVault._filename(record[0]),ciphertext)
            vault=CheckpointVault(folder,anchor,source)
            stage="RESTORE"
            ring,scanner=vault.restore(datadir/"wallet-runtime.sqlite",password)
            stage="CORE"
            _,cli,receipt=verified_core_paths(core_dir)
            if receipt["platform"]!=custody.platform_name():
                raise WalletSessionError("WALLET_MACOS_CORE_DENIED")
            rpc=WalletCoreCli(cli,datadir)
            rpc.attest()
            stage="HEIGHT"
            height=rpc.call("getblockcount")
            if height not in (102,103):
                raise WalletSessionError("WALLET_FRESH_TEST_CHAIN_REQUIRED")
            stage="SYNC"
            scanner.sync(rpc)
            account=ring.rotate(height+1)
            scanner.reconfigure(ring.accounts())
            stage="FUND"
            _public_fixture_payment(rpc,account,mining_address,funding_height=height-100,
                                    expected_before_height=height)
            scanner.sync(rpc)
            session=cls(core_dir,datadir,source,ring,scanner,vault,password,mining_address,
                        core_cli=cli,core_receipt=receipt)
            stage="SAVE"
            session._save()
            return session
        except Exception as error:
            # Fixed public diagnostics only (stage token + public error code);
            # never message text, paths, payload or secrets.
            code=error.args[0] if (len(error.args)==1 and type(error.args[0]) is str
                                   and re.fullmatch(r"[A-Z0-9_]{3,80}",error.args[0])) else type(error).__name__
            if scanner is not None:
                scanner.close()
            if ring is not None:
                ring.close()
            denied=WalletSessionError("WALLET_CROSS_SESSION_RECOVERY_DENIED")
            denied.recovery_stage,denied.recovery_cause=stage,code
            raise denied from None

    @property
    def locked(self):
        return self.ring is None

    def _rpc(self):
        if self.locked or self.faulted:
            raise WalletSessionError("WALLET_LOCKED_OR_FAULTED")
        if getattr(self,'_managed_owner',None) is not None:
            from .managed_wallet_session import check_session
            check_session(self)
        if self.vault.anchor.read()!=self.vault._expected:
            self.faulted=True
            raise WalletSessionError("WALLET_STALE_SESSION_DENIED")
        try:
            _pinned_source(self.source)
            cli, receipt = self._ensure_core_identity()
            from .rpc_scope import identity
            if (self._core_receipt is not None and self._core_receipt.get("wamd_sha256")
                    != receipt.get("wamd_sha256")):
                self._fault_core()
                raise WalletSessionError("WALLET_CORE_IDENTITY_CHANGED")
            current = identity(self.datadir)
            if current is None or current.faulted:
                raise WalletSessionError("WALLET_CORE_OWNED_SCOPE_REQUIRED")
            if self._rpc_client is None:
                increment('wallet_session_rpc_client_create')
                self._rpc_client = WalletCoreCli(cli,self.datadir,on_trust_failure=self._fault_core)
                self._rpc_client.attest()
            return self._rpc_client
        except WalletSessionError:
            self._fault_core()
            raise
        except (ValueError,RuntimeError,OSError):
            self._fault_core()
            raise WalletSessionError('WALLET_CORE_UNVERIFIED') from None

    def _fault_core(self):
        # Latch only. Never release reservations, reset custody or replay an
        # uncertain operation. Lock/unlock remains explicit and authenticated.
        self.faulted=True
        self._core_reauthentication_required=True
        self._close_rpc()

    def _close_rpc(self):
        client,self._rpc_client=self._rpc_client,None
        if client is not None and getattr(client,'_transport',None) is not None:
            client._transport.close()

    def _save(self):
        try:
            if getattr(self,'_managed_owner',None) is not None:
                from .managed_wallet_session import check_session
                check_session(self)
                from .managed_wallet_checkpoint import durable_core_checkpoint
                durable_core_checkpoint(self._managed_owner,*self.scanner.store.tip())
            self.vault.save(self.ring, self.scanner, self._password)
        except Exception:
            self.faulted = True
            if getattr(self,'_managed_owner',None) is not None:
                # A failed publication may follow irreversible reservation
                # changes. Closing keys must never delete that unknown runtime.
                self._managed_checkpoint_uncertain=True
            raise WalletSessionError("WALLET_ANCHORED_SAVE_FAILED") from None

    def snapshot(self, history_offset=0):
        from wam_sp.wallet import Wallet
        with self._lock:
            if type(history_offset) is not int or not 0<=history_offset<=HISTORY_OFFSET_MAX:
                raise WalletSessionError("WALLET_HISTORY_INCONSISTENT")
            rpc = self._rpc()
            result = self.scanner.sync(rpc)
            self.scanner.assert_current()
            tip = self.scanner.store.tip()
            if tip != (rpc.call("getblockcount"),rpc.call("getbestblockhash")):
                raise WalletSessionError("WALLET_CHAIN_CHANGED_DENIED")
            if result.blocks or result.rollback:
                self._save()
            wallet = Wallet(self.scanner)
            try:
                with self.scanner.store.transaction():
                    if self.scanner.store.tip()!=tip:
                        raise WalletSessionError("WALLET_CHAIN_CHANGED_DENIED")
                    balance=wallet._balance(1)
                    utxos=len(self.scanner.coins())
                    declared=wallet.db.execute('SELECT count(*) FROM history').fetchone()[0]
                    receive_count=wallet.db.execute(
                        'SELECT count(*) FROM history WHERE credit>0').fetchone()[0]
                    if (type(receive_count) is not int or receive_count<0
                            or type(declared) is not int or receive_count>declared):
                        raise _SessionHistoryDenied('HISTORY_INCONSISTENT')
                    def page(limit,offset):
                        try:
                            return wallet._history(limit,offset)
                        except ValueError:
                            raise _SessionHistoryDenied('HISTORY_INCONSISTENT') from None
                    count,digest,rows=complete_history(
                        page,declared,tip[0],keep_tail=GUI_HISTORY_LIMIT,
                        skip_newest=history_offset,error=_SessionHistoryDenied)
                    from wam_regtest.managed_wallet_checkpoint import (
                        ManagedWalletError,reservation_fingerprint)
                    import sqlite3
                    try:
                        reservation_count,reservation_sha256,reservation_states=(
                            reservation_fingerprint(wallet.db.execute(
                                'SELECT txid,vout,token,state,created '
                                'FROM reservations ORDER BY txid,vout')))
                        # Same transaction as the fingerprint (W-TX-03b): rows per state.
                        state_counts=tuple(sorted(
                            (row[0],row[1]) for row in wallet.db.execute(
                                'SELECT state,count(*) FROM reservations GROUP BY state')))
                        from wam_regtest.domain.payment_state import state_counts_match
                        if not state_counts_match(state_counts,reservation_count,reservation_states):
                            raise ManagedWalletError('MANAGED_WALLET_RESERVATION_INCONSISTENT')
                    except (ManagedWalletError,sqlite3.Error):
                        raise WalletSessionError('WALLET_RESERVATION_INCONSISTENT') from None
            except _SessionHistoryDenied as error:
                raise WalletSessionError(error.args[0]) from None
            if (self.scanner.store.tip()!=tip
                    or tip!=(rpc.call("getblockcount"),rpc.call("getbestblockhash"))):
                raise WalletSessionError("WALLET_CHAIN_CHANGED_DENIED")
            history = tuple(HistoryRow(r["txid"],r["height"],r["confirmations"],r["credit"],r["debit"])
                            for r in reversed(rows))
            return WalletReadSnapshot(
                "regtest",tip[0],tip[1],self.ring.accounts()[-1].payment_code(),
                balance["confirmed_atoms"],utxos,history,
                self._ensure_core_identity()[1]["wamd_sha256"],
                signer_allowed=True,broadcast_allowed=True,
                history_count=count,history_sha256=digest,
                history_complete=history_offset==0 and count<=GUI_HISTORY_LIMIT,
                receive_count=receive_count,history_offset=history_offset,
                reservation_count=reservation_count,
                reservation_sha256=reservation_sha256,
                reservation_states=tuple(reservation_states),
                reservation_state_counts=state_counts,
            )

    def prepare(self, code, atoms, fee):
        """Explicit fee for tests and non-GUI probes. The production GUI uses prepare_auto.

        There is no fee field and no privileged override on the Fusion window,
        the owner window, or the operational window. Callers that still pass a
        fee are the existing unit tests (draft release, broadcast rejection,
        payment state, signed-intent recovery, signer bridge) and the non-GUI
        probes linux_headless, linux_headless_probe, reopen_probe and
        q05_checkpoint_scenario.
        """
        from wam_sp.wallet import Wallet, Intent, Signer
        with self._lock:
            if self._prepared is not None:
                raise WalletSessionError("WALLET_PAYMENT_ALREADY_PENDING")
            self.snapshot()
            intent = Intent(code, atoms)
            intent.validate()
            wallet = Wallet(self.scanner)
            proposal = wallet.propose((intent,),fee)
            try:
                prepared = Signer(self.ring).prepare(proposal)
            except Exception:
                # No review, signature, save or network action exists. Release
                # ONLY this new token, and only while every row is still draft.
                self._release_unreviewed_draft(wallet,proposal.token)
                raise WalletSessionError("WALLET_PREPARE_DENIED") from None
            try:
                self._save()  # Reservation is durable before exposing review.
            except Exception:
                # Publication outcome is unknown: the anchored checkpoint may
                # already contain this draft. Retain it conservatively.
                raise WalletSessionError("WALLET_PREPARE_DENIED") from None
            commitment = sha256(prepared.psbt).hexdigest()
            change = sum(c["atoms"] for c in proposal.coins)-atoms-fee
            review = PaymentReview(code,atoms,fee,change,len(proposal.coins),commitment)
            self._prepared,self._review,self._tip = prepared,review,self.scanner.store.tip()
            return review

    def prepare_auto(self, code, atoms):
        """Quote a network fee and reserve one monotone draft. Never signs.

        The fee starts from a one-input, two-output estimate and never falls.
        A measured need that is already covered is accepted, so a change/dust
        oscillation (155 then 112 then 155) stops on the higher fee. At most
        four rounds. Every abandoned draft is released only while it is still
        an unsaved, unreviewed draft. The accepted draft is saved exactly as
        prepare() saves: an uncertain save keeps the reservation.
        """
        from wam_sp.wallet import Wallet, Intent, Signer
        from .domain.fee_policy import (
            MAX_FEE_ATOMS, FeePolicyError, check_fee_limits, fee_for_vsize, quote)
        from .infrastructure.fee_rpc import read_policy_inputs
        from .infrastructure.tx_size import estimated_one_input_vsize, psbt_vsize
        with self._lock:
            if self._prepared is not None:
                raise WalletSessionError("WALLET_PAYMENT_ALREADY_PENDING")
            self.snapshot()
            intent = Intent(code, atoms)
            intent.validate()
            rpc = self._rpc()
            rpc.attest()
            try:
                quoted = quote(read_policy_inputs(rpc, rpc.verified_network))
            except FeePolicyError as error:
                raise WalletSessionError(_fee_code(error)) from None
            wallet = Wallet(self.scanner)
            fee = fee_for_vsize(estimated_one_input_vsize(), quoted.rate_atoms_per_kvb)
            accepted = None
            for _round in range(4):
                if type(fee) is not int or not 1 <= fee <= MAX_FEE_ATOMS:
                    raise WalletSessionError("FEE_ABSOLUTE_LIMIT")
                available_before = wallet.balance()["available_atoms"]
                proposal = wallet.propose((intent,), fee)
                try:
                    prepared = Signer(self.ring).prepare(proposal)
                    vsize = psbt_vsize(prepared.psbt)
                    need = fee_for_vsize(vsize, quoted.rate_atoms_per_kvb)
                except FeePolicyError as error:
                    self._abort_unreviewed(wallet, proposal.token)
                    raise WalletSessionError(_fee_code(error)) from None
                except Exception:
                    self._abort_unreviewed(wallet, proposal.token)
                    raise WalletSessionError("WALLET_PREPARE_DENIED") from None
                if need <= fee:
                    accepted = (proposal, prepared, vsize, need, fee, available_before)
                    break
                self._abort_unreviewed(wallet, proposal.token)
                fee = need
            if accepted is None:
                raise WalletSessionError("FEE_STRUCTURE_UNSTABLE")
            proposal, prepared, vsize, need, fee, available_before = accepted
            try:
                check_fee_limits(fee, atoms, vsize, quoted)
            except FeePolicyError as error:
                self._abort_unreviewed(wallet, proposal.token)
                raise WalletSessionError(_fee_code(error)) from None
            try:
                self._save()
            except Exception:
                # Publication may already contain this draft. Do not release it.
                raise WalletSessionError("WALLET_PREPARE_DENIED") from None
            change = sum(c["atoms"] for c in proposal.coins) - atoms - fee
            if type(available_before) is not int or change < 0:
                self.faulted = True
                raise WalletSessionError("WALLET_PREPARE_DENIED")
            available_after = wallet.balance()["available_atoms"]
            review = PaymentReview(
                code, atoms, fee, change, len(proposal.coins),
                sha256(prepared.psbt).hexdigest(),
                rate_atoms_per_kvb=quoted.rate_atoms_per_kvb,
                rate_source=quoted.source,
                rate_classification=quoted.estimator,
                vsize=vsize,
                total_debit=atoms + fee,
                available_before=available_before,
                available_after=available_after,
                overpay_atoms=fee - need,
                fee_quote=quoted)
            self._prepared, self._review, self._tip = prepared, review, self.scanner.store.tip()
            return review

    def _abort_unreviewed(self, wallet, token):
        """Release one never-saved draft, and stop the loop if that release fails."""
        self._release_unreviewed_draft(wallet, token)
        if self.faulted:
            raise WalletSessionError("WALLET_PREPARE_DENIED")

    def _require_fresh_fee_quote(self, rpc):
        """Before mark_signed: the approved rate must still cover the floor.

        An explicit-fee review has no quote and is unchanged. A stale quote
        does not sign, mark, or alter the fee. The user prepares again.
        """
        quote_ = self._review.fee_quote
        if quote_ is None:
            return
        from .domain.fee_policy import FeePolicyError, quote_still_valid
        from .infrastructure.fee_rpc import read_policy_inputs
        rpc.attest()
        try:
            fresh = read_policy_inputs(rpc, rpc.verified_network)
        except FeePolicyError as error:
            raise WalletSessionError(_fee_code(error)) from None
        if not quote_still_valid(quote_, fresh):
            raise WalletSessionError("FEE_QUOTE_STALE")

    def _release_unreviewed_draft(self, wallet, token):
        """Release a never-saved, never-reviewed draft; latch on any doubt.

        WSP release_draft rechecks every row of `token` inside one store
        transaction and refuses signed/uncertain/broadcast/manual rows. Rows of
        other tokens are never touched. Failure keeps the rows and faults.
        """
        if self.faulted:
            return
        try:
            wallet.release_draft(token)
        except Exception:
            self.faulted=True

    def _unchanged_inputs(self, rpc):
        from wam_sp.scanner import atoms
        if self.scanner.store.tip() != self._tip or rpc.call("getbestblockhash") != self._tip[1]:
            raise WalletSessionError("WALLET_REVIEW_CHAIN_CHANGED")
        for c in self._prepared.proposal.coins:
            actual = rpc.call("gettxout",[c["txid"],c["vout"],True])
            if (type(actual) is not dict or atoms(actual.get("value")) != c["atoms"]
                    or actual.get("scriptPubKey",{}).get("hex") != "5120"+c["public_key"]):
                raise WalletSessionError("WALLET_REVIEW_UTXO_CHANGED")

    def sign(self, commitment):
        from wam_sp.wallet import Signer, Wallet
        from wam_sp.psbt import PSBT
        try:
            with self._lock, self.vault.anchor.lease():
                if self._review is None or commitment != self._review.commitment or self._signed is not None:
                    raise WalletSessionError("WALLET_EXACT_INTENT_APPROVAL_REQUIRED")
                rpc=self._rpc()
                self._unchanged_inputs(rpc)
                proposal=self._prepared.proposal
                # A stale network quote refuses before the irreversible mark.
                # The approved fee is never edited. Explicit-fee reviews skip this.
                self._require_fresh_fee_quote(rpc)
                # Approving Sign makes this reservation irreversible BEFORE
                # entering native crypto. A crash/failure cannot restore a draft
                # that is cancelable, even if no signature was returned.
                Wallet(self.scanner).mark_signed(proposal.token)
                self._save()
                try:
                    signed=Signer(self.ring).sign(self._prepared,proposal.intents,self._review.fee)
                    raw=PSBT.decode(signed).finalize()  # Verify signatures and sender proof.
                    if self._review.vsize is not None:
                        from .infrastructure.tx_size import serialized_vsize
                        if serialized_vsize(raw) != self._review.vsize:
                            raise ValueError("FEE_SIGNED_VSIZE_MISMATCH")
                except Exception:
                    self.faulted=True
                    raise WalletSessionError("WALLET_SIGN_UNCERTAIN_LOCK_RETAINED") from None
                self._signed=signed
                return self._review
        except LinuxWitnessError:
            self.faulted=True;self._signed=None
            raise WalletSessionError("WALLET_ROOT_LEASE_UNCERTAIN_LOCK_RETAINED") from None

    def broadcast(self, commitment):
        from wam_sp.wallet import Wallet
        try:
            with self._lock, self.vault.anchor.lease():
                if self._review is None or self._signed is None or commitment != self._review.commitment:
                    raise WalletSessionError("WALLET_BROADCAST_APPROVAL_REQUIRED")
                rpc=self._rpc()
                self._unchanged_inputs(rpc)
                token=self._prepared.proposal.token
                # Read-only policy preflight while the durable state is still
                # 'signed'. Nothing has been handed to sendrawtransaction, so a
                # definitive rejection must not become network uncertainty.
                # The reservation stays signed/irreversible: no release, no
                # retry, and this session latches exactly as before.
                self._preflight_not_submitted(rpc)
                self._before_broadcast_submission()
                # Retain irreversible uncertainty in encrypted storage BEFORE RPC.
                # Every row of this token: that is the historical statement.
                from wam_regtest.domain.payment_state import (
                    mark_reservations_uncertain_before_submission)
                mark_reservations_uncertain_before_submission(
                    self.scanner.store.db, token, signed_rows_only=False)
                self._save()
                try:
                    txid=Wallet(self.scanner).broadcast(self._signed,token,rpc)
                    self._save()
                except Exception:
                    self.faulted=True
                    self._signed=None
                    raise WalletSessionError("WALLET_BROADCAST_UNCERTAIN_LOCK_RETAINED") from None
                self._prepared=self._signed=self._review=self._tip=None
                return txid
        except LinuxWitnessError:
            self.faulted=True;self._signed=None
            raise WalletSessionError("WALLET_ROOT_LEASE_UNCERTAIN_LOCK_RETAINED") from None

    def _preflight_not_submitted(self, rpc):
        """testmempoolaccept only; raises with the durable state still 'signed'.

        A verification/transport failure latches (Core trust is in doubt); a
        definitive rejection does not (see below).

        Any later rejection observed inside WSP's own broadcast, after the
        uncertain checkpoint, is deliberately NOT relabelled (conservative).
        """
        from wam_sp.psbt import PSBT
        try:
            raw=PSBT.decode(self._signed).finalize().hex()
            allowed=rpc.call("testmempoolaccept",[[raw]])[0]["allowed"]
        except Exception:
            self.faulted=True
            self._signed=None
            raise WalletSessionError("WALLET_BROADCAST_NOT_SUBMITTED_LOCK_RETAINED") from None
        if allowed is not True:
            # Definitive and fully consistent: nothing was submitted and the
            # durable state equals the runtime ('signed'). Do NOT latch a fault
            # (a faulted isolated profile cannot reopen to spend); forget only
            # the in-memory payment. The irreversible reservation remains and
            # is reported by TX-03 signed-intent status. Never released.
            self._prepared=self._signed=self._review=self._tip=None
            raise WalletSessionError("WALLET_BROADCAST_REJECTED_LOCK_RETAINED")

    def _before_broadcast_submission(self):
        """Hook: subclasses persist submission-intent evidence here."""

    def cancel(self):
        from wam_sp.wallet import Wallet
        with self._lock:
            self._rpc()
            if self._prepared is None or self._signed is not None:
                raise WalletSessionError("WALLET_ONLY_UNSIGNED_DRAFT_CAN_CANCEL")
            Wallet(self.scanner).release_draft(self._prepared.proposal.token)
            self._save()
            self._prepared=self._review=self._tip=None

    def disclose_record(self,txid,fields,password,*,approved=False):
        import hmac
        from .disclosure import LocalDisclosureGate,DisclosureError
        from wam_sp.wallet import Wallet
        with self._lock,self.vault.anchor.lease():
            self._rpc()
            if (approved is not True or type(password) is not bytes or not 12<=len(password)<=1024
                    or not hmac.compare_digest(password,self._password)):
                raise WalletSessionError("WALLET_DISCLOSURE_REAUTH_CONSENT_REQUIRED")
            self.snapshot()  # Facts belong to live validated local WSP history.
            if type(txid) is not str or not re.fullmatch('[0-9a-f]{64}',txid):
                raise WalletSessionError("WALLET_DISCLOSURE_LOCAL_RECORD_REQUIRED")
            with self.scanner.store.transaction():
                found=Wallet(self.scanner).db.execute(
                    'SELECT txid,height,credit,debit FROM history WHERE txid=?',(txid,)).fetchall()
            if len(found)!=1:
                raise WalletSessionError("WALLET_DISCLOSURE_LOCAL_RECORD_REQUIRED")
            row=found[0]
            fact={'txid':row[0],'block_height':row[1],
                  'credit_atoms':row[2],'debit_atoms':row[3]}
            if self._disclosure_gate is None:
                self._disclosure_gate=LocalDisclosureGate(self.vault.anchor.wallet_id)
            anchor=self.vault.anchor.read()
            ticket=self._disclosure_gate.issue(fact,fields,anchor,approved=True,authenticated=True)
            return self._disclosure_gate.release(ticket,fact,self.vault.anchor.read())

    def network_diagnostics(self):
        from .network_policy import diagnostics
        with self._lock:
            return diagnostics(self._rpc())

    def mine(self):
        with self._lock:
            rpc=self._rpc()
            result=rpc._call("generatetoaddress",["1",self.mining_address])
            if type(result) is not list or len(result)!=1:
                raise WalletSessionError("WALLET_TEST_MINING_DENIED")
            return self.snapshot()

    def backup(self, directory, name):
        with self._lock:
            self.snapshot()
            self._save()
            return self.vault.backup(directory,name)

    def lock(self):
        with self._lock:
            if getattr(self,'_managed_owner',None) is not None:
                from .managed_wallet_session import close_session
                return close_session(self)
            gate,self._disclosure_gate=self._disclosure_gate,None
            unlocked=not self.locked
            failed=False
            try:
                # Every close is attempted even if an earlier one raises.
                try:
                    self._close_rpc()
                except Exception:
                    failed=True
                if gate is not None:
                    try:
                        gate.close()
                    except Exception:
                        failed=True
                if unlocked:
                    try:
                        self.scanner.close()
                    except Exception:
                        failed=True
                    try:
                        self.ring.close()
                    except Exception:
                        failed=True
            finally:
                # Drop this session's signing/password references regardless.
                # (Python cannot guarantee zeroization of other copies.)
                self._rpc_client=None
                self.scanner=self.ring=None
                self._password=None
                self._prepared=self._signed=self._review=self._tip=None
            if failed:
                # Cleanup outcome unknown: latch, keep the runtime for review,
                # and refuse unlock in this process. Reservations untouched.
                self.faulted=True
                self._lock_cleanup_uncertain=True
                raise WalletSessionError("WALLET_LOCK_CLEANUP_UNCERTAIN") from None
            if not unlocked:
                return
            # This path was created only by this disposable session. No user DB.
            self.runtime.unlink(missing_ok=True)

    def unlock(self, password, reauthenticate_core=False):
        with self._lock:
            if getattr(self,'_managed_owner',None) is not None:
                raise WalletSessionError('WALLET_MANAGED_REOPEN_REQUIRED')
            if getattr(self,'_lock_cleanup_uncertain',False):
                raise WalletSessionError('WALLET_LOCK_CLEANUP_UNCERTAIN')
            if not self.locked:
                raise WalletSessionError("WALLET_ALREADY_UNLOCKED")
            if self._core_reauthentication_required and reauthenticate_core is not True:
                raise WalletSessionError('WALLET_CORE_REAUTHENTICATION_REQUIRED')
            ring,scanner=self.vault.restore(self.runtime,password)
            self.ring,self.scanner,self._password=ring,scanner,password
            try:
                if self._core_reauthentication_required:
                    from .rpc_scope import reauthenticate_owned
                    reauthenticate_owned(self.datadir,authorized=True)
                self.faulted=False
                self._core_reauthentication_required=False
                return self.snapshot()
            except Exception:
                self.faulted=True
                self.lock()
                raise WalletSessionError("WALLET_RECOVERY_LIVE_SYNC_DENIED") from None

    def recover_backup(self, directory, name, password, reauthenticate_core=False):
        if getattr(self,'_managed_owner',None) is not None:
            raise WalletSessionError('WALLET_MANAGED_EXPLICIT_RECOVERY_REQUIRED')
        storage=custody.storage()
        read,publish=storage.read,storage.publish
        with self._lock:
            if not self.locked:
                raise WalletSessionError("WALLET_LOCK_BEFORE_RECOVERY")
            record=self.vault.anchor.read()
            ciphertext=read(directory,name)
            if record is None or sha256(ciphertext).hexdigest()!=record[1]:
                raise WalletSessionError("WALLET_BACKUP_STALE_OR_TAMPERED")
            folder=self.datadir/("recovered-vault-"+secrets.token_hex(8))
            custody.create_directory(folder)
            publish(folder,self.vault._filename(record[0]),ciphertext)
            self.vault=CheckpointVault(folder,self.vault.anchor,self.source)
            return self.unlock(password,reauthenticate_core)

    def close(self):
        self.lock()
