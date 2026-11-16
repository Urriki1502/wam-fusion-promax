"""R0 English catalog snapshot at f8926405 (F-14).

gui_errors user-visible messages and the bip39_locale 'en' table, byte for
byte. A later catalog move must keep these English strings identical.
"""
import unittest

from wam_regtest.bip39_locale import _STRINGS
from wam_regtest.gui_errors import _MESSAGES, error_text

ENGLISH_GUI_ERRORS = {'FEE_ABSOLUTE_LIMIT': 'The fee exceeds 0.01 WAM. Nothing was saved or signed.',
 'FEE_BELOW_NETWORK_FLOOR': 'The fee is below the network minimum. Nothing was saved or signed.',
 'FEE_DISPROPORTIONATE': 'The fee is too large for this payment amount. Nothing was saved or signed.',
 'FEE_EXCEEDS_AMOUNT': 'The fee is larger than the payment amount. Nothing was saved or signed.',
 'FEE_EXPLICIT_PREPARE_DENIED': 'A manually chosen fee is not accepted. Nothing was prepared or signed.',
 'FEE_POLICY_UNVERIFIED': 'The network fee could not be verified. Nothing was prepared or signed.',
 'FEE_QUOTE_STALE': 'The network fee changed after this review. Nothing was signed and the fee was not changed. Cancel the unsigned draft and prepare the payment again.',
 'FEE_STRUCTURE_UNSTABLE': 'The fee for this payment could not be settled. Nothing was saved or signed. Unsigned drafts from this attempt were released.',
 'Q06_RECONCILIATION_NOT_NEEDED': 'The active custody session is healthy. Refresh the chain before '
                                  'requesting recovery.',
 'Q06_SHARED_RECONCILIATION_DENIED': 'Shared-chain reconciliation was refused. Native checkpoints, '
                                     'signed evidence and reservations are preserved. Verify the '
                                     'original profile, password and chain; do not remove runtime '
                                     'files.',
 'RBF_SIGNALLING_MISSING': 'This payment is missing explicit BIP125 replaceability. Nothing was signed.',
 'SHARED_CONFIRMED_PEER_REQUIRED': 'The configured Core peer is disconnected or not yet verified. '
                                   'Reconnect and verify the shared chain; signed and pending '
                                   'payments remain preserved.',
 'SHARED_SINGLE_COORDINATOR_REQUIRED': 'Only the explicitly designated Shared REGTEST coordinator '
                                       'may mine. This participant only receives and validates '
                                       'blocks.',
 'WALLET_BACKUP_DIRECTORY_DENIED': 'Backup destination was refused. Choose a new private folder '
                                   'owned by this account, without links or inherited access.',
 'WALLET_BACKUP_STALE_OR_TAMPERED': 'This backup does not match the latest anchored checkpoint. '
                                    'Choose the current unmodified backup; do not reset the '
                                    'anchor.',
 'WALLET_BROADCAST_NOT_SUBMITTED_LOCK_RETAINED': 'Pre-submission verification could not complete; '
                                                 'the transaction was not sent by this wallet. '
                                                 'Input reservations stay signed and locked. '
                                                 'Nothing is retried or released automatically.',
 'WALLET_BROADCAST_REJECTED_LOCK_RETAINED': 'The local node rejected the signed transaction before '
                                            'submission; it was not sent. Input reservations stay '
                                            'signed and locked. Nothing is retried or released '
                                            'automatically.',
 'WALLET_BROADCAST_UNCERTAIN_LOCK_RETAINED': 'Broadcast result is uncertain. The node may have '
                                             'accepted the transaction. Do not retry '
                                             'automatically; reservations remain locked.',
 'WALLET_CHANGE_BELOW_DUST': "This payment would leave change below the network's minimum output (330 atoms). Adjust the amount.",
 'WALLET_CORE_AUTHENTICATION_DENIED': 'Local Core authentication failed. Balances are hidden and '
                                      'sensitive operations are stopped. Verify the authorized '
                                      'local credentials, then explicitly reauthenticate. Wallet '
                                      'state and reservations are retained.',
 'WALLET_CORE_IDENTITY_DENIED': 'Local Core identity or private configuration changed. Balances '
                                'are hidden and sensitive operations are stopped. Verify the '
                                'original REGTEST node before authenticated reopening; do not '
                                'reset custody.',
 'WALLET_CORE_REAUTHENTICATION_REQUIRED': 'Explicit approval to reauthenticate the original '
                                          'REGTEST Core is required after wallet passphrase and '
                                          'custody verification. No automatic retry or external '
                                          'node adoption is allowed.',
 'WALLET_CORE_UNAVAILABLE': 'The verified local Core is unavailable. Balances are hidden and '
                            'sensitive operations are stopped. Check the authorized local node; no '
                            'request is retried automatically.',
 'WALLET_CORE_UNVERIFIED': 'Core verification failed. Balances are hidden and sensitive operations '
                           'are stopped. Explicitly verify the original REGTEST environment before '
                           'authenticated reopening. Reservations remain protected.',
 'WALLET_EXECUTOR_BUSY_OR_CLOSED': 'A wallet operation is in progress or the session is closed. '
                                   'Wait for completion or explicitly reopen the wallet.',
 'WALLET_EXECUTOR_OPERATION_STILL_PENDING': 'The operation is still running. Wait for completion; '
                                            'signing or broadcast will not be repeated '
                                            'automatically.',
 'WALLET_INPUT_AMOUNT_INVALID': 'Amount not accepted. Enter 0.00000330 to 22000000 WAM, using a '
                                'decimal point and at most 8 decimal places.',
 'WALLET_INPUT_FEE_INVALID': 'Fee not accepted. Enter 0.00000001 to 0.01000000 WAM, using a '
                             'decimal point and at most 8 decimal places.',
 'WALLET_INPUT_FUNDS_UNAVAILABLE': 'Not enough available confirmed funds in one privacy cluster '
                                   'for the amount and fee. Coins still reserved, in the mempool, '
                                   'or waiting for confirmation stay unavailable; locks are not '
                                   'released.',
 'WALLET_INPUT_RECIPIENT_INVALID': 'Recipient not accepted. Use the complete REGTEST '
                                   'silent-payment code (wamrtsp1…). Ordinary Core addresses, '
                                   'other networks and invalid checksums are not supported.',
 'WALLET_LOCKED_OR_FAULTED': 'Wallet is locked or faulted. Balances are hidden and sensitive '
                             'operations are unavailable; reservations remain protected.',
 'WALLET_LOCK_CLEANUP_UNCERTAIN': 'Lock could not close every wallet resource. Keys were dropped '
                                  'from this session and it is stopped; local wallet data and '
                                  'reservations are preserved. Restart the application before '
                                  'reopening; do not remove files.',
 'WALLET_MANAGED_OPEN_DENIED': 'The wallet could not be authenticated or opened safely. Check the '
                               'passphrase and current recovery state; existing data is preserved.',
 'WALLET_MANAGED_RUNTIME_PRESERVED': 'Wallet keys are closed and recovery data is preserved. '
                                     'Authenticated recovery is required before reopening; do not '
                                     'remove files.',
 'WALLET_NATIVE_CHECKPOINT_VERIFICATION_REQUIRED': 'This original wallet has a native checkpoint. '
                                                   'Use Enable sending and explicitly approve '
                                                   'custody verification before refreshing its '
                                                   'history. Reservations remain protected; no '
                                                   'wallet data should be reset.',
 'WALLET_OPERATION_DENIED_STATE_RETAINED': 'Operation could not complete safely. Wallet state and '
                                           'reservations are retained. Verify the live chain and '
                                           'latest checkpoint; do not reset custody.',
 'WALLET_PAYMENT_ALREADY_PENDING': 'A payment review is already active. Finish that review or '
                                   'cancel its unsigned draft before preparing another.',
 'WALLET_RECOVERY_REFUSED': 'Recovery was refused: backup authentication, freshness or custody '
                            'could not be verified. The wallet remains locked; use the latest '
                            'same-platform backup.',
 'WALLET_REVIEW_CHAIN_CHANGED': 'The chain changed after review. Recheck the live chain. Only an '
                                'unsigned draft may be canceled; signed reservations stay locked.',
 'WALLET_REVIEW_UTXO_CHANGED': 'A reviewed input is no longer available. Signing or broadcast was '
                               'refused. Reservations remain protected.',
 'WALLET_ROOT_LEASE_UNCERTAIN_LOCK_RETAINED': 'The independent custody lease was lost. Operations '
                                              'are stopped and reservations retained. Do not reset '
                                              'the witness or retry automatically.',
 'WALLET_SIGN_UNCERTAIN_LOCK_RETAINED': 'Signing did not complete safely. Input reservations are '
                                        'irreversible. Do not retry automatically or release the '
                                        'locks.',
 'WALLET_STALE_SESSION_DENIED': 'Wallet session is stale. Sensitive operations are stopped and '
                                'reservations retained. Use the latest anchored backup; do not '
                                'reset or replace the anchor.',
 'WALLET_SYNC_UNVERIFIED': 'Live REGTEST synchronization could not be verified. Balances are '
                           'hidden. Verify the local node and use Sync again; do not reset '
                           'custody.',
 'WALLET_UNLOCK_REFUSED': 'Could not unlock: passphrase, encrypted snapshot or custody '
                          'verification failed. The wallet remains locked. Check the passphrase '
                          'and latest backup; do not reset custody.'}

ENGLISH_LOCALE = {'app_name': 'WAM Fusion',
 'back_up_later': 'Back up later',
 'back_up_now': 'Confirm backup',
 'backup_back': 'Back',
 'backup_flow_kicker': 'Create your wallet / Backup verification · REGTEST',
 'backup_privacy_note': 'Verification happens locally.',
 'backup_step_progress': 'STEP {step} OF {total}',
 'backup_subtitle': 'Write down all 12 words in order. They are shown only once.',
 'backup_title': 'Back up your wallet',
 'backup_warning': 'Never share these recovery words, including with support. Use disposable REGTEST words only. Never use mainnet words or real funds.',
 'cancel': 'Cancel',
 'close_to_lock': 'Closing without verifying will lock the wallet. You can complete backup on '
                  'reopen.',
 'confirm_subtitle': 'Enter the requested words from your 12-word recovery phrase.',
 'confirm_title': 'Confirm your backup',
 'continue': 'Continue',
 'leave_backup_confirm': 'Leave and lock wallet',
 'leave_backup_message': 'These 12 words are shown only once and will not be displayed again. If '
                         'you leave now, this wallet locks and reopening it requires words from '
                         'this phrase. Leave only if you have already written all 12 words down in '
                         'order.',
 'leave_backup_stay': 'Stay',
 'leave_backup_title': 'Leave without finishing backup?',
 'locked_subtitle': 'Backup is unfinished and this REGTEST wallet is locked. Reopen it and enter the requested words from your written backup. The phrase will not be shown again.',
 'locked_title': 'Wallet locked',
 'ok': 'OK',
 'phrase_grid_title': 'Write these 12 words down in order',
 'recovery_cancel': 'Cancel',
 'recovery_clear_words': 'Clear all',
 'recovery_invalid': 'Recovery phrase is not a valid 12-word BIP39 phrase. Check the words and try '
                     'again.',
 'recovery_paste_words': 'Paste 12 words',
 'recovery_readonly_notice': 'This check only reads history on this REGTEST chain. It does not restore spending access or unlock signing. An empty new chain has no earlier transactions.',
 'recovery_verify_kicker': 'WAM Fusion / Independent Recovery · REGTEST',
 'recovery_verify_phrase': 'Check recovery words',
 'recovery_verify_subtitle': 'Enter all 12 disposable REGTEST recovery words in order. Never enter mainnet words.',
 'recovery_verify_title': 'Check your recovery words',
 'recovery_word_count': '{entered}/12 words entered',
 'recovery_word_position': 'Word #{position}',
 'regtest_preview': 'REGTEST PREVIEW',
 'success_subtitle': 'The requested words match your written backup. Keep all 12 words private. This check does not prove recovery on another device.',
 'success_title': 'Backup confirmed',
 'verify': 'Verify',
 'verify_backup': 'Verify backup',
 'verify_error': 'One or more words do not match. Check your written backup and enter the newly requested words.',
 'verify_prompt': 'Enter word #{position}',
 'verify_subtitle': 'Enter the requested words to confirm you saved the phrase.',
 'verify_title': 'Verify your backup',
 'verify_unavailable': 'Your words were not checked. Enter the newly requested words within 2 minutes. If this keeps happening, leave and lock the wallet, then reopen it to verify your backup.',
 'word_label': 'Word',
 'written_checkbox': 'I have written these 12 words down in the correct order'}


class EnglishCatalog(unittest.TestCase):
    """F-14. English UI literals stay byte-identical across a catalog move."""

    def test_gui_error_messages_match_the_english_snapshot(self):
        self.assertEqual(_MESSAGES, ENGLISH_GUI_ERRORS)
        for code, text in ENGLISH_GUI_ERRORS.items():
            self.assertEqual(error_text(code), text)
            self.assertIsInstance(text, str)
            self.assertTrue(text)

    def test_bip39_locale_en_table_matches_the_english_snapshot(self):
        self.assertEqual(_STRINGS['en'], ENGLISH_LOCALE)
        for key, text in ENGLISH_LOCALE.items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(text, str)
            self.assertTrue(key)
            self.assertTrue(text)


if __name__ == '__main__':
    unittest.main()
