"""Public error categories must never expose arbitrary exceptions or authorize work."""
import unittest
from wam_regtest.gui_errors import operation_error,error_text,INPUT_ERRORS,raw_cause

class ErrorPrivacy(unittest.TestCase):
 def test_arbitrary_exception_text_is_not_displayed_or_even_formatted(self):
  class Hostile(RuntimeError):
   def __str__(self):raise AssertionError('external exception formatted')
  self.assertEqual(operation_error('prepare',Hostile('rpcpassword=private-test-marker')),'WALLET_OPERATION_DENIED_STATE_RETAINED')
  self.assertNotIn('private-test-marker',error_text('rpcpassword=private-test-marker'))
 def test_valid_prefix_with_private_suffix_is_not_a_public_error(self):
  code=operation_error('prepare',ValueError('INSUFFICIENT_SINGLE_CLUSTER_FUNDS rpcpassword=private-test-marker'))
  self.assertNotIn(code,INPUT_ERRORS)
  self.assertNotIn('private-test-marker',error_text(code))
 def test_native_validation_category_is_scoped_to_prepare(self):
  code=operation_error('prepare',ValueError('INSUFFICIENT_SINGLE_CLUSTER_FUNDS'))
  self.assertIn(code,INPUT_ERRORS)
  self.assertNotIn(operation_error('broadcast',ValueError('INSUFFICIENT_SINGLE_CLUSTER_FUNDS')),INPUT_ERRORS)
 def test_unknown_long_or_non_string_codes_have_constant_fallback(self):
  fallback=error_text('UNKNOWN')
  for code in (None,1,object(),'x'*10000,'/private/user/wallet.sqlite'):
   self.assertEqual(error_text(code),fallback)
 def test_shared_port_in_use_project_as_the_specific_gui_code(self):
  # PM-105 r2: reserve_ports maps a port EADDRINUSE to the single code-shaped
  # SHARED_PORT_IN_USE. The owner thread wraps args[0] into a
  # WalletExecutorError before the GUI projects it, so the GUI's _last_error_code
  # and _last_error_raw are the specific SHARED_PORT_IN_USE, never the generic
  # fallback. The exact-type gate leaves the raw backend value as its class name.
  from wam_regtest.shared_regtest import SharedRegtestError
  from wam_regtest.wallet_executor import WalletExecutorError
  failure = SharedRegtestError('SHARED_PORT_IN_USE')
  self.assertEqual(raw_cause(failure), 'SharedRegtestError')
  wrapped = WalletExecutorError('SHARED_PORT_IN_USE')   # what the GUI receives
  self.assertEqual(raw_cause(wrapped), 'SHARED_PORT_IN_USE')   # _last_error_raw
  self.assertEqual(operation_error('open', wrapped), 'SHARED_PORT_IN_USE')  # _last_error_code
  shown = error_text('SHARED_PORT_IN_USE')
  self.assertIn('Network port is in use', shown)
  self.assertNotIn('SHARED_PORT_IN_USE', shown)

if __name__=='__main__':unittest.main()
