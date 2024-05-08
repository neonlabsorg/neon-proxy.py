import unittest

from common.solana.commit_level import SolCommit, SolRpcCommit


class TestSolCommit(unittest.TestCase):

    def test_level_property(self):
        self.assertEqual(SolCommit.Processed.to_level(), 0)
        self.assertEqual(SolCommit.Finalized.to_level(), 3)
        self.assertEqual(SolCommit.Earliest.to_level(), 4)

    def test_from_raw_with_sol_commit(self):
        self.assertIs(SolCommit.from_raw(SolCommit.Processed), SolCommit.Processed)
        self.assertIs(SolCommit.from_raw(SolCommit.Safe), SolCommit.Safe)

    def test_from_raw_with_int(self):
        self.assertEqual(SolCommit.from_raw(0), SolCommit.Processed)
        self.assertEqual(SolCommit.from_raw(1), SolCommit.Confirmed)
        self.assertEqual(SolCommit.from_raw(4), SolCommit.Earliest)

    def test_from_raw_with_str(self):
        self.assertEqual(SolCommit.from_raw("cOnfirmed"), SolCommit.Confirmed)
        self.assertEqual(SolCommit.from_raw("FinaLized"), SolCommit.Finalized)
        self.assertEqual(SolCommit.from_raw("SafE"), SolCommit.Safe)

    def test_to_level_with_sol_commit(self):
        self.assertEqual(SolCommit.Finalized.to_level(), 3)
        self.assertEqual(SolCommit.Earliest.to_level(), 4)

    def test_to_rpc_commit_with_sol_commit(self):
        self.assertEqual(SolCommit.Processed.to_rpc_commit(), SolRpcCommit.Processed)
        self.assertEqual(SolCommit.Safe.to_rpc_commit(), SolRpcCommit.Confirmed)
        self.assertEqual(SolCommit.Finalized.to_rpc_commit(), SolRpcCommit.Finalized)

    def test_to_rpc_commit_with_str(self):
        self.assertEqual(SolCommit.from_raw("confirmed").to_rpc_commit(), SolRpcCommit.Confirmed)
        self.assertEqual(SolCommit.from_raw("safe").to_rpc_commit(), SolRpcCommit.Confirmed)
        self.assertEqual(SolCommit.from_raw("finalized").to_rpc_commit(), SolRpcCommit.Finalized)

    def test_from_raw_with_invalid_value(self):
        with self.assertRaises(ValueError):
            SolCommit.from_raw("invalid-value")
        with self.assertRaises(ValueError):
            SolCommit.from_raw(" Safe ")
        with self.assertRaises(ValueError):
            SolCommit.from_raw(10)
        with self.assertRaises(ValueError):
            SolCommit.from_raw(None)  # noqa
        with self.assertRaises(ValueError):
            SolCommit.from_raw([])  # noqa
        with self.assertRaises(ValueError):
            SolCommit.from_raw({})  # noqa


if __name__ == "__main__":
    unittest.main()
