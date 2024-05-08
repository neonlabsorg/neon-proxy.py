import unittest
from common.ethereum.commit_level import EthCommit


class TestEthCommit(unittest.TestCase):
    def test_from_raw_valid(self):
        self.assertIs(EthCommit.from_raw("pEndiNg"), EthCommit.Pending)
        self.assertIs(EthCommit.from_raw("LaTest"), EthCommit.Latest)
        self.assertIs(EthCommit.from_raw("SafE"), EthCommit.Safe)
        self.assertIs(EthCommit.from_raw("FiNalizeD"), EthCommit.Finalized)

    def test_from_raw_invalid(self):
        with self.assertRaises(ValueError):
            EthCommit.from_raw("invalid_commit_level")
        with self.assertRaises(ValueError):
            EthCommit.from_raw(10)  # noqa


if __name__ == "__main__":
    unittest.main()
