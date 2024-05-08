from common.ethereum.transaction import EthTx
from common.neon.transaction_model import NeonTxModel

import unittest


class TestNeonTx(unittest.TestCase):
    raw_tx = "0xF86B80850BA43B7400825208947917bc33eea648809c285607579c9919fb864f8f8703BAF82D03A0008025A0067940651530790861714b2e8fd8b080361d1ada048189000c07a66848afde46A069b041db7c29dbcc6becf42017ca7ac086b12bd53ec8ee494596f790fb6a0a69"

    def setUp(self):
        self.maxDiff = None

    def test_neon_tx(self):
        neon_tx = EthTx.from_raw(self.raw_tx)
        self.assertEqual(neon_tx.nonce, 0)
        self.assertEqual(neon_tx.gas_price, 50000000000)
        self.assertEqual(neon_tx.gas_limit, 21000)
        self.assertEqual(neon_tx.value, 1050000000000000)
        self.assertEqual(neon_tx.chain_id, 1)
        self.assertEqual(neon_tx.to_address.hex(), "7917bc33eea648809c285607579c9919fb864f8f")
        self.assertEqual(neon_tx.s, 0x69B041DB7C29DBCC6BECF42017CA7AC086B12BD53EC8EE494596F790FB6A0A69)
        self.assertEqual(neon_tx.r, 0x067940651530790861714B2E8FD8B080361D1ADA048189000C07A66848AFDE46)
        self.assertEqual(neon_tx.v, 0x25)
        self.assertEqual(neon_tx.call_data, bytes())
        self.assertIsNone(neon_tx.contract)
        self.assertEqual(neon_tx.from_address.hex(), "8d900bfa2353548a4631be870f99939575551b60")
        self.assertEqual(neon_tx.neon_tx_hash.hex(), "14a298c1eea89f42285948b7d51eeac2876ca7406c9784b9b90dd3591d156d64")

    def test_neon_tx_model(self):
        neon_tx_info = NeonTxModel.from_raw(self.raw_tx)
        self.assertEqual(neon_tx_info.nonce, 0)
        self.assertEqual(neon_tx_info.gas_price, 50000000000)
        self.assertEqual(neon_tx_info.gas_limit, 21000)
        self.assertEqual(neon_tx_info.value, 1050000000000000)
        self.assertEqual(neon_tx_info.chain_id, 1)
        self.assertEqual(neon_tx_info.to_address.to_string(), "0x7917bc33eea648809c285607579c9919fb864f8f")
        self.assertTrue(neon_tx_info.has_chain_id)
        self.assertEqual(neon_tx_info.r, 0x067940651530790861714B2E8FD8B080361D1ADA048189000C07A66848AFDE46)
        self.assertEqual(neon_tx_info.s, 0x69B041DB7C29DBCC6BECF42017CA7AC086B12BD53EC8EE494596F790FB6A0A69)
        self.assertEqual(neon_tx_info.v, 0x25)
        self.assertTrue(neon_tx_info.call_data.is_empty)
        self.assertTrue(neon_tx_info.contract.is_empty)
        self.assertEqual(neon_tx_info.from_address.to_string(), "0x8d900bfa2353548a4631be870f99939575551b60")
        self.assertEqual(
            neon_tx_info.neon_tx_hash.to_string(), "0x14a298c1eea89f42285948b7d51eeac2876ca7406c9784b9b90dd3591d156d64"
        )
        self.assertIsNone(neon_tx_info.error)
        self.assertTrue(neon_tx_info.is_valid)

        neon_tx_json = {
            "tx_type": "0x0",
            "nonce": "0x0",
            "gas_price": "0xba43b7400",
            "gas_limit": "0x5208",
            "value": "0x3baf82d03a000",
            "chain_id": "0x1",
            "to_address": "0x7917bC33EeA648809c285607579c9919FB864F8F",
            "neon_tx_hash": "0x14a298c1eea89f42285948b7d51eeac2876ca7406c9784b9b90dd3591d156d64",
            "r": "0x67940651530790861714b2e8fd8b080361d1ada048189000c07a66848afde46",
            "s": "0x69b041db7c29dbcc6becf42017ca7ac086b12bd53ec8ee494596f790fb6a0a69",
            "v": "0x25",
            "call_data": "0x",
            "contract": None,
            "from_address": "0x8d900bfA2353548a4631bE870f99939575551B60",
            "error": None,
        }
        for key, value in neon_tx_info.to_dict().items():
            if value is None:
                self.assertIsNone(neon_tx_json[key], key)
            else:
                self.assertEqual(value, neon_tx_json[key], key)

        neon_tx_str = (
            "NeonTxModel("
            "tx_type=0, "
            "neon_tx_hash=0x14a298c1eea89f42285948b7d51eeac2876ca7406c9784b9b90dd3591d156d64, "
            "from_address=0x8d900bfA2353548a4631bE870f99939575551B60, "
            "to_address=0x7917bC33EeA648809c285607579c9919FB864F8F, "
            "contract=None, "
            "nonce=0, "
            "gas_price=50000000000, "
            "gas_limit=21000, "
            "value=1050000000000000, "
            "call_data=0x, "
            "v=37, "
            "r=2928110023290089484253548116616605334358013891920862960710110507440823852614, "
            "s=47804268715460771705062403734867221257027780543816644424145154262186536340073, "
            "chain_id=1)"
        )
        self.assertEqual(neon_tx_info.to_string(), neon_tx_str)


if __name__ == "__main__":
    unittest.main()
