import unittest
from typing import Final

from common.neon.cu_cost_packed import CuCostPktData
from common.neon.neon_program import NeonProg
from common.solana.cb_program import SolCbProg


def check_unpack(self: unittest.TestCase, base_gas: int, base_iter_cnt: int, cu_price: int):
    gas = base_gas + base_iter_cnt * NeonProg.BaseGas
    iter_cnt = base_iter_cnt + NeonProg.MinIterCnt

    pkt = CuCostPktData.from_raw(gas, iter_cnt, cu_price)

    pkt_gas = pkt.tx_cost
    self.assertGreater(pkt_gas, 0)

    unpkt = CuCostPktData.unpack(pkt_gas)

    self.assertGreaterEqual(unpkt.cu_price, cu_price)
    self.assertGreater(cu_price + SolCbProg.BaseCuPrice, unpkt.cu_price)

    self.assertEqual(unpkt.iter_cnt, iter_cnt)

    self.assertGreater(unpkt.base_tx_cost, gas)


def check_range_unpack(self: unittest.TestCase, base_gas_range: range, iter_range: range, cu_price_range: range):
    for base_gas in base_gas_range:
        for iter_cnt in iter_range:
            for cu_price in cu_price_range:
                check_unpack(self, base_gas, iter_cnt, cu_price)


class TestCuCostPktData(unittest.TestCase):
    _1sol: Final[int] = pow(10, 9)
    _max_cu_price: Final[int] = _1sol * SolCbProg.MicroLamport // SolCbProg.MaxCuLimit
    _fast_cu_range: Final[range] = range(10_000, _max_cu_price, SolCbProg.BaseCuPrice * 100)
    _slow_cu_range: Final[range] = range(1_000, SolCbProg.BaseCuPrice * 5)
    _gas_price_range: Final[range] = range(NeonProg.MinTxCost, 1_000_000, 250_000)

    def test_min_gas_limit(self):
        pkt = CuCostPktData.from_raw(NeonProg.MinTxCost, NeonProg.MinIterCnt, SolCbProg.BaseCuPrice)
        assert pkt.tx_cost == 0x127ff

    def test_range_it0_250(self):
        check_range_unpack(
            self,
            self._gas_price_range,
            range(0, 250, 25),
            self._fast_cu_range,
        )

    def test_range_it300_4000(self):
        check_range_unpack(
            self,
            self._gas_price_range,
            range(300, 4000, 250),
            self._fast_cu_range,
        )

    def test_range_it0_50_slow(self):
        check_range_unpack(
            self,
            self._gas_price_range,
            range(0, 50),
            self._slow_cu_range,
        )


if __name__ == "__main__":
    unittest.main()