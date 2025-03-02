import dataclasses
import unittest
from typing import Sequence

from common.config.config import CuPriceMode, CuPriceLevel
from common.cu_price.api import PriorityFeeCfg
from common.neon.block import NeonBlockCuPriceInfo
from common.neon.cu_price_data_model import CuPricePercentileModel
from common.neon.neon_program import NeonProg, NeonProgCfg, TokenInfo
from common.solana.pubkey import SolPubKey
from proxy.mempool.gas_price_calculator import MpGasPriceCalculator


class TestDb:
    def __init__(self, block_cu_price_list: Sequence[NeonBlockCuPriceInfo]):
        self._block_cu_price_list = block_cu_price_list

    async def get_block_cu_price_list(self, _: int) -> Sequence[NeonBlockCuPriceInfo]:
        return self._block_cu_price_list


class TestGasPriceCalculator(MpGasPriceCalculator):
    def __init__(self, block_cu_price_list: Sequence[NeonBlockCuPriceInfo]):  # noqa
        self._db = TestDb(block_cu_price_list)  # noqa


def _init_neon_prog():
    cfg = NeonProgCfg(
        deployed_slot=0,
        treasury_pool_cnt=100,
        treasury_pool_seed=b"treasury",
        treasury_payment=5000,
        account_seed_version=3,
        evm_version="1.14.0",
        evm_step_cnt=500,
        holder_msg_size=950,
        gas_limit_multiplier_wo_chain_id=10,
        tree_account_slot_out=90,
        tree_account_finish_tx_gas=5000,
        token_list=[
            TokenInfo(name="NEON", mint=SolPubKey.default(), chain_id=111),
            TokenInfo(name="SOL", mint=SolPubKey.default(), chain_id=112),
        ]
    )
    NeonProg.init_prog(cfg)


class TestCuPricePercentile(unittest.TestCase):
    def setUp(self):
        _init_neon_prog()

    def test_up_weighted_percentile(self):
        start_slot = 1000
        slot_cnt = 50
        cu_level = CuPriceLevel.High
        cu_level_pct = CuPriceLevel.to_pct(cu_level)
        #                     0  10 20 30 40 50 60    70     80      90       100
        base_cu_price_list = [0, 0, 0, 0, 0, 5, 5000, 46535, 768060, 4500000, 100000000]
        block_cu_price_list = [
            NeonBlockCuPriceInfo(slot, base_cu_price_list)
            for slot in range(start_slot, start_slot + slot_cnt - 1)
        ]
        #                    0  10 20 30 40 50 60    70(+)  80(+)   90       100
        big_cu_price_list = [0, 0, 0, 0, 0, 5, 5000, 66535, 868060, 4500000, 100000000]
        block_cu_price_list.append(
            NeonBlockCuPriceInfo(block_cu_price_list[-1].slot + 1, big_cu_price_list),
        )

        base_cu_price = CuPricePercentileModel.from_raw(base_cu_price_list).get_percentile(cu_level_pct)
        cu_price = CuPricePercentileModel.get_weighted_percentile(
            cu_level_pct,
            len(block_cu_price_list),
            [block.cu_price_list for block in block_cu_price_list],
        )
        self.assertGreater(cu_price, base_cu_price)

    def test_down_weighted_percentile(self):
        slot_cnt = 50
        start_slot = 2000
        cu_level = CuPriceLevel.High
        cu_level_pct = CuPriceLevel.to_pct(cu_level)
        #                     0  10 20 30 40 50 60    70     80      90       100
        base_cu_price_list = [0, 0, 0, 0, 0, 5, 5000, 46535, 768060, 4500000, 100000000]
        block_cu_price_list = [
            NeonBlockCuPriceInfo(slot, base_cu_price_list)
            for slot in range(start_slot, start_slot + slot_cnt - 1)
        ]
        #                    0  10 20 30 40 50 60    70(-)  80(-)   90       100
        low_cu_price_list = [0, 0, 0, 0, 0, 5, 5000, 26535, 168060, 4500000, 100000000]
        block_cu_price_list.append(
            NeonBlockCuPriceInfo(block_cu_price_list[-1].slot + 1, low_cu_price_list),
        )

        base_cu_price = CuPricePercentileModel.from_raw(base_cu_price_list).get_percentile(cu_level_pct)
        cu_price = CuPricePercentileModel.get_weighted_percentile(
            cu_level_pct,
            len(block_cu_price_list),
            [block.cu_price_list for block in block_cu_price_list],
        )
        self.assertLess(cu_price, base_cu_price)

    def test_percentile(self):
        cu_level = CuPriceLevel.High
        cu_level_pct = CuPriceLevel.to_pct(cu_level)
        self.assertEqual(cu_level_pct, 75)

        #                0  10 20 30 40 50 60    70     80      90       100
        cu_price_list = [0, 0, 0, 0, 0, 5, 5000, 26535, 168060, 4500000, 100000000]
        cu_price = CuPricePercentileModel.from_raw(cu_price_list).get_percentile(cu_level_pct)
        #
        idx = cu_level_pct // CuPricePercentileModel._PercentileStep
        self.assertLess(cu_price_list[idx], cu_price)
        self.assertGreater(cu_price_list[idx + 1], cu_price)


class TestCuPriceCalculator(unittest.IsolatedAsyncioTestCase):
    _fee_cfg = PriorityFeeCfg(
        operator_fee=0.5,
        min_priority_fee=2.5,
        max_priority_fee=20.0,
        const_gas_price=None,
        min_gas_price=None,
        cu_price_mode=CuPriceMode.Atlas,
        cu_price_level=CuPriceLevel.High,
        cu_price_block_cnt=50,
        def_cu_price=100500,
        def_simple_cu_price=10500,
    )

    _start_slot = 3000
    _cu_price_list = [0, 0, 0, 0, 0, 5, 5000, 46535, 168060, 4500000, 100000000]

    @property
    def _block_cu_price_list(self):
        return [
            NeonBlockCuPriceInfo(slot, self._cu_price_list)
            for slot in range(self._start_slot, self._start_slot + self._fee_cfg.cu_price_block_cnt)
        ]

    def setUp(self):
        _init_neon_prog()

        gas_price_calculator = TestGasPriceCalculator(self._block_cu_price_list)

        self.base_cu_price = int(gas_price_calculator._calc_base_cu_price(1.0))
        self.min_cu_price = int(gas_price_calculator._calc_base_cu_price(self._fee_cfg.min_priority_fee))
        self.max_cu_price = int(gas_price_calculator._calc_base_cu_price(self._fee_cfg.max_priority_fee))

    def test_base_cu_price(self):
        self.assertEqual(self.base_cu_price, 7142)
        self.assertEqual(self.min_cu_price, 17857)
        self.assertEqual(self.max_cu_price, 142857)

    async def test_target_cu_price(self):
        gas_price_calculator = TestGasPriceCalculator(self._block_cu_price_list)
        cu_price = await gas_price_calculator._calc_target_cu_price(self._fee_cfg)
        #
        step = CuPricePercentileModel._PercentileStep
        cu_level_pct = CuPriceLevel.to_pct(self._fee_cfg.cu_price_level)
        idx = cu_level_pct // step
        mul_coeff = cu_level_pct % step
        low_cu_price = self._cu_price_list[idx]
        high_cu_price = self._cu_price_list[idx + 1]
        self.assertEqual(int(cu_price), int(low_cu_price + (high_cu_price - low_cu_price) / step * mul_coeff))

    async def test_ok_priority_fee(self):
        gas_price_calculator = TestGasPriceCalculator(self._block_cu_price_list)
        #
        priority_fee, cu_price = await gas_price_calculator._calc_priority_fee(self._fee_cfg)
        self.assertGreater(priority_fee, self._fee_cfg.min_priority_fee)
        self.assertLess(priority_fee, self._fee_cfg.max_priority_fee)
        #
        self.assertGreater(cu_price, self.min_cu_price)
        self.assertLess(cu_price, self.max_cu_price)
        step = CuPricePercentileModel._PercentileStep
        cu_level_pct = CuPriceLevel.to_pct(self._fee_cfg.cu_price_level)
        idx = cu_level_pct // step
        low_cu_price = self._cu_price_list[idx]
        high_cu_price = self._cu_price_list[idx + 1]
        self.assertGreater(cu_price, low_cu_price)
        self.assertLess(cu_price, high_cu_price)
        target_cu_price = gas_price_calculator._calc_base_cu_price(priority_fee)
        self.assertEqual(cu_price, int(target_cu_price))

    async def test_min_priority_fee(self):
        gas_price_calculator = TestGasPriceCalculator(self._block_cu_price_list)
        #
        fee_cfg = dataclasses.replace(self._fee_cfg, cu_price_level=CuPriceLevel.Low)
        priority_fee, cu_price = await gas_price_calculator._calc_priority_fee(fee_cfg)
        self.assertEqual(int(priority_fee*100), int(self._fee_cfg.min_priority_fee*100))
        #
        self.assertEqual(cu_price, self.min_cu_price)

    async def test_max_priority_fee(self):
        gas_price_calculator = TestGasPriceCalculator(self._block_cu_price_list)
        #
        fee_cfg = dataclasses.replace(self._fee_cfg, cu_price_level=CuPriceLevel.UnsafeMax)
        priority_fee, cu_price = await gas_price_calculator._calc_priority_fee(fee_cfg)
        self.assertEqual(cu_price, self.max_cu_price)
        self.assertEqual(int(priority_fee * 100), int(self._fee_cfg.max_priority_fee * 100))


if __name__ == "__main__":
    unittest.main()
