import unittest

from common.neon.account import NeonAccount
from common.solana.pubkey import SolPubKey
from common.neon_rpc.api import (
    CoreApiResultCode,
    CoreApiResp,
    NeonAccountModel,
    NeonContractModel,
    NeonAccountStatus,
    HolderAccountStatus,
    HolderAccountModel,
    EvmConfigModel,
    CoreApiBuildModel,
)


class TestLayout(unittest.TestCase):
    _TestSolPubKey = SolPubKey.from_string("AddressLookupTab1e1111111111111111111111111")

    def test_neon_account_model(self):
        json_data = {
            "status": "legacy",
            "solana_address": self._TestSolPubKey.to_string(),
            "contract_solana_address": None,
            "trx_count": 10,
            "balance": "0x1245",
        }

        neon_acct = NeonAccount.random(15)
        neon_acct_info = NeonAccountModel.from_dict(json_data, account=neon_acct)
        self.assertIs(neon_acct_info.account, neon_acct)
        self.assertEqual(neon_acct_info.status, NeonAccountStatus.Legacy)
        self.assertEqual(neon_acct_info.state_tx_cnt, 10)
        self.assertEqual(neon_acct_info.balance, 4677)
        self.assertEqual(neon_acct_info.sol_address, self._TestSolPubKey)
        self.assertEqual(neon_acct_info.contract_sol_address, SolPubKey.default())

    def test_neon_account_status(self):
        for name in NeonAccountStatus:
            self.assertEqual(name, NeonAccountStatus.from_raw(name))
        self.assertIs(NeonAccountStatus.Empty, NeonAccountStatus.from_raw("Something"))

    def test_neon_contract(self):
        json_data = {"chain_id": 10, "code": "abcd", "solana_address": self._TestSolPubKey}
        acct = NeonAccount.random(15)
        neon_contract = NeonContractModel.from_dict(json_data, account=acct)
        self.assertEqual(neon_contract.account.to_checksum_address(), acct.to_checksum_address())
        self.assertEqual(neon_contract.chain_id, 10)
        self.assertEqual(neon_contract.code, "0xabcd")
        self.assertEqual(neon_contract.sol_address, self._TestSolPubKey)
        self.assertTrue(neon_contract.has_code)

    def test_holder_account_status(self):
        for name in HolderAccountStatus:
            self.assertEqual(name, HolderAccountStatus.from_raw(name))
        self.assertIs(HolderAccountStatus.Error, HolderAccountStatus.from_raw("Something"))

    def test_empty_holder_account(self):
        json_data = {
            "status": "Empty",
            "steps_executed": 0,
        }

        result = HolderAccountModel.from_dict(self._TestSolPubKey, 111, json_data)
        self.assertTrue(isinstance(result, HolderAccountModel))
        self.assertIs(result.address, self._TestSolPubKey)
        self.assertTrue(result.owner.is_empty)
        self.assertEqual(result.status, HolderAccountStatus.Empty)
        self.assertEqual(result.size, 0)
        self.assertTrue(result.neon_tx_hash.is_empty)
        self.assertEqual(result.evm_step_cnt, 0)
        self.assertEqual(result.account_key_list, [])

    def test_active_holder_account(self):
        json_data = {
            "status": "Active",
            "len": 262144,
            "owner": self._TestSolPubKey.to_string(),
            "tx": "10f9724bb40ed81d953baa7dfbe2a10f41d3591a075b405a49b2ef5b656a0e72",
            "chain_id": 111,
            "accounts": [
                self._TestSolPubKey.to_string(),
            ],
            "steps_executed": 501,
        }

        result = HolderAccountModel.from_dict(self._TestSolPubKey, 111, json_data)

        self.assertTrue(isinstance(result, HolderAccountModel))
        self.assertIs(result.address, self._TestSolPubKey)
        self.assertEqual(result.owner, self._TestSolPubKey)
        self.assertEqual(result.status, HolderAccountStatus.Active)
        self.assertEqual(result.size, 262144)
        self.assertEqual(result.neon_tx_hash, "0x10f9724bb40ed81d953baa7dfbe2a10f41d3591a075b405a49b2ef5b656a0e72")
        self.assertEqual(result.evm_step_cnt, 501)
        self.assertEqual(result.account_key_list, [self._TestSolPubKey])

    def test_finalized_holder_account(self):
        json_data = {
            "status": "Finalized",
            "len": 262144,
            "owner": self._TestSolPubKey,
            "tx": "bd4186a4a4a4bfbdec837dbfb6c92985e08b37a29c8e44c5e9ccb8dface2e504",
            "steps_executed": 0,
        }
        result = HolderAccountModel.from_dict(self._TestSolPubKey, 111, json_data)

        self.assertTrue(isinstance(result, HolderAccountModel))
        self.assertIs(result.address, self._TestSolPubKey)
        self.assertEqual(result.owner, self._TestSolPubKey)
        self.assertEqual(result.status, HolderAccountStatus.Finalized)
        self.assertEqual(result.size, 262144)
        self.assertEqual(result.neon_tx_hash, "0xbd4186a4a4a4bfbdec837dbfb6c92985e08b37a29c8e44c5e9ccb8dface2e504")
        self.assertEqual(result.evm_step_cnt, 0)
        self.assertEqual(result.account_key_list, [])

    def test_evm_cfg_from_core_api(self):
        json_data = {
            "result": "success",
            "value": {
                "version": "1.11.0-dev",
                "revision": "93a4694e6cbf89b6ae96bdf24075e84883d8390b",
                "status": "Ok",
                "environment": "ci",
                "chains": [
                    {"id": 111, "name": "neon", "token": "HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU"},
                    {"id": 112, "name": "sol", "token": "So11111111111111111111111111111111111111112"},
                    {"id": 113, "name": "usdt", "token": "2duuuuhNJHUYqcnZ7LKfeufeeTBgSJdftf2zM3cZV6ym"},
                    {"id": 114, "name": "eth", "token": "EwJYd3UAFAgzodVeHprB2gMQ68r4ZEbbvpoVzCZ1dGq5"},
                ],
                "config": {
                    "NEON_ACCOUNT_SEED_VERSION": "3",
                    "NEON_EVM_STEPS_LAST_ITERATION_MAX": "1",
                    "NEON_EVM_STEPS_MIN": "500",
                    "NEON_GAS_LIMIT_MULTIPLIER_NO_CHAINID": "1000",
                    "NEON_HOLDER_MSG_SIZE": "950",
                    "NEON_PAYMENT_TO_TREASURE": "5000",
                    "NEON_STORAGE_ENTRIES_IN_CONTRACT_ACCOUNT": "64",
                    "NEON_TREASURY_POOL_COUNT": "128",
                    "NEON_TREASURY_POOL_SEED": "treasury_pool",
                },
            },
        }
        resp = CoreApiResp.model_validate(json_data)
        self.assertEqual(resp.result, CoreApiResultCode.Success)
        evm_cfg = EvmConfigModel.from_dict(resp.value, deployed_slot=1)
        self.assertEqual(evm_cfg.deployed_slot, 1)
        self.assertEqual(evm_cfg.version, "1.11.0-dev")
        self.assertEqual(evm_cfg.revision, "93a4694e6cbf89b6ae96bdf24075e84883d8390b")
        self.assertEqual(evm_cfg.default_chain_id, 111)
        self.assertEqual(evm_cfg.token_dict["ETH"].chain_id, 114)
        self.assertEqual(evm_cfg.chain_dict[113].name, "USDT")

    def test_evm_cfg_from_cmd_line(self):
        json_data = {
            "result": "success",
            "value": {
                "NEON_TREASURY_POOL_SEED": "treasury_pool",
                "NEON_EVM_STEPS_MIN": "500",
                "NEON_GAS_LIMIT_MULTIPLIER_NO_CHAINID": "1000",
                "NEON_ACCOUNT_SEED_VERSION": "3",
                "NEON_PKG_VERSION": "1.11.0-dev",
                "NEON_STATUS_NAME": "WORK",
                "NEON_HOLDER_MSG_SIZE": "950",
                "NEON_CHAIN_ID": "111",
                "NEON_EVM_STEPS_LAST_ITERATION_MAX": "1",
                "NEON_STORAGE_ENTRIES_IN_CONTRACT_ACCOUNT": "64",
                "NEON_TOKEN_MINT": "HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU",
                "NEON_TREASURY_POOL_COUNT": "128",
                "NEON_REVISION": "93a4694e6cbf89b6ae96bdf24075e84883d8390b",
                "NEON_PAYMENT_TO_TREASURE": "5000",
            },
            "logs": [
                {
                    "message": 'BuildInfo={"timestamp":"2024-03-29T08:48:41.630069196Z","profile":"release","optimization_level":"O3","crate_info":{"name":"neon-cli","version":"1.11.0-dev"},"compiler":{"version":"1.73.0"},"version_control":{"commit_id":"93a4694e6cbf89b6ae96bdf24075e84883d8390b","dirty":true,"branch":"develop","tags":[]}}',
                    "source": "cli/src/main.rs:214",
                    "level": "DEBUG",
                },
                {
                    "message": "execution time: 0.029988197 sec",
                    "source": "cli/src/main.rs:219",
                    "level": "INFO",
                },
            ],
        }
        resp = CoreApiResp.model_validate(json_data)
        self.assertEqual(resp.result, CoreApiResultCode.Success)
        evm_cfg = EvmConfigModel.from_dict(resp.value, deployed_slot=2)
        self.assertEqual(evm_cfg.deployed_slot, 2)
        self.assertEqual(evm_cfg.version, "1.11.0-dev")
        self.assertEqual(evm_cfg.revision, "93a4694e6cbf89b6ae96bdf24075e84883d8390b")
        self.assertEqual(evm_cfg.default_chain_id, 111)
        self.assertEqual(evm_cfg.token_dict["NEON"].chain_id, 111)
        self.assertEqual(evm_cfg.gas_limit_multiplier_wo_chain_id, 1000)
        self.assertEqual(evm_cfg.treasury_pool_seed, b"treasury_pool")
        self.assertEqual(evm_cfg.treasury_pool_cnt, 128)
        self.assertEqual(evm_cfg.evm_step_cnt, 500)
        self.assertEqual(evm_cfg.holder_msg_size, 950)
        self.assertEqual(evm_cfg.environment, "Unknown")
        self.assertEqual(evm_cfg.chain_dict[111].name, "NEON")


class Conversion:
    def __init__(self):
        self.treasury_pool_cnt = 0
        self.treasury_pool_seed = bytes()
        self.evm_step_cnt = 0
        self.holder_msg_size = 0
        self.gas_limit_multiplier_wo_chain_id = 0

    def test_build_info(self):
        json_data = {
            "timestamp": "2024-03-29T08:48:41.900517477Z",
            "profile": "release",
            "optimization_level": "O3",
            "crate_info": {"name": "neon-api", "version": "1.11.0-dev"},
            "compiler": {"version": "1.73.0"},
            "version_control": {
                "commit_id": "93a4694e6cbf89b6ae96bdf24075e84883d8390b",
                "dirty": True,
                "branch": "develop",
                "tags": [],
            },
        }
        build_info = CoreApiBuildModel.model_validate(json_data)
        self.assertEqual(build_info.crate_info.version, "1.11.0-dev")
        self.assertEqual(build_info.version_control.commit_id, "93a4694e6cbf89b6ae96bdf24075e84883d8390b")


if __name__ == "__main__":
    unittest.main()
