import json
import unittest

from common.solana.pubkey import SolPubKey
from common.solana.signature import SolTxSig
from common.solana.transaction_meta import SolRpcTxSlotInfo
from common.solana_rpc.transaction_error_parser import SolTxErrorParser
from common.solana_rpc.transaction_list_sender import SolTxListSender
from common.solana_rpc.transaction_list_sender_stat import SolTxStatClient, SolTxDoneData, SolTxFailData
from common.utils.cached import cached_property


class TestCbExceeded(unittest.TestCase):
    _test_tx = {
        "slot": 274611500,
        "transaction": {
            "signatures": ["QRY9xdaWqopY8zS6STRcV6vm3MXogNiYi4uTwLtiGHYXp5H1GPJ5otmuedyUQL9QxioLdRavf7nLRiANiUWivjs"],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 4,
                },
                "accountKeys": [
                    "8wXUvU388JosWK5i9zmWJP8dsxLmtsGCUp47nS9Yso8w",
                    "AN8syzN7yLCbUmBuKgTi1addZS6C85q29nkHXnyfUa84",
                    "EGf1GHs8VAGC3h72uxZJ3vAbptS1f1WpBRhijzBnYGko",
                    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "11111111111111111111111111111111",
                    "ComputeBudget111111111111111111111111111111",
                    "NeonVMyRX5GbCrsAHnUwx1nYYoJAtskU1bWUo6JGNyG",
                ],
                "recentBlockhash": "twFxPfNNJhk1Qi98vskcqcEWTtEu4N8TdhFK2GhJ9K4",
                "instructions": [
                    {"programIdIndex": 5, "accounts": [], "data": "3MZf3aXK9QFy", "stackHeight": None},
                    {"programIdIndex": 5, "accounts": [], "data": "7YXqSw", "stackHeight": None},
                    {"programIdIndex": 5, "accounts": [], "data": "HNdmuR", "stackHeight": None},
                    {
                        "programIdIndex": 6,
                        "accounts": [
                            1,
                            0,
                            8,
                            2,
                            4,
                            32,
                            3,
                            26,
                            49,
                            47,
                            43,
                            38,
                            44,
                            40,
                            19,
                            17,
                            27,
                            18,
                            35,
                            16,
                            46,
                            20,
                            52,
                            23,
                            25,
                            11,
                            50,
                            36,
                            41,
                            51,
                            12,
                            9,
                            7,
                            30,
                            28,
                            15,
                            24,
                            48,
                            31,
                            29,
                            33,
                            10,
                            13,
                            14,
                            37,
                            42,
                            21,
                            45,
                            22,
                            34,
                            39,
                        ],
                        "data": "5SRDCKWJ1bY1mp7EZD",
                        "stackHeight": None,
                    },
                ],
                "addressTableLookups": [
                    {
                        "accountKey": "G54YahNN4Ucy9Me8teSxBGsk5Dqe2WD1zNniKH6RXJGN",
                        "writableIndexes": [7, 24],
                        "readonlyIndexes": [
                            0,
                            1,
                            2,
                            4,
                            5,
                            6,
                            8,
                            9,
                            10,
                            11,
                            12,
                            13,
                            14,
                            15,
                            16,
                            17,
                            18,
                            19,
                            20,
                            21,
                            22,
                            23,
                            25,
                            26,
                            27,
                            28,
                            29,
                            30,
                            31,
                            32,
                            33,
                            34,
                            35,
                            36,
                            37,
                            38,
                            39,
                            40,
                            41,
                            42,
                            43,
                            44,
                            45,
                            46,
                        ],
                    }
                ],
            },
        },
        "meta": {
            "err": {"InstructionError": [3, "ProgramFailedToComplete"]},
            "status": {"Err": {"InstructionError": [3, "ProgramFailedToComplete"]}},
            "fee": 21800,
            "preBalances": [
                3709179983,
                1825413120,
                1545120,
                934087680,
                1,
                1,
                1141440,
                1405920,
                3730880,
                83471280,
                31647120,
                0,
                1162320,
                2039280,
                80854320,
                1162320,
                36881040,
                1162320,
                31647120,
                89874480,
                30206400,
                31647120,
                1162320,
                1162320,
                1162320,
                1162320,
                31647120,
                1162320,
                31647120,
                3229440,
                31647120,
                0,
                20100480,
                2039280,
                0,
                1162320,
                58241280,
                3229440,
                174104400,
                1162320,
                0,
                111339120,
                166253520,
                0,
                1162320,
                2616960,
                145178640,
                76184160,
                1162320,
                1162320,
                0,
                1162320,
                39908640,
            ],
            "postBalances": [
                3709158183,
                1825413120,
                1545120,
                934087680,
                1,
                1,
                1141440,
                1405920,
                3730880,
                83471280,
                31647120,
                0,
                1162320,
                2039280,
                80854320,
                1162320,
                36881040,
                1162320,
                31647120,
                89874480,
                30206400,
                31647120,
                1162320,
                1162320,
                1162320,
                1162320,
                31647120,
                1162320,
                31647120,
                3229440,
                31647120,
                0,
                20100480,
                2039280,
                0,
                1162320,
                58241280,
                3229440,
                174104400,
                1162320,
                0,
                111339120,
                166253520,
                0,
                1162320,
                2616960,
                145178640,
                76184160,
                1162320,
                1162320,
                0,
                1162320,
                39908640,
            ],
            "innerInstructions": [
                {
                    "index": 3,
                    "instructions": [
                        {"programIdIndex": 4, "accounts": [0, 8], "data": "3Bxs4PckVVt51W8w", "stackHeight": 2}
                    ],
                }
            ],
            "logMessages": [
                "Program ComputeBudget111111111111111111111111111111 invoke [1]",
                "Program ComputeBudget111111111111111111111111111111 success",
                "Program ComputeBudget111111111111111111111111111111 invoke [1]",
                "Program ComputeBudget111111111111111111111111111111 success",
                "Program ComputeBudget111111111111111111111111111111 invoke [1]",
                "Program ComputeBudget111111111111111111111111111111 success",
                "Program NeonVMyRX5GbCrsAHnUwx1nYYoJAtskU1bWUo6JGNyG invoke [1]",
                "Program log: Instruction: Begin or Continue Transaction from Account",
                "Program data: SEFTSA== yU/T3YRF9+7uq6G4IgieYurgXKLe9qcZp2DyoNotZIc=",
                "Program data: TUlORVI= tZzr9d3zNCwtrm813f05dyCzRdw=",
                "Program data: RU5URVI= Q0FMTA== Oy9oib+sK5hHVJaRFs0dBER9AS0=",
                "Program data: RU5URVI= REVMRUdBVEVDQUxM wc2jaWdRvBHHV5RkRju3DXYozKY=",
                "Program data: RU5URVI= U1RBVElDQ0FMTA== VQ+cxGVmVg2NYIgVqsNDBcra9Wk=",
                "Program data: RVhJVA== UkVUVVJO",
                "Program data: U1RFUFM= 9QEAAAAAAAA= 9QEAAAAAAAA=",
                "Program 11111111111111111111111111111111 invoke [2]",
                "Program 11111111111111111111111111111111 success",
                "Program data: R0FT ECcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= YFsDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "Program NeonVMyRX5GbCrsAHnUwx1nYYoJAtskU1bWUo6JGNyG consumed 559494 of 559550 compute units",
                "Program NeonVMyRX5GbCrsAHnUwx1nYYoJAtskU1bWUo6JGNyG failed: exceeded CUs meter at BPF instruction",
            ],
            "preTokenBalances": [
                {
                    "accountIndex": 13,
                    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                    "uiTokenAmount": {"uiAmount": None, "decimals": 6, "amount": "0", "uiAmountString": "0"},
                    "owner": "8FqvkRVSusXByDSE4bnX9B7yf8XSEjPRxJKJ6t4pzG8j",
                    "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                },
                {
                    "accountIndex": 33,
                    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                    "uiTokenAmount": {
                        "uiAmount": 57127.95884,
                        "decimals": 6,
                        "amount": "57127958840",
                        "uiAmountString": "57127.95884",
                    },
                    "owner": "8FqvkRVSusXByDSE4bnX9B7yf8XSEjPRxJKJ6t4pzG8j",
                    "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                },
            ],
            "postTokenBalances": [
                {
                    "accountIndex": 13,
                    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                    "uiTokenAmount": {"uiAmount": None, "decimals": 6, "amount": "0", "uiAmountString": "0"},
                    "owner": "8FqvkRVSusXByDSE4bnX9B7yf8XSEjPRxJKJ6t4pzG8j",
                    "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                },
                {
                    "accountIndex": 33,
                    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                    "uiTokenAmount": {
                        "uiAmount": 57127.95884,
                        "decimals": 6,
                        "amount": "57127958840",
                        "uiAmountString": "57127.95884",
                    },
                    "owner": "8FqvkRVSusXByDSE4bnX9B7yf8XSEjPRxJKJ6t4pzG8j",
                    "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                },
            ],
            "rewards": [],
            "loadedAddresses": {
                "writable": [
                    "B2YaZinnN4mkwxExFfWC8voRnkySHP5quq5GWpL6fbp8",
                    "GBT2JskgQuXDQ9T9mZdoWi4df3Ygba4MGNz7vybfaBdx",
                ],
                "readonly": [
                    "Ay5FD24dMRiBvDnPs4r8z6dbnem9dFh3eQQrRRFLjA7Z",
                    "DokBrmi15AXFos5XX7zabUdD61cyybkcNjCmHvzL4N3t",
                    "82YgZcQeLDCcx7t7wqLHdmC2eCgGsc14JhJnvgdV8eqL",
                    "AX78f5WgW36eVz1YN4xQE4BjdYUJvf3nT5dxPZDVRydz",
                    "DxrYMFk5mNo5fzqWyzYfuTdqJVjrBdwaDiJt489WizmC",
                    "E8pYqnTdKtTirUryzeVha67TrhkE9gczNsRgWag4LSfe",
                    "CafqV9xukCh4i11eZV3ARHtPZCkB6WawEQZH8gfztUSD",
                    "6t63YbTNE6E6tmUPyVhoHFqmnnJntVW34avMBvWhmiky",
                    "4K9BmJdQDPnXm4xrE2iav6QgYx4CYfTa4YubdHF9XCAV",
                    "4dKREkLscgGmrASdjMiQvuz8UiwfCtHkyoSikBrLUTu8",
                    "3vs4EBNRyazLuUx4MrPgvQqV5cJ4dWyc9dH6TNbdxHaS",
                    "6wDFDfx9zth4RJqQNH89ZqWjraEc2ZL62wxUnMsJvGSU",
                    "FB6mLcU72BVop4taE6uDrDi7QqhPAyWb1E6gzY1HHCqp",
                    "HM1hgc1yPrJMS6zEuapa55AKaxEvszXo8LidURxHLpbE",
                    "6xjVYYjKyrxRxeqycU19Tu8K9D6NzZHVGENZ9hZWiJ8q",
                    "CmV2mcbq1XAiEQa4LifKCpHyVhMVsCb3eQYV64fzuVR2",
                    "7qRRr1X2NKNteQxmSQcfH7muRfmqagvJC4VZN4KaNbMa",
                    "WQRH1oGcWZvfakRZi1TxVBgEnWBHPSAXTP4JSYJKc7D",
                    "4R1L3oUMmFokSz2RMbdH91ufjMT9bPKWg3robuLf4vif",
                    "CNyMrfdbzv9ytCF2KU2dLY8EBQ96x5wmjJSe1EYXCb5c",
                    "DbSMkZP4Qy8EYxgtpDYSWLRbtgCPmnGqxLTgUhRGmrLE",
                    "CLDwMQuJ8uJCEV1vHiBuL6MMFn9exyTj4JyQrEjV8s2g",
                    "DUoQv8FFNDrSpgZjDKs6NmWydC4LRPok4SgzCuPBuFpf",
                    "MKtth5hsFhyhWtVyWSCrqu4ZE68bNoz86JYUfsw9xg6",
                    "DdYR1EVV2yhpUGCJDLgCRn2hZ3zJjRZv9VgCbWGjbmJS",
                    "HQFk77T98MKv1asweb4kvbKwksa5BbifoMWM9YQEBVP4",
                    "6dWn4aaas57Z84ch9AeHef3YCQ6TKsyyrgXAKoEiXdF6",
                    "8FqvkRVSusXByDSE4bnX9B7yf8XSEjPRxJKJ6t4pzG8j",
                    "ETcxfXNboA8vtLeAWLjCmDRTCwF7VYTZKZMw1csZNCtr",
                    "pQtrrQChNWm7Fv166iEG1cKhP4ZC6zEUQSgsCYAMxuE",
                    "J28qMdg8BfMRjqGLyhoAWsqnfRo6Db3wXJeWc1Xn4EWq",
                    "2rpTL8MbmK2PMaFTn1KRJuqGHN9xNzNAihgmv2hc3ay3",
                    "8RbsucQkL3ca1HjxHTw9bE4M9MWjpRJHrPLskypuxPXK",
                    "F3Vyktg2bs4L9bnRPo3LoHsyzDtWm3DmBhUzKjux9Li6",
                    "ky6PwQZGM1LbNYY1R9YeYqYSePcqHjDgSnwL8BrdpmB",
                    "2erTq9AQPbVkaGKbLwrVdrr1rah8HUpCq1W1RodY34Q7",
                    "GzGuoKXE8Unn7Vcg1DtomwD27tL4bVUpSK2M1yk6Xfz5",
                    "6vAjqUJSVnCWQHSVBV6rG52sDmmYKs8i1hrSfxJFKR9R",
                    "dxPJSgbrMkJJv4qSCRBL8e1GarzrGoU5H14vQDuj9ia",
                    "CoNTKW7cEvYtF1Pgyxi893jJosvKYPR7a5YuR1mkKd2u",
                    "YkvWqAY6Acc9KSXwe4njog44Aus1x1e5C2XYa5Bo9fS",
                    "8CRFKbuJsffnqihZAhUukyYaEdyZw7UYztBJWDzNBfp4",
                    "AEVhJsvwCsm5QntAH88yNhuzgE7rKqh6ihittnYioUe9",
                    "6waHh9kdg3qPE4f8pFrb9eYHCYr58g6HJfaMGGimKUX4",
                ],
            },
            "computeUnitsConsumed": 560000,
        },
        "version": 0,
        "blockTime": 1719631150,
    }

    _test_json_tx = json.dumps(_test_tx)
    _test_meta_tx = SolRpcTxSlotInfo.from_json(_test_json_tx)

    class _TestTx:
        def __init__(self, tx_meta: SolRpcTxSlotInfo) -> None:
            self._tx_meta = tx_meta

        @cached_property
        def message(self):
            return self._tx_meta.transaction.transaction.message

        @cached_property
        def is_signed(self) -> bool:
            return True

        @cached_property
        def sig(self) -> SolTxSig:
            return SolTxSig.from_raw(self._tx_meta.transaction.transaction.signatures[0])

        @cached_property
        def account_key_list(self):
            raw_key_list = self._tx_meta.transaction.transaction.message.account_keys
            alt_key_list = self._tx_meta.transaction.meta.loaded_addresses
            acct_key_list = list(map(lambda x: SolPubKey.from_raw(x), raw_key_list))
            acct_key_list.extend(map(lambda x: SolPubKey.from_raw(x), alt_key_list.writable))
            acct_key_list.extend(map(lambda x: SolPubKey.from_raw(x), alt_key_list.readonly))
            return acct_key_list

    def _get_tx(self) -> _TestTx:
        return self._TestTx(self._test_meta_tx)

    def test_error_parser(self):
        error_parser = SolTxErrorParser(self._get_tx(), self._test_meta_tx)
        self.assertTrue(error_parser.check_if_cb_exceeded)

    def test_tx_sender(self):
        class _Cfg:
            @property
            def commit_timeout_sec(self) -> int:
                return 10

        class _SolTxStatClient(SolTxStatClient):
            def commit_sol_tx_done(self, data: SolTxDoneData) -> None: pass
            def commit_sol_tx_fail(self, data: SolTxFailData) -> None: pass


        tx_sender = SolTxListSender(_Cfg(), _SolTxStatClient(), None, None)
        status = tx_sender._decode_tx_status(self._get_tx(), 0, self._test_meta_tx)
        self.assertEqual(status.tx_status, status.tx_status.CbExceededError)


if __name__ == "__main__":
    unittest.main()
