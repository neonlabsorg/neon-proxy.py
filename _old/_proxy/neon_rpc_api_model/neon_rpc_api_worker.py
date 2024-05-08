from __future__ import annotations

import logging
import multiprocessing
import threading
from dataclasses import dataclass
from typing import Optional, Union, Dict, Any, List, NewType, Iterable

import base58
from eth_account import Account as NeonAccount
from sha3 import keccak_256

from .estimate import GasEstimate
from .transaction_validator import NeonTxValidator
from ..common_neon.address import NeonAddress
from ..common_neon.config import Config
from ..common_neon.constants import EVM_PROGRAM_ID_STR
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.db.db_connect import DBConnection
from ..common_neon.errors import EthereumError, InvalidParamError, NonceTooHighError, NonceTooLowError
from ..common_neon.eth_commit import EthCommit
from ..common_neon.evm_log_decoder import NeonLogTxEvent
from ..common_neon.keys_storage import KeyStorage
from ..common_neon.neon_instruction import EvmIxCodeName, AltIxCodeName
from ..common_neon.neon_tx_receipt_info import NeonTxReceiptInfo
from ..common_neon.solana_block import SolBlockInfo
from ..common_neon.solana_interactor import SolInteractor
from ..common_neon.solana_neon_tx_receipt import SolNeonIxReceiptInfo, SolAltIxInfo
from ..common_neon.solana_tx import SolCommit
from ..common_neon.utils import NeonTxInfo
from ..common_neon.utils.eth_proto import NeonTx
from ..common_neon.utils.utils import u256big_to_hex, hex_to_bytes
from ..gas_tank.gas_less_accounts_db import GasLessAccountsDB
from ..indexer.indexer_db import IndexerDB
from ..mempool import (
    MemPoolClient, MP_SERVICE_ADDR,
    MPNeonTxResult, MPTxSendResult, MPTxSendResultCode, MPGasPriceResult, MPGasPriceTokenResult
)
from ..neon_core_api.neon_core_api_client import NeonCoreApiClient
from ..neon_core_api.neon_layouts import NeonAccountInfo

NEON_PROXY_PKG_VERSION = '1.11.0-dev'
NEON_PROXY_REVISION = 'NEON_PROXY_REVISION_TO_BE_REPLACED'
LOG = logging.getLogger(__name__)


@dataclass
class OpCostInfo:
    sol_spent: int = 0
    neon_income: int = 0


class TxReceiptDetail:
    Type = NewType('TxReceiptDetail', str)
    Eth = Type('ethereum')
    Neon = Type('neon')
    SolTxList = Type('solanaTransactionList')

    TypeList = [Eth, Neon, SolTxList]

    @staticmethod
    def to_type(value: str) -> TxReceiptDetail.Type:
        for detail in TxReceiptDetail.TypeList:
            if detail.upper() == value.upper():
                return detail

        raise InvalidParamError(message='Wrong receipt type')

    @staticmethod
    def to_prop_filter(detail: TxReceiptDetail.Type) -> NeonLogTxEvent.PropFilter:
        if detail == TxReceiptDetail.Eth:
            return NeonLogTxEvent.PropFilter.Eth
        return NeonLogTxEvent.PropFilter.Full


def get_req_id_from_log():
    th = threading.current_thread()
    req_id = getattr(th, "log_context", {}).get("req_id", "")
    return req_id


class NeonRpcApiWorkerData:
    proxy_id_glob = multiprocessing.Value('i', 0)

    def __init__(self, cfg: Config):
        db_conn = DBConnection(cfg)
        self.config = cfg
        self.solana = SolInteractor(cfg)

        self.db = IndexerDB.from_db(cfg, db_conn)
        self.gas_tank = GasLessAccountsDB(db_conn)

        self.core_api_client = NeonCoreApiClient(cfg)
        self.mempool_client = MemPoolClient(MP_SERVICE_ADDR)

        self._gas_price_value: Optional[MPGasPriceResult] = None
        self._gas_price_dict: Dict[int, MPGasPriceTokenResult] = dict()
        self._last_gas_price_time = 0

        self._last_evm_cfg_time = 0
        self._def_chain_id = 0
        self._is_evm_compatible = False

        with self.proxy_id_glob.get_lock():
            proxy_id = self.proxy_id_glob.value
            self.proxy_id_glob.value += 1

        if proxy_id == 0:
            LOG.debug(f'Neon Proxy version: {self.neon_proxyVersion()}')
        LOG.debug(f'Worker id {proxy_id}')


    @property
    def is_evm_compatible(self) -> bool:
        return self._is_evm_compatible


class NeonRpcApiWorker:
    @staticmethod
    def _normalize_topic(raw_topic: Any) -> str:
        try:
            assert isinstance(raw_topic, str)

            topic = raw_topic.strip().lower()
            assert topic[:2] == '0x'

            bin_topic = hex_to_bytes(topic)
            assert len(bin_topic) == 32
            assert len(topic) == 66

            return '0x' + bin_topic.hex().lower()
        except (Exception,):
            raise InvalidParamError(message=f'bad topic {raw_topic}')

    def _get_event_list(self, obj: Dict[str, Any]) -> List[NeonLogTxEvent]:
        from_block: Optional[int] = None
        to_block: Optional[int] = None
        address_list: List[str] = list()
        topic_list: List[List[str]] = list()

        if not isinstance(obj, dict):
            raise InvalidParamError(message=f'invalid input params: {obj}')

        if obj.get('fromBlock', 0) not in {0, '0x0', EthCommit.Earliest}:
            from_block = self._process_block_tag(obj['fromBlock']).slot
        if obj.get('toBlock', 'latest') not in {EthCommit.Latest, EthCommit.Pending}:
            to_block = self._process_block_tag(obj['toBlock']).slot

        if obj.get('blockHash', None) is not None:
            if ('fromBlock' in obj) or ('toBlock' in obj):
                raise InvalidParamError(
                    message='invalid filter: if blockHash is supplied fromBlock and toBlock must not be"',
                    code=-32600
                )

            block_hash = obj['blockHash']
            block = self._get_block_by_hash(block_hash)
            if block.is_empty:
                raise InvalidParamError(message=f'block hash {block_hash} does not exist')

            from_block = block.slot
            to_block = block.slot

        if obj.get('address', None) is not None:
            raw_address_list = obj['address']
            if isinstance(raw_address_list, str):
                address_list = [self._normalize_address(raw_address_list).address]
            elif isinstance(raw_address_list, list):
                for raw_address in raw_address_list:
                    address_list.append(self._normalize_address(raw_address).address)
            else:
                raise InvalidParamError(message=f'bad address {raw_address_list}')

        if 'topics' in obj:
            raw_topic_list = obj['topics']
            if raw_topic_list is None:
                raw_topic_list = []

            if not isinstance(raw_topic_list, list):
                raise InvalidParamError(message=f'bad topics {raw_topic_list}')

            for raw_topic in raw_topic_list:
                if isinstance(raw_topic, list):
                    item_list = [self._normalize_topic(raw_item) for raw_item in raw_topic if raw_item is not None]
                    topic_list.append(item_list)
                elif raw_topic is None:
                    topic_list.append(list())
                else:
                    topic_list.append([self._normalize_topic(raw_topic)])

        return self._db.get_event_list(from_block, to_block, address_list, topic_list)

    @staticmethod
    def _filter_event_list(event_list: Iterable[NeonLogTxEvent],
                           prop_filter: NeonLogTxEvent.PropFilter) -> List[Dict[str, Any]]:
        return [
            event.as_rpc_dict(prop_filter)
            for event in event_list
            if event.has_rpc_dict(prop_filter)
        ]

    def eth_getLogs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        event_list = self._get_event_list(obj)
        return self._filter_event_list(event_list, NeonLogTxEvent.PropFilter.Eth)

    def neon_getLogs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        event_list = self._get_event_list(obj)
        return self._filter_event_list(event_list, NeonLogTxEvent.PropFilter.Full)

    def _fill_transaction_receipt_answer(self, tx: NeonTxReceiptInfo, details: TxReceiptDetail.Type) -> dict:
        contract = NeonAddress.from_raw(tx.neon_tx.contract)
        if contract:
            contract = contract.checksum_address

        from_addr = NeonAddress.from_raw(tx.neon_tx.addr)
        from_addr = from_addr.checksum_address if from_addr else '0x' + '0' * 40

        to_addr = NeonAddress.from_raw(tx.neon_tx.to_addr)
        to_addr = to_addr.checksum_address if to_addr else None

        res = tx.neon_tx_res

        receipt = {
            "transactionHash": tx.neon_tx.sig,
            "transactionIndex": hex(res.tx_idx),
            "type": hex(tx.neon_tx.tx_type),
            "blockHash": res.block_hash,
            "blockNumber": hex(res.slot),
            "from": from_addr,
            "to": to_addr,
            "effectiveGasPrice": hex(tx.neon_tx.gas_price),
            "gasUsed": hex(res.gas_used),
            "cumulativeGasUsed": hex(res.sum_gas_used),
            "contractAddress": contract,
            "status": hex(res.status),
            "logsBloom": u256big_to_hex(res.log_bloom)
        }

        if details != TxReceiptDetail.SolTxList:
            receipt['logs'] = self._filter_event_list(
                tx.neon_tx_res.event_list,
                TxReceiptDetail.to_prop_filter(details)
            )

        if details == TxReceiptDetail.Eth:
            return receipt

        inner_idx = None if tx.neon_tx_res.sol_inner_ix_idx is None else hex(res.sol_inner_ix_idx)
        receipt.update({
            'solanaBlockHash': base58.b58encode(hex_to_bytes(res.block_hash)).decode('utf-8'),
            'solanaCompleteTransactionHash': tx.neon_tx_res.sol_sig,
            'solanaCompleteInstructionIndex': hex(tx.neon_tx_res.sol_ix_idx),
            'solanaCompleteInnerInstructionIndex': inner_idx,
            'neonRawTransaction': '0x' + tx.neon_tx.as_raw_tx().hex(),
            'neonIsCompleted': res.is_completed,
            'neonIsCanceled': res.is_canceled
        })

        if details != TxReceiptDetail.SolTxList:
            return receipt

        self._fill_sol_tx_info_list(tx, receipt)
        return receipt

    def _fill_sol_tx_info_list(self, tx: NeonTxReceiptInfo, receipt: Dict[str, Any]) -> None:
        result_tx_list: List[Dict[str, Any]] = list()
        result_cost_list: List[Dict[str, Union[str, int]]] = list()

        receipt['solanaTransactions'] = result_tx_list
        receipt['neonCosts'] = result_cost_list

        sol_neon_ix_list: List[SolNeonIxReceiptInfo] = self._db.get_sol_ix_info_list_by_neon_sig(tx.neon_tx.sig)
        if not len(sol_neon_ix_list):
            LOG.warning(f'Cannot find Solana txs for the NeonTx {tx.neon_tx.sig}')
            return

        sol_alt_ix_list: List[SolAltIxInfo] = self._db.get_sol_alt_tx_list_by_neon_sig(tx.neon_tx.sig)
        full_log_dict: Dict[str, List[Dict[str, Any]]] = self._get_full_log_dict(tx)

        sol_sig = ''
        op_cost = OpCostInfo()
        result_ix_list: List[Dict[str, Any]] = list()
        result_cost_dict: Dict[str, OpCostInfo] = dict()

        def _fill_sol_tx(ix: Union[SolNeonIxReceiptInfo, SolAltIxInfo]):
            tx_cost = ix.sol_tx_cost
            new_op_cost = result_cost_dict.setdefault(tx_cost.operator, OpCostInfo())
            new_op_cost.sol_spent += tx_cost.sol_spent

            new_ix_list: List[Dict[str, Any]] = list()
            result_tx_list.append({
                'solanaTransactionHash': ix.sol_sig,
                'solanaTransactionIsSuccess': ix.is_success,
                'solanaBlockNumber': hex(ix.slot),
                'solanaLamportSpent': hex(tx_cost.sol_spent),
                'solanaOperator': tx_cost.operator,
                'solanaInstructions': new_ix_list,
            })
            return new_ix_list, new_op_cost

        for neon_ix in sol_neon_ix_list:
            if neon_ix.sol_sig != sol_sig:
                sol_sig = neon_ix.sol_sig
                result_ix_list, op_cost = _fill_sol_tx(neon_ix)

            neon_income = neon_ix.neon_tx_ix_gas_used * tx.neon_tx.gas_price
            op_cost.neon_income += neon_income

            result_ix_list.append({
                'solanaProgram': 'NeonEVM',
                'solanaInstructionIndex': hex(neon_ix.sol_ix_idx),
                'solanaInnerInstructionIndex': hex(neon_ix.sol_inner_ix_idx) if neon_ix.sol_inner_ix_idx else None,
                'svmHeapSizeLimit': hex(neon_ix.max_heap_size),
                'svmHeapSizeUsed': hex(neon_ix.used_heap_size),
                'svmCyclesLimit': hex(neon_ix.max_bpf_cycle_cnt),
                'svmCyclesUsed': hex(neon_ix.used_bpf_cycle_cnt),
                'neonInstructionCode': hex(neon_ix.ix_code),
                'neonInstructionName': EvmIxCodeName().get(neon_ix.ix_code),
                'neonStepLimit': hex(neon_ix.neon_step_cnt) if neon_ix.neon_step_cnt else None,
                'neonAlanIncome': hex(neon_income),
                'neonGasUsed': hex(neon_ix.neon_tx_ix_gas_used),
                'neonTotalGasUsed': hex(neon_ix.neon_total_gas_used),
                'neonLogs': full_log_dict.get(neon_ix.str_ident, None),
            })

        sol_sig = ''
        for alt_ix in sol_alt_ix_list:
            if alt_ix.sol_sig != sol_sig:
                sol_sig = alt_ix.sol_sig
                result_ix_list, op_cost = _fill_sol_tx(alt_ix)

            result_ix_list.append({
                'solanaProgram': 'AddressLookupTable',
                'solanaInstructionIndex': hex(alt_ix.sol_ix_idx),
                'solanaInnerInstructionIndex': hex(alt_ix.sol_inner_ix_idx) if alt_ix.sol_inner_ix_idx else None,
                'altInstructionCode': hex(alt_ix.ix_code),
                'altInstructionName': AltIxCodeName().get(alt_ix.ix_code),
                'altAddress': alt_ix.address,
            })

        result_cost_list.extend([{
                'solanaOperator': op,
                'solanaLamportSpent': hex(cost.sol_spent),
                'neonAlanIncome': hex(cost.neon_income)
            }
            for op, cost in result_cost_dict.items()
        ])

    @staticmethod
    def _get_full_log_dict(tx: NeonTxReceiptInfo) -> Dict[str, List[Dict[str, Any]]]:
        full_log_dict: Dict[str, List[Dict[str, Any]]] = dict()
        for event in tx.neon_tx_res.event_list:
            full_log_dict.setdefault(event.str_ident, list()).append(
                event.as_rpc_dict(NeonLogTxEvent.PropFilter.Neon)
            )

        return full_log_dict

    def _get_transaction_receipt(self, neon_tx_hash: str) -> Optional[NeonTxReceiptInfo]:
        neon_sig = self._normalize_tx_id(neon_tx_hash)

        neon_tx_or_error = self._mempool_client.get_pending_tx_by_hash(get_req_id_from_log(), neon_tx_hash)
        if isinstance(neon_tx_or_error, EthereumError):
            raise neon_tx_or_error
        return self._db.get_tx_by_neon_sig(neon_sig)

    def neon_getTransactionReceipt(self, neon_tx_hash: str, details: str = TxReceiptDetail.SolTxList) -> Optional[dict]:
        tx = self._get_transaction_receipt(neon_tx_hash)
        if tx is None:
            return None
        return self._fill_transaction_receipt_answer(tx, TxReceiptDetail.to_type(details))

    @staticmethod
    def eth_accounts() -> [str]:
        storage = KeyStorage()
        account_list = storage.get_list()
        return [a.checksum_address for a in account_list]

    def eth_sign(self, account: str, data: str) -> str:
        address = self._normalize_address(account)
        try:
            data = hex_to_bytes(data)
        except (Exception,):
            raise InvalidParamError(message='data is not hex string')

        account = KeyStorage().get_key(address)
        if not account:
            raise EthereumError(message='unknown account')

        message = str.encode(f'\x19Ethereum Signed Message:\n{len(data)}') + data
        return str(account.private_key.sign_msg(message))

    def eth_signTransaction(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        if 'from' not in tx:
            raise InvalidParamError(message='no sender in transaction')

        sender = tx['from']
        del tx['from']
        sender = self._normalize_address(sender, 'from-address')

        if 'to' in tx:
            tx['to'] = self._normalize_address(tx['to'], 'to-address').checksum_address

        account = KeyStorage().get_key(sender)
        if not account:
            raise EthereumError(message='unknown account')

        if 'nonce' not in tx:
            tx['nonce'] = self.eth_getTransactionCount(sender.address, EthCommit.Pending)

        if 'chainId' not in tx:
            tx['chainId'] = hex(self._chain_id)

        try:
            signed_tx = NeonAccount().sign_transaction(tx, account.private_key)
            raw_tx = signed_tx.rawTransaction.hex()
            neon_tx = NeonTx.from_string(bytearray.fromhex(raw_tx[2:]))

            tx.update({
                'from': sender.checksum_address,
                'hash': neon_tx.hex_tx_sig,
                'r': hex(neon_tx.r),
                's': hex(neon_tx.s),
                'v': hex(neon_tx.v)
            })

            return {
                'raw': raw_tx,
                'tx': tx
            }
        except BaseException as exc:
            LOG.error('Failed on sign transaction', exc_info=exc)
            raise InvalidParamError(message='bad transaction')

    def eth_sendTransaction(self, tx: Dict[str, Any]) -> str:
        tx = self.eth_signTransaction(tx)
        return self.eth_sendRawTransaction(tx['raw'])

    @staticmethod
    def web3_sha3(data: str) -> str:
        try:
            data = hex_to_bytes(data)
        except (Exception,):
            raise InvalidParamError(message='data is not hex string')

        return '0x' + keccak_256(data).hexdigest()

    @staticmethod
    def eth_mining() -> bool:
        return False

    def eth_syncing(self) -> Union[bool, dict]:
        try:
            slots_behind = self._sol_client.get_slots_behind()
            latest_slot = self._db.latest_slot
            first_slot = self._db.earliest_slot

            LOG.debug(f'slots_behind: {slots_behind}, latest_slot: {latest_slot}, first_slot: {first_slot}')
            if (slots_behind == 0) or (slots_behind is None) or (latest_slot is None) or (first_slot is None):
                return False

            return {
                'startingBlock': first_slot,
                'currentBlock': latest_slot,
                'highestBlock': latest_slot + slots_behind
            }
        except (Exception,):
            return False

    def net_peerCount(self) -> str:
        cluster_node_list = self._sol_client.get_cluster_nodes()
        return hex(len(cluster_node_list))

    @staticmethod
    def net_listening() -> bool:
        return False

    @staticmethod
    def _mp_pool_tx(neon_tx_info: NeonTxInfo) -> Dict[str, Any]:
        to_addr = NeonAddress.from_raw(neon_tx_info.to_addr)
        if to_addr:
            to_addr = to_addr.checksum_address

        return {
            'blockHash': '0x' + '0' * 64,
            'blockNumber': None,
            'transactionIndex': None,
            'from': NeonAddress.from_raw(neon_tx_info.addr).checksum_address,
            'gas': hex(neon_tx_info.gas_limit),
            'gasPrice': hex(neon_tx_info.gas_price),
            'hash': neon_tx_info.sig,
            'input': neon_tx_info.calldata,
            'nonce': hex(neon_tx_info.nonce),
            'to': to_addr,
            'value': hex(neon_tx_info.value),
            'chainId': hex(neon_tx_info.chain_id) if neon_tx_info.has_chain_id else None
        }

    def _mp_pool_queue(self, tx_list: List[NeonTxInfo]) -> Dict[str, Any]:
        sender_addr = ''
        sender_pool: Dict[int, Any] = dict()
        sender_pool_dict: Dict[str, Any] = dict()
        for tx in tx_list:
            if sender_addr != tx.addr and len(sender_addr):
                sender_pool_dict[sender_addr] = sender_pool
                sender_pool = dict()

            sender_addr = tx.addr
            sender_pool[tx.nonce] = self._mp_pool_tx(tx)

        if sender_addr:
            sender_pool_dict[sender_addr] = sender_pool

        return sender_pool_dict

    def txpool_content(self) -> Dict[str, Any]:
        result_dict: Dict[str, Any] = dict()

        req_id = get_req_id_from_log()
        content = self._mempool_client.get_content(req_id)

        result_dict['pending'] = self._mp_pool_queue(content.pending_list)
        result_dict['queued'] = self._mp_pool_queue(content.queued_list)
        return result_dict

    def neon_getSolanaTransactionByNeonTransaction(
        self, neon_tx_id: str,
        full: bool = False
    ) -> Union[List[str], List[Optional[Dict[str, Any]]]]:
        neon_sig = self._normalize_tx_id(neon_tx_id)
        alt_sig_list = self._db.get_alt_sig_list_by_neon_sig(neon_sig)
        sol_sig_list = self._db.get_sol_sig_list_by_neon_sig(neon_sig)

        sol_sig_list = alt_sig_list + sol_sig_list
        if not full:
            return sol_sig_list

        sol_tx_list = self._sol_client.get_tx_receipt_list(sol_sig_list, SolCommit.Confirmed)
        for sol_tx in sol_tx_list:
            if sol_tx is None:
                return sol_sig_list
        return sol_sig_list

    def neon_getEvmParams(self) -> Dict[str, str]:
        """Returns map of Neon-EVM parameters"""
        evm_param_dict = self._evm_cfg.evm_param_dict
        evm_param_dict['NEON_EVM_ID'] = EVM_PROGRAM_ID_STR
        return evm_param_dict

    def is_allowed_api(self, method_name: str) -> bool:
        for prefix in ('eth_', 'net_', 'web3_', 'neon_', 'txpool_'):
            if method_name.startswith(prefix):
                break
        else:
            return False

        always_allowed_method_set = {
            "neon_proxyVersion",
            "eth_chainId",
            "neon_cliVersion",
            "neon_evmVersion",
            "neon_solanaVersion",
            "neon_versions",
            "neon_getEvmParams",
            "net_version",
            "web3_clientVersion"
        }

        if method_name in always_allowed_method_set:
            return True

        if not self._data.is_evm_compatible:
            raise EthereumError(
                f'Neon Proxy {self.neon_proxyVersion()} is not compatible with '
                f'Neon EVM {self.web3_clientVersion()}'
            )

        if method_name == 'eth_sendRawTransaction':
            return self._cfg.enable_send_tx_api

        private_method_set = {
            "eth_accounts",
            "eth_sign",
            "eth_sendTransaction",
            "eth_signTransaction",
            "txpool_content"
        }

        if method_name in private_method_set:
            if (not self._cfg.enable_send_tx_api) or (not self._cfg.enable_private_api):
                return False

        return True
