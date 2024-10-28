from common.solana_rpc.transaction_error_parser import SolTxErrorParser

class NeonTxErrorParser(SolTxErrorParser):
    code: int
    message: str

    @cached_method
    def check_if_require_resize_iter(self) -> bool:
        if self.check_if_preprocessed_error():
            if self._get_tx_ix_error() == SolRpcTxIxFieldErrorCode.ProgramFailedToComplete:
                return True

        log_list = self._get_evm_log_list()
        return any(log_rec.find(self._require_resize_iter_msg) != -1 for log_rec in reversed(log_list))

    @cached_method
    def check_if_neon_account_already_exists(self) -> bool:
        evm_log_list = self._get_evm_log_list()
        if any(self._create_neon_acct_re.match(log_rec) for log_rec in evm_log_list):
            return True

        raw_log_list = self._get_log_list()
        return any(self._create_acct_re.match(log_rec) for log_rec in raw_log_list)

    @cached_method
    def check_if_already_finalized(self) -> bool:
        log_list = self._get_evm_log_list()
        return any(log_rec == self._already_finalized_msg for log_rec in log_list)

    @cached_method
    def get_nonce_error(self) -> tuple[int, int] | None:
        log_list = self._get_evm_log_list()
        for log_rec in log_list:
            if match := self._nonce_re.match(log_rec):
                state_tx_cnt, tx_nonce = match[1], match[2]
                return int(state_tx_cnt), int(tx_nonce)
        return None

    @cached_method
    def get_out_of_gas_error(self) -> tuple[int, int] | None:
        log_list = self._get_evm_log_list()
        for log_rec in log_list:
            if match := self._out_of_gas_re.match(log_rec):
                has_gas_limit, req_gas_limit = match[1], match[2]
                return int(has_gas_limit), int(req_gas_limit)
        return None

    @cached_method
    def _get_evm_log_list(self) -> tuple[str, ...]:
        if isinstance(self._receipt, SolRpcSendTxErrorInfo):
            rpc_meta = self._receipt
        elif isinstance(self._receipt, SolRpcTxSlotInfo):
            rpc_meta = self._receipt.transaction.meta
        else:
            return tuple()

        log_list: list[str] = list()
        log_state = SolTxLogTreeDecoder.decode(self._tx.message, rpc_meta, self._tx.account_key_list)
        # TODO: add EvmLogDecoder, add parsing, error, and return that transaction is finalized
        for log_info in log_state.log_list:
            if log_info.prog_id == NeonProg.ID:
                log_list.extend(log_info.log_msg_list())
            for inner_log_info in log_info.inner_log_list:
                if inner_log_info.prog_id == NeonProg.ID:
                    log_list.extend(inner_log_info.log_msg_list())
        return tuple(log_list)

# class NeonTxErrorInvalidTagParser(NeonTxErrorParser):
#
# class NeonTxErrorOutOfGasParser(NeonTxErrorParser):
#
# class NeonTxErrorInvalidNonceParser(NeonTxErrorParser):