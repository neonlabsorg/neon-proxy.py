from __future__ import annotations

import math
import os
import sys
from decimal import Decimal
from typing import Optional, Dict

from eth_account import Account
from eth_typing import Address
from web3 import Web3
from web3.eth import Eth
from web3.types import Wei

from common_neon import NeonAccount
from .secret import get_key_info_list, get_token_name, get_token_name_list


class NeonHandler:
    _percent = "PERCENT"
    _percent_postfix = "_PERCENT"

    def _proxy(self, chain_id: int) -> Eth:
        proxy = self._proxy_dict.get(chain_id)
        if proxy:
            return proxy

        proxy_url = os.environ.get("PROXY_URL", "http://localhost:9090/solana")
        # TODO: fix chain-id URL
        # token_name = get_token_name(chain_id)
        # proxy_url = proxy_url + '/' + token_name

        proxy = Web3(Web3.HTTPProvider(proxy_url)).eth
        self._proxy_dict[chain_id] = proxy
        return proxy

    def _gas_price(self, chain_id: int) -> Wei:
        gas_price = self._gas_price_dict.get(chain_id)
        if gas_price:
            return gas_price

        gas_price = self._proxy(chain_id).gas_price
        self._gas_price_dict[chain_id] = gas_price
        return gas_price

    def _create_tx(self, from_addr: NeonAccount, to_addr: Address, amount: int) -> dict:
        signer = Account.from_key(from_addr.private_key)
        tx = dict(
            chainId=from_addr.chain_id,
            gasPrice=self._gas_price(from_addr.chain_id),
            nonce=self._proxy(from_addr.chain_id).get_transaction_count(
                signer.address, "pending"
            ),
            to=to_addr,
            value=amount,
        )
        tx["from"] = signer.address
        return tx

    def _send_tx(
        self, from_addr: NeonAccount, to_addr: Address, amount: Wei, gas: int
    ) -> None:
        signer = Account.from_key(from_addr.private_key)
        tx = self._create_tx(from_addr, to_addr, amount)
        tx["gas"] = gas

        proxy = self._proxy(from_addr.chain_id)
        tx_signed = proxy.account.sign_transaction(tx, signer.key)
        neon_tx_hash = proxy.send_raw_transaction(tx_signed.rawTransaction)
        amount = self._get_neon_amount(amount)
        token_name = get_token_name(from_addr.chain_id)
        to_addr = NeonAccount.from_raw(to_addr, from_addr.chain_id, neon_tx_hash=)

        print(
            f"send {amount:,.18} {token_name} "
            f"from {from_addr.to_checksum_address()} "
            f"to {to_addr.to_checksum_address()}: "
            f"{tx_hash.hex()}"
        )

    def _estimate_tx(self, from_addr: NeonAccount, to_addr: Address) -> int:
        tx = self._create_tx(from_addr, to_addr, 1)
        return self._proxy(from_addr.chain_id).estimate_gas(tx)

    def _withdraw_neon(self, args) -> None:
        sent_amount_dict: Dict[str, int] = dict()
        for neon_addr, balance in neon_acct_dict.items():
            if balance <= 0:
                continue
            token_name = get_token_name(neon_addr.chain_id)
            if a_type not in {self._percent, token_name}:
                continue

            gas = self._estimate_tx(neon_addr, dest_addr)
            tx_cost = gas * self._gas_price(neon_addr.chain_id)
            balance -= tx_cost
            if balance <= 0:
                continue

            balance = min(balance, amount)
            self._send_tx(neon_addr, dest_addr, balance, gas)

            amount -= balance
            sent_amount_dict[token_name] = sent_amount_dict.get(token_name, 0) + balance

            if amount <= 0:
                break

        dest_addr = NeonAccount.from_raw(dest_addr, 0, neon_tx_hash=)
        for token_name, balance in sent_amount_dict.items():
            balance = self._get_neon_amount(balance)
            print(
                f"successfully send {balance:,.18} {token_name} to {dest_addr.to_checksum_address()}"
            )
