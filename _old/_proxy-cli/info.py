from __future__ import annotations

import sys
import json
import base58

from decimal import Decimal
from typing import Dict, List, Any

from common_neon import NeonAccount
from common_neon.solana import SolInteractor
from common_neon.solana import SolPubKey
from common_neon.config import Config

from proxy.neon_core_api.neon_client import NeonClient
from proxy.neon_core_api.neon_layouts import HolderStatus

from .secret import get_key_info_list, get_res_info_list, get_token_name


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


class InfoHandler:
    def __init__(self):
        self._cfg = Config()
        self._sol_client = SolInteractor(self._cfg)
        self._neon_client = NeonClient(self._cfg)
        self.command = 'info'

    @staticmethod
    def init_args_parser(parsers) -> InfoHandler:
        h = InfoHandler()
        h.root_parser = parsers.add_parser(h.command)
        h.sub_parser = h.root_parser.add_subparsers(title='command', dest='subcommand', description='valid commands')
        h.holder_parser = h.sub_parser.add_parser('holder-accounts')
        h.solana_pk_parser = h.sub_parser.add_parser('solana-private-keys')
        h.neon_pk_parser = h.sub_parser.add_parser('neon-private-keys')
        h.full_parser = h.sub_parser.add_parser('full')
        return h

    def execute(self, args) -> None:
        if args.subcommand == 'holder-accounts':
            self._holder_accounts_info(args)
        elif args.subcommand == 'solana-private-keys':
            self._sol_client_private_key_info(args)
        elif args.subcommand == 'neon-private-keys':
            self._neon_private_key_info(args)
        elif args.subcommand == 'full' or args.subcommand is None:
            self._all_info(args)
        else:
            print(f'Unknown command {args.subcommand} for info', file=sys.stderr)
            return

    def _holder_accounts_info(self, _) -> None:
        res_info_list = get_res_info_list()
        for res_info in res_info_list:
            acct_info = self._sol_client.get_account_info(res_info.holder_address)
            if acct_info is None:
                continue

            balance = Decimal(acct_info.lamports) / 1_000_000_000
            holder_address = str(res_info.holder_address)
            print(f'{ holder_address }\t { str(res_info) }\t { balance:,.9f} SOL')

    @staticmethod
    def _solana_private_key_info(_) -> None:
        key_info_list = get_key_info_list()
        for key_info in key_info_list:
            address = str(key_info.public_key)
            private = base58.b58encode(key_info.private_key).decode('utf-8')

            print(f'{ address }\t { private }')

    @staticmethod
    def _neon_private_key_info(_) -> None:
        key_info_list = get_key_info_list()
        for key_info in key_info_list:
            for neon_acct in key_info.neon_account_dict.values():
                print(
                    f'{ get_token_name(neon_acct.chain_id) }\t '
                    f'{ neon_acct.neon_address.to_checksum_address() }\t '
                    f'{ str(neon_acct.neon_address.private_key) }'
                )
