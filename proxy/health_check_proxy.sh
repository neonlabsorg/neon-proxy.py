#!/bin/bash

HAS_BLOCK=`curl --location --request POST 'http://proxy:9090/solana' \
--header 'Content-Type: application/json' \
--data-raw '{"jsonrpc":"2.0", "method":"eth_blockNumber", "id":1 }' 2> /dev/null | grep -cF '"result"'`

if [[ "$HAS_BLOCK" == "1" ]]; then
  exit 0
fi
exit 1
