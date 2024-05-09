#!/bin/bash
COMPONENT=Proxy
echo \{\"level\": \"INFO\", \"date\": \"$(date "+%F %X.%3N")\", \"module\": \"$(basename "$0"):${LINENO}\"\}, \"process\": $!, \"message\": \"Start ${COMPONENT} service\"\}

if [ -z "$SOLANA_URL" ]; then
  echo \{\"level\": \"INFO\", \"date\": \"$(date "+%F %X.%3N")\", \"module\": \"$(basename "$0"):${LINENO}\"\}, \"process\": $!, \"message\": \"SOLANA_URL is not set\"\}
  exit 1
fi

solana config set -u $SOLANA_URL
ln -s /opt/neon-proxy/test-operator-keypairs/id?*.json /root/.config/solana/

/spl/bin/create-test-accounts.sh 1

export NUM_ACCOUNTS=30
/spl/bin/create-test-accounts.sh $NUM_ACCOUNTS &

proxy/run-proxy.sh
