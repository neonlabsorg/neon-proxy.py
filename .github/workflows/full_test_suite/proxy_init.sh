#!/bin/bash


# Install docker
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get update
sudo apt-get -y install ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io

sudo apt-get -y install pbzip2

# Install docker-compose
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose


cd /tmp

ls -la /tmp
pwd

echo "Print envs for debug"
echo "REVISION=$REVISION"
echo "SOLANA_URL=$SOLANA_URL"
echo "SOLANA_WS_URL=$SOLANA_WS_URL"
echo "NEON_EVM_COMMIT=$NEON_EVM_COMMIT"
echo "FAUCET_COMMIT=$FAUCET_COMMIT"
echo "CI_PP_SOLANA_URL=$CI_PP_SOLANA_URL"
echo "DOCKERHUB_ORG_NAME=$DOCKERHUB_ORG_NAME"
echo "DEVNET_SOLANA_URL=$DEVNET_SOLANA_URL"

# Set required environment variables
sudo cat > /root/.bashrc <<- EOM
export REVISION=$REVISION
export SOLANA_URL=$SOLANA_URL
export SOLANA_WS_URL=$SOLANA_WS_URL
export NEON_EVM_COMMIT=$NEON_EVM_COMMIT
export FAUCET_COMMIT=$FAUCET_COMMIT
export CI_PP_SOLANA_URL=$CI_PP_SOLANA_URL
export DOCKERHUB_ORG_NAME=$DOCKERHUB_ORG_NAME
export DEVNET_SOLANA_URL=$DEVNET_SOLANA_URL
EOM

# Generate docker-compose override file
cat > proxy-docker-compose-ci.override.yml <<EOF
version: "3"

services:
  solana:
    container_name: solana
    environment:
      DEVNET_SOLANA_URL: $DEVNET_SOLANA_URL
    healthcheck:
      test: [ CMD-SHELL, "echo done" ]
    entrypoint: "/usr/bin/sleep 10000"

  proxy:
    container_name: proxy
    environment:
      SOLANA_URL: $SOLANA_URL
      SOLANA_WS_URL: $SOLANA_WS_URL
    ports:
      - "9090:9090"

  faucet:
    container_name: faucet
    environment:
      SOLANA_URL: $SOLANA_URL
    ports:
      - "3333:3333"

  indexer:
    container_name: indexer
    environment:
      SOLANA_URL: $SOLANA_URL
      SOLANA_WS_URL: $SOLANA_WS_URL

  postgres:
    container_name: postgres

  dbcreation:
    container_name: dbcreation
EOF


# Get list of services
SERVICES=$(/bin/bash -c sudo docker-compose -f docker-compose-ci.yml -f proxy-docker-compose-ci.override.yml config --services | grep -vP "solana|gas_tank|neon_test_invoke_program_loader")

# Pull latest versions
/bin/bash -c sudo docker-compose -f docker-compose-ci.yml -f proxy-docker-compose-ci.override.yml pull $SERVICES


function wait_service() {
  local SERVICE=$1
  local URL=$2
  local DATA=$3
  local RESULT=$4
  local SHOW_DOCKER_LOGS_IF_FAIL=$5

  # Max attepts is 100 (each for 2 seconds)
  local MAX_COUNT=100
  local CURRENT_ATTEMPT=1

  local CHECK_COMMAND="curl $URL -s -X POST -H 'Content-Type: application/json' -d '$DATA' | grep -cF '$RESULT'"

  while [[ $CURRENT_ATTEMPT -lt $MAX_COUNT ]]
  do
    echo "$SERVICE attempt: $CURRENT_ATTEMPT" 1>&2
    local CHECK_COMMAND_RESULT=$(eval $CHECK_COMMAND)
    echo $CHECK_COMMAND_RESULT >> /tmp/output.txt
    if [[ "$CHECK_COMMAND_RESULT" == "1" ]]; then
      echo "$SERVICE is up" 1>&2
      break
    fi

    ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
    sleep 2
  done;

  if [[ $CURRENT_ATTEMPT -eq $MAX_COUNT ]]; then
      echo ""
      echo "Service $SERVICE failed to respond as expected after $MAX_COUNT attempts."
      if [[ "$SHOW_DOCKER_LOGS_IF_FAIL" == "show_docker_logs_if_fail" ]]; then
        docker ps -a
        docker ps -a --format "{{.ID}} {{.Names}}" | while read -r id name; do
          echo ""
          echo "Logs for container: $name"
          docker logs "$id"
          echo ""
        done
      fi
      exit 1
  fi
}

# Check if Solana is available
SOLANA_DATA='{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
SOLANA_RESULT='"ok"'
wait_service "solana" $SOLANA_URL $SOLANA_DATA $SOLANA_RESULT


# Up all services
/bin/bash -c sudo docker-compose -f docker-compose-ci.yml -f proxy-docker-compose-ci.override.yml up -d $SERVICES


# Check if Proxy is available
PROXY_URL="http://localhost:9090/solana"
PROXY_DATA='{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest", false],"id":1}'
PROXY_RESULT='"number"'

wait_service "proxy" $PROXY_URL "$PROXY_DATA" $PROXY_RESULT "show_docker_logs_if_fail"

# /bin/bash -c sudo docker rm -f solana
