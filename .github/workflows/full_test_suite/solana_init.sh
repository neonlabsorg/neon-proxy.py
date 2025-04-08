#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Script needs to be run as root. Re-executing with sudo..."
    exec sudo /bin/bash "$0" "$@"
fi

# Install docker
apt-get remove docker docker-engine docker.io containerd runc
apt-get update
apt-get -y install ca-certificates curl gnupg lsb-release pbzip2
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update


# Tune instance for Solana requirements(must be applied before start services)
bash -c "cat >/etc/sysctl.d/20-solana-udp-buffers.conf<<EOF
# Increase UDP buffer size
net.core.rmem_default = 134217728
net.core.rmem_max = 134217728
net.core.wmem_default = 134217728
net.core.wmem_max = 134217728
EOF"
sysctl -p /etc/sysctl.d/20-solana-udp-buffers.conf

bash -c "cat >/etc/sysctl.d/20-solana-mmaps.conf<<EOF
# Increase memory mapped files limit
vm.max_map_count = 1000000
EOF"
sysctl -p /etc/sysctl.d/20-solana-mmaps.conf

bash -c "cat >/etc/security/limits.d/90-solana-nofiles.conf<<EOF
# Increase process file descriptor count limit
* - nofile 1000000
EOF"


# Install docker-compose
apt-get -y install docker-ce docker-ce-cli containerd.io
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

echo "Print envs for debug"
echo "REVISION=$REVISION"
echo "NEON_EVM_COMMIT=$NEON_EVM_COMMIT"
echo "FAUCET_COMMIT=$FAUCET_COMMIT"
echo "DOCKERHUB_ORG_NAME=$DOCKERHUB_ORG_NAME"
echo "DEVNET_SOLANA_URL=$DEVNET_SOLANA_URL"

# Set required environment variables
bash -c "cat > /root/.bashrc <<- EOF
export REVISION=$REVISION
export NEON_EVM_COMMIT=$NEON_EVM_COMMIT
export FAUCET_COMMIT=$FAUCET_COMMIT
export DOCKERHUB_ORG_NAME=$DOCKERHUB_ORG_NAME
export DEVNET_SOLANA_URL=$DEVNET_SOLANA_URL
EOF"

# Receive docker-compose file and create override file
cd /tmp

whoami
ls -la /tmp
pwd

cat > solana-docker-compose-ci.override.yml<<EOF
version: "3"

services:
  solana:
    environment:
      DEVNET_SOLANA_URL: $DEVNET_SOLANA_URL
    ports:
      - "8899:8899"
      - "9900:9900"
      - "8900:8900"
      - "8001:8001"
      - "8001-8009:8001-8009/udp"
  
  nginx:
    image: nginx:latest
    ports:
      - "8080:8080"
    expose:
      - 8080
    hostname: nginx
    container_name: nginx
    volumes:
        - /var/log/nginx:/var/log/nginx
        - /tmp/nginx.conf:/etc/nginx/nginx.conf
    networks:
      - net
    entrypoint: >
      /bin/sh -c "echo 'Nginx Configuration:' && cat /etc/nginx/nginx.conf && nginx -g 'daemon off;'"
EOF

# wake up Solana
bash -c docker-compose -f docker-compose-ci.yml -f solana-docker-compose-ci.override.yml pull nginx solana
bash -c docker-compose -f docker-compose-ci.yml -f solana-docker-compose-ci.override.yml up -d nginx solana
