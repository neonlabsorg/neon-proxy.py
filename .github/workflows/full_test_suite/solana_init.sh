#!/bin/bash


# Install docker
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get update
sudo apt-get -y install ca-certificates curl gnupg lsb-release pbzip2
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update


# Tune instance for Solana requirements(must be applied before start services)
sudo bash -c "cat >/etc/sysctl.d/20-solana-udp-buffers.conf<<EOF
# Increase UDP buffer size
net.core.rmem_default = 134217728
net.core.rmem_max = 134217728
net.core.wmem_default = 134217728
net.core.wmem_max = 134217728
EOF"
sysctl -p /etc/sysctl.d/20-solana-udp-buffers.conf

sudo bash -c "cat >/etc/sysctl.d/20-solana-mmaps.conf<<EOF
# Increase memory mapped files limit
vm.max_map_count = 1000000
EOF"
sysctl -p /etc/sysctl.d/20-solana-mmaps.conf

bash -c "cat >/etc/security/limits.d/90-solana-nofiles.conf<<EOF
# Increase process file descriptor count limit
* - nofile 1000000
EOF"


# Install docker-compose
sudo apt-get -y install docker-ce docker-ce-cli containerd.io
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

export REVISION=${proxy_image_tag}
export NEON_EVM_COMMIT=${neon_evm_commit}
export FAUCET_COMMIT=${faucet_model_commit}
export DOCKERHUB_ORG_NAME=${dockerhub_org_name}

# Receive docker-compose file and create override file
cd /tmp

cat > docker-compose-ci.override.yml<<EOF
version: "3"

services:
  solana:
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
docker-compose -f docker-compose-ci.yml -f docker-compose-ci.override.yml pull nginx solana
docker-compose -f docker-compose-ci.yml -f docker-compose-ci.override.yml up -d nginx solana
