ARG NEON_EVM_COMMIT
ARG DOCKERHUB_ORG_NAME

FROM ${DOCKERHUB_ORG_NAME}/evm_loader:${NEON_EVM_COMMIT} AS spl
FROM ${DOCKERHUB_ORG_NAME}/neon_test_invoke_program:develop AS neon_test_invoke_program

FROM ubuntu:22.04

WORKDIR /opt/neon-proxy

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC \
        apt install -y \
            software-properties-common \
            openssl \
            curl \
            libuv1 \
            netcat-openbsd \
            ca-certificates \
            python3-pip \
            python3-venv \
            postgresql-client && \
    rm -rf /var/lib/apt/lists/*

ENV SSL_URL=http://security.ubuntu.com/ubuntu/pool/main/o/openssl
ENV SSL_VER=1.1.1f-1ubuntu2

RUN \
    curl ${SSL_URL}/libssl1.1_${SSL_VER}_amd64.deb -O && \
    curl ${SSL_URL}/openssl_${SSL_VER}_amd64.deb -O && \
    apt install -y --allow-downgrades \
        ./libssl1.1_${SSL_VER}_amd64.deb \
        ./openssl_${SSL_VER}_amd64.deb && \
    rm -f \
        ./libssl1.1_${SSL_VER}_amd64.deb \
        ./openssl_${SSL_VER}_amd64.deb

COPY ./requirements.txt .

RUN pip3 install uv && \
    uv venv && \
    uv pip install --upgrade pip && \
    uv pip install -r requirements.txt

COPY --from=spl \
    /root/.local/share/solana/install/active_release/bin/solana \
    /root/.local/share/solana/install/active_release/bin/solana-keygen \
    /cli/bin/

COPY --from=spl \
    /root/.local/share/solana/install/active_release/bin/spl-token \
    /opt/create-test-accounts.sh \
    /opt/neon-cli \
    /opt/evm_loader-keypair.json \
    /spl/bin/
RUN chmod +x /spl/bin/create-test-accounts.sh

# TODO: rename
COPY --from=spl /opt/neon-api /spl/bin/neon-core-api

COPY --from=spl \
    /opt/solidity/ \
    ./contracts/

COPY --from=neon_test_invoke_program \
    /opt/neon_test_invoke_program-keypair.json \
    /spl/bin/

COPY test-operator-keypairs/id.json /root/.config/solana/

COPY . .
ARG PROXY_REVISION
RUN sed -i 's/NEON_PROXY_REVISION_TO_BE_REPLACED/'"$PROXY_REVISION"'/g' ./common/config/constants.py

ENV PATH /venv/bin:/cli/bin/:/spl/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

EXPOSE 9090/tcp
ENTRYPOINT [ "proxy/run-proxy.sh" ]
