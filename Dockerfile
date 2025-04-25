ARG NEON_EVM_COMMIT
ARG DOCKERHUB_ORG_NAME

FROM ${DOCKERHUB_ORG_NAME}/evm_loader:${NEON_EVM_COMMIT} AS spl

FROM ubuntu:24.04

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
            git \
            cargo \
            postgresql-client && \
    rm -rf /var/lib/apt/lists/*

COPY ./requirements.txt .

RUN python3 -m venv .venv && \
    . .venv/bin/activate && \
    pip install uv && \
    uv pip install --upgrade pip && \
    uv pip install -r requirements.txt

COPY --from=spl \
    /root/.local/share/solana/install/active_release/bin/solana \
    /root/.local/share/solana/install/active_release/bin/solana-keygen \
    /cli/bin/

COPY --from=spl \
    /root/.local/share/solana/install/active_release/bin/spl-token \
    /opt/create-test-accounts.sh \
    /opt/evm_loader-keypair.json \
    /spl/bin/
RUN chmod +x /spl/bin/create-test-accounts.sh

# TODO: rename
COPY --from=spl /opt/neon-api /spl/bin/neon-core-api

COPY test-operator-keypairs/id.json /root/.config/solana/

COPY . .

# disable Robyn command line parser
COPY patch/disable_robyn_argument_parser.py .venv/lib64/python3.10/site-packages/robyn/argument_parser.py

ARG PROXY_REVISION
RUN sed -i 's/NEON_PROXY_REVISION_TO_BE_REPLACED/'${PROXY_REVISION}'/g' ./common/config/constants.py
RUN ln -s /opt/neon-proxy/proxy_client/proxy-cli /opt/neon-proxy/proxy-cli
RUN ln -s /opt/neon-proxy/proxy_client/run-core-api /opt/neon-proxy/run-core-api
RUN ln -s /opt/neon-proxy/indexer_client/indexer-cli /opt/neon-proxy/indexer-cli

# for backward compatibility
RUN ln -s /opt/neon-proxy/proxy_client/proxy-cli /opt/neon-proxy/proxy-cli.sh

ENV PATH /venv/bin:/cli/bin/:/spl/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

EXPOSE 9090/tcp
ENTRYPOINT [ "proxy/run-proxy.sh" ]
