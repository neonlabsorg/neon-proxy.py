    ---- Prepare stage
--     CREATE OR REPLACE FUNCTION does_table_have_column(t_name TEXT, c_name TEXT)
--         RETURNS BOOLEAN
--         LANGUAGE plpgsql
--     AS
--     $$
--     DECLARE
--         column_count INT;
--     BEGIN
--         SELECT COUNT(t.column_name)
--           INTO column_count
--           FROM information_schema.columns AS t
--          WHERE t.table_name = t_name AND t.column_name=c_name;
--         RETURN column_count > 0;
--     END;
--     $$;
--
--     CREATE OR REPLACE FUNCTION does_table_exist(t_name TEXT)
--         RETURNS BOOLEAN
--         LANGUAGE plpgsql
--     AS
--     $$
--     DECLARE
--         column_count INT;
--     BEGIN
--         SELECT COUNT(t.column_name)
--           INTO column_count
--           FROM information_schema.columns AS t
--          WHERE t.table_name = t_name;
--         RETURN column_count > 0;
--     END;
--     $$;

    --- Initialize stage

CREATE TABLE IF NOT EXISTS constants (
    key TEXT UNIQUE,
    value BYTEA
);

CREATE TABLE IF NOT EXISTS gas_less_accounts (
    address TEXT,
    contract TEXT,
    nonce BIGINT,
    nonce_done BIGINT,
    gas_limit BIGINT,
    block_slot BIGINT,
    neon_sig TEXT
);
ALTER TABLE gas_less_accounts
    ADD COLUMN IF NOT EXISTS nonce_done BIGINT,
    ADD COLUMN IF NOT EXISTS gas_limit BIGINT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_gas_less_accounts ON gas_less_accounts(address, contract, nonce);

CREATE TABLE IF NOT EXISTS gas_less_usages(
    address TEXT,
    block_slot BIGINT,
    neon_sig TEXT,
    nonce BIGINT,
    to_addr TEXT,
    neon_total_gas_usage BIGINT,
    operator TEXT
);
CREATE INDEX IF NOT EXISTS idx_gas_less_usages ON gas_less_usages(address);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gas_less_usages_neon_sig ON gas_less_usages(neon_sig);
CREATE INDEX IF NOT EXISTS idx_gas_less_block_lost ON gas_less_usages(block_slot);

CREATE TABLE IF NOT EXISTS solana_blocks (
    block_slot BIGINT,
    block_hash TEXT,
    block_time BIGINT,
    parent_block_slot BIGINT,
    is_finalized BOOL,
    is_active BOOL,
    cu_price_percentiles INT ARRAY
);
ALTER TABLE solana_blocks
    ADD COLUMN IF NOT EXISTS cu_price_percentiles INT ARRAY;
CREATE UNIQUE INDEX IF NOT EXISTS idx_solana_blocks_slot ON solana_blocks(block_slot);
CREATE INDEX IF NOT EXISTS idx_solana_blocks_hash ON solana_blocks(block_hash);
CREATE INDEX IF NOT EXISTS idx_solana_blocks_slot_active ON solana_blocks(block_slot, is_active);

CREATE TABLE IF NOT EXISTS neon_block_fees (
    block_slot BIGINT,
    chain_id BIGINT,
    base_fee TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_neon_block_fees ON neon_block_fees(block_slot, chain_id);

CREATE TABLE IF NOT EXISTS neon_transaction_logs (
    address TEXT,
    block_slot BIGINT,

    tx_hash TEXT,
    tx_idx INT,
    tx_log_idx INT,
    log_idx INT,

    event_level INT,
    event_order INT,

    sol_sig TEXT,
    idx INT,
    inner_idx INT,

    log_topic1 TEXT,
    log_topic2 TEXT,
    log_topic3 TEXT,
    log_topic4 TEXT,
    log_topic_cnt INT,

    log_data TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_neon_transaction_logs_block_tx_log ON neon_transaction_logs(block_slot, tx_hash, tx_log_idx);
CREATE INDEX IF NOT EXISTS idx_neon_transaction_logs_address ON neon_transaction_logs(address);
CREATE INDEX IF NOT EXISTS idx_neon_transaction_logs_slot ON neon_transaction_logs(block_slot);
CREATE INDEX IF NOT EXISTS idx_neon_transaction_logs_topic1 ON neon_transaction_logs(log_topic1);
CREATE INDEX IF NOT EXISTS idx_neon_transaction_logs_topic2 ON neon_transaction_logs(log_topic2);
CREATE INDEX IF NOT EXISTS idx_neon_transaction_logs_topic3 ON neon_transaction_logs(log_topic3);
CREATE INDEX IF NOT EXISTS idx_neon_transaction_logs_topic4 ON neon_transaction_logs(log_topic4);

CREATE TABLE IF NOT EXISTS solana_neon_transactions (
    sol_sig TEXT,
    block_slot BIGINT,
    idx INT,
    inner_idx INT,
    ix_code INT,
    is_success BOOLEAN,

    neon_sig TEXT,
    neon_miner TEXT,
    neon_step_cnt INT,
    neon_total_step_cnt INT,
    neon_gas_used BIGINT,
    neon_total_gas_used BIGINT,

    max_heap_size INT,
    used_heap_size INT,

    max_bpf_cycle_cnt INT,
    used_bpf_cycle_cnt INT
);

ALTER TABLE solana_neon_transactions
    ADD COLUMN IF NOT EXISTS neon_total_step_cnt INT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS neon_miner TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_solana_neon_transactions_neon_sol_idx_inner ON solana_neon_transactions(sol_sig, block_slot, idx, inner_idx);
CREATE INDEX IF NOT EXISTS idx_solana_neon_transactions_neon_sig ON solana_neon_transactions(neon_sig, block_slot);
CREATE INDEX IF NOT EXISTS idx_solana_neon_transactions_neon_block ON solana_neon_transactions(block_slot);

CREATE TABLE IF NOT EXISTS neon_transactions (
    neon_sig TEXT,
    tx_type INT,
    from_addr TEXT,

    sol_sig TEXT,
    sol_ix_idx INT,
    sol_ix_inner_idx INT,
    block_slot BIGINT,
    tx_idx INT,

    chain_id INT DEFAULT 0,
    nonce TEXT,
    gas_price TEXT,
    max_fee_per_gas TEXT,
    max_priority_fee_per_gas TEXT,
    priority_fee_spent TEXT,
    gas_limit TEXT,
    value TEXT,
    gas_used TEXT,
    sum_gas_used TEXT,

    to_addr TEXT,
    contract TEXT,

    status TEXT,
    is_canceled BOOLEAN,
    is_completed BOOLEAN,

    v TEXT,
    r TEXT,
    s TEXT,

    calldata TEXT,
    logs BYTEA
);

ALTER TABLE neon_transactions
    ADD COLUMN IF NOT EXISTS chain_id INT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_fee_per_gas TEXT,
    ADD COLUMN IF NOT EXISTS max_priority_fee_per_gas TEXT,
    ADD COLUMN IF NOT EXISTS priority_fee_spent TEXT;

CREATE INDEX IF NOT EXISTS idx_neon_transactions_sol_sig_block ON neon_transactions(sol_sig, block_slot);
CREATE UNIQUE INDEX IF NOT EXISTS idx_neon_transactions_neon_sig_block ON neon_transactions(neon_sig, block_slot);
DROP INDEX IF EXISTS idx_neon_transactions_sender_nonce_block;
CREATE INDEX IF NOT EXISTS idx_neon_transactions_sender_nonce_v_block ON neon_transactions(from_addr, nonce, v, block_slot);
CREATE INDEX IF NOT EXISTS idx_neon_transactions_slot_tx_idx ON neon_transactions(block_slot, tx_idx);


CREATE TABLE IF NOT EXISTS solana_alt_transactions (
    sol_sig TEXT,
    block_slot BIGINT,
    idx INT,
    inner_idx INT DEFAULT -1,
    ix_code INT,
    alt_address TEXT,
    is_success BOOLEAN,

    neon_sig TEXT
);
ALTER TABLE solana_alt_transactions ADD COLUMN IF NOT EXISTS inner_idx INT DEFAULT -1;
DROP INDEX IF EXISTS idx_solana_alt_transactions_sig_slot_idx;
CREATE UNIQUE INDEX IF NOT EXISTS idx_solana_alt_transactions_sig_slot_idx_inner ON solana_alt_transactions(sol_sig, block_slot, idx, inner_idx);
CREATE INDEX IF NOT EXISTS idx_solana_alt_transactions_neon_sig ON solana_alt_transactions(neon_sig, block_slot);
CREATE INDEX IF NOT EXISTS idx_solana_alt_transactions_slot ON solana_alt_transactions(block_slot);

CREATE TABLE IF NOT EXISTS solana_transaction_costs (
    sol_sig TEXT,
    block_slot BIGINT,

    operator TEXT,
    sol_spent BIGINT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_solana_transaction_costs_sig ON solana_transaction_costs(sol_sig, block_slot);
CREATE INDEX IF NOT EXISTS idx_solana_transaction_costs_slot ON solana_transaction_costs(block_slot);
CREATE INDEX IF NOT EXISTS idx_solana_transaction_costs_operator ON solana_transaction_costs(operator, block_slot);

CREATE TABLE IF NOT EXISTS solana_transaction_signatures (
    slot  BIGINT,
    signature   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_solana_transaction_signatures_sig ON solana_transaction_signatures(block_slot);

CREATE TABLE IF NOT EXISTS stuck_neon_holders (
    block_slot BIGINT,
    json_data_list TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_stuck_neon_holders_block ON stuck_neon_holders(block_slot);

CREATE TABLE IF NOT EXISTS stuck_neon_transactions (
    is_finalized BOOLEAN,
    block_slot BIGINT,
    json_data_list TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_stuck_neon_transactions_block ON stuck_neon_transactions(is_finalized, block_slot);

CREATE TABLE IF NOT EXISTS solana_alt_infos (
    block_slot BIGINT,
    json_data_list TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_solana_alt_infos_block ON solana_alt_infos(block_slot);
