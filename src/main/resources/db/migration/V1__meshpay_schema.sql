-- MeshPay schema. Every money invariant is also enforced here, so a bug in the
-- application layer fails loudly instead of corrupting balances.

create table accounts (
    vpa          varchar(128)  primary key,
    holder_name  varchar(128)  not null,
    balance      numeric(19,2) not null check (balance >= 0),
    pin_salt     varchar(64)   not null,
    pin_hash     varchar(128)  not null,
    version      bigint        not null default 0,
    created_at   timestamptz   not null default now()
);

create table devices (
    device_id      varchar(64)  primary key,
    vpa            varchar(128) not null references accounts (vpa),
    public_key     text         not null,
    key_algorithm  varchar(32)  not null,
    status         varchar(16)  not null,          -- ACTIVE | FLAGGED | REVOKED
    flagged_reason varchar(128),
    registered_at  timestamptz  not null
);
create index ix_devices_vpa on devices (vpa);

-- Server keys. Private halves are wrapped (AES-GCM) with a master key held outside
-- the database: the DbKeyVault is a stand-in for a KMS / Vault transit engine.
create table server_keys (
    key_id              varchar(64) primary key,
    purpose             varchar(16) not null,       -- ENCRYPTION | SIGNING
    algorithm           varchar(32) not null,
    public_key          text        not null,
    wrapped_private_key text        not null,
    status              varchar(16) not null,       -- ACTIVE | RETIRED
    created_at          timestamptz not null,
    retired_at          timestamptz
);
create unique index ux_server_keys_one_active on server_keys (purpose) where status = 'ACTIVE';

-- Offline wallets: money moved out of the main balance and reserved for one device.
create table offline_wallets (
    cert_id        varchar(36)   primary key,
    vpa            varchar(128)  not null references accounts (vpa),
    device_id      varchar(64)   not null references devices (device_id),
    offline_limit  numeric(19,2) not null check (offline_limit > 0),
    per_txn_cap    numeric(19,2) not null check (per_txn_cap > 0 and per_txn_cap <= offline_limit),
    remaining      numeric(19,2) not null check (remaining >= 0 and remaining <= offline_limit),
    counter_start  bigint        not null check (counter_start >= 0),
    issued_at      timestamptz   not null,
    expires_at     timestamptz   not null,
    status         varchar(16)   not null,          -- ACTIVE | CLOSED
    signing_key_id varchar(64)   not null,
    signature      text          not null,
    closed_at      timestamptz,
    refunded       numeric(19,2),
    version        bigint        not null default 0
);
create unique index ux_wallets_one_active_per_device on offline_wallets (device_id) where status = 'ACTIVE';

-- One row per packet that got past decryption. Rejections are recorded too (with a reason).
create table payments (
    id                bigserial     primary key,
    packet_hash       varchar(64)   not null,
    sender_vpa        varchar(128),
    receiver_vpa      varchar(128),
    amount            numeric(19,2),
    device_id         varchar(64),
    counter           bigint,
    nonce             varchar(64),
    wallet_cert_id    varchar(36),
    signed_at         timestamptz,
    settled_at        timestamptz   not null,
    bridge_node_id    varchar(64)   not null,
    hop_count         int           not null,
    status            varchar(16)   not null,       -- SETTLED | REJECTED
    reason            varchar(64),
    receipt_key_id    varchar(64)   not null,
    receipt_signature text          not null,
    constraint ux_payments_packet_hash unique (packet_hash),
    constraint ck_settled_complete check (
        status <> 'SETTLED' or (sender_vpa is not null and receiver_vpa is not null and amount > 0
                                and device_id is not null and counter is not null and wallet_cert_id is not null))
);
-- Double-spend backstop: a device counter can be SETTLED at most once.
create unique index ux_payments_device_counter_settled on payments (device_id, counter) where status = 'SETTLED';
create index ix_payments_receiver on payments (receiver_vpa, id desc);
create index ix_payments_sender on payments (sender_vpa, id desc);
