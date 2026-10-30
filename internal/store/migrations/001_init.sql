CREATE TABLE settings (
    key   text PRIMARY KEY,
    value jsonb NOT NULL
);

-- Hosting packages (plans): limits and feature switches.
CREATE TABLE packages (
    id          bigserial PRIMARY KEY,
    slug        text NOT NULL UNIQUE,
    name        text NOT NULL,
    limits      jsonb NOT NULL,
    max_sites   int NOT NULL DEFAULT 1,
    max_dbs     int NOT NULL DEFAULT 1,
    max_zones   int NOT NULL DEFAULT 1,
    php_versions text[] NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- A customer = one hosting account (one Linux user).
CREATE TABLE customers (
    id             bigserial PRIMARY KEY,
    uuid           uuid NOT NULL UNIQUE,
    external_id    text UNIQUE,
    username       text NOT NULL UNIQUE,
    number         int NOT NULL UNIQUE CHECK (number BETWEEN 1 AND 999999),
    package_id     bigint NOT NULL REFERENCES packages(id),
    status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'terminated')),
    suspend_reason text NOT NULL DEFAULT '',
    display_name   text NOT NULL DEFAULT '',
    email          text NOT NULL DEFAULT '',
    php_version    text NOT NULL DEFAULT '',
    applied        boolean NOT NULL DEFAULT false,
    apply_error    text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    terminated_at  timestamptz,
    delete_after   timestamptz
);

CREATE TABLE users (
    id                   bigserial PRIMARY KEY,
    username             text NOT NULL,
    display_name         text NOT NULL DEFAULT '',
    email                text NOT NULL DEFAULT '',
    password_hash        text NOT NULL,
    role                 text NOT NULL CHECK (role IN ('admin', 'operator', 'viewer', 'customer')),
    customer_id          bigint REFERENCES customers(id) ON DELETE CASCADE,
    totp_secret          text NOT NULL DEFAULT '',
    totp_enabled         boolean NOT NULL DEFAULT false,
    totp_last_step       bigint NOT NULL DEFAULT 0,
    recovery_codes       text[] NOT NULL DEFAULT '{}',
    must_change_password boolean NOT NULL DEFAULT false,
    disabled             boolean NOT NULL DEFAULT false,
    lang                 text NOT NULL DEFAULT '',
    created_at           timestamptz NOT NULL DEFAULT now(),
    last_login_at        timestamptz,
    CHECK ((role = 'customer') = (customer_id IS NOT NULL))
);
CREATE UNIQUE INDEX users_username ON users (lower(username));

CREATE TABLE sessions (
    token_hash text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage      text NOT NULL CHECK (stage IN ('mfa', 'full')),
    created_at timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    ip         text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT '',
    -- an administrator working in a customer's panel ("log in as")
    acting_admin text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE login_blocks (
    ip         text PRIMARY KEY,
    until      timestamptz NOT NULL,
    strikes    int NOT NULL,
    reason     text NOT NULL,
    updated_at timestamptz NOT NULL
);

-- Append-only, hash-chained audit log: hash = SHA-256(prev_hash, fields).
CREATE TABLE audit_log (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL,
    username  text NOT NULL,
    ip        text NOT NULL,
    action    text NOT NULL,
    target    text NOT NULL,
    detail    text NOT NULL,
    prev_hash text NOT NULL,
    hash      text NOT NULL
);

CREATE TABLE api_tokens (
    id         bigserial PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    scopes     text[] NOT NULL DEFAULT '{}',
    allowed    text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    last_used  timestamptz,
    last_ip    text NOT NULL DEFAULT ''
);
CREATE INDEX api_tokens_user ON api_tokens (user_id);

-- Single sign-on links from the billing system (one use, 60 s).
CREATE TABLE sso_links (
    token_hash text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_by text NOT NULL
);

-- Idempotency keys of API calls (24 h).
CREATE TABLE idempotency (
    key        text NOT NULL,
    token_id   bigint NOT NULL,
    status     int NOT NULL,
    body       bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (token_id, key)
);

-- Background jobs (account creation, termination …).
CREATE TABLE jobs (
    id          uuid PRIMARY KEY,
    kind        text NOT NULL,
    customer_id bigint REFERENCES customers(id) ON DELETE SET NULL,
    status      text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    detail      text NOT NULL DEFAULT '',
    error       text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);
CREATE INDEX jobs_open ON jobs (status) WHERE status IN ('queued', 'running');

CREATE TABLE sites (
    id            bigserial PRIMARY KEY,
    customer_id   bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    domain        text NOT NULL UNIQUE,
    aliases       text[] NOT NULL DEFAULT '{}',
    doc_root      text NOT NULL,
    php_version   text NOT NULL,
    www           boolean NOT NULL DEFAULT true,
    canonical     text NOT NULL DEFAULT '',
    force_https   boolean NOT NULL DEFAULT true,
    hsts          boolean NOT NULL DEFAULT false,
    cache         boolean NOT NULL DEFAULT false,
    cache_minutes int NOT NULL DEFAULT 60,
    wordpress     boolean NOT NULL DEFAULT false,
    block_xmlrpc  boolean NOT NULL DEFAULT false,
    redirects     jsonb NOT NULL DEFAULT '[]',
    upload_mb     int NOT NULL DEFAULT 64,
    auto_tls      boolean NOT NULL DEFAULT true,
    cert_status   text NOT NULL DEFAULT '',
    cert_error    text NOT NULL DEFAULT '',
    cert_not_after timestamptz,
    cert_names    text[] NOT NULL DEFAULT '{}',
    cert_tried_at timestamptz,
    applied       boolean NOT NULL DEFAULT false,
    apply_error   text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sites_customer ON sites (customer_id);

-- Every host name of every site, unique across the server.
CREATE TABLE site_names (
    name    text PRIMARY KEY,
    site_id bigint NOT NULL REFERENCES sites(id) ON DELETE CASCADE
);

CREATE TABLE zones (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name        text NOT NULL UNIQUE,
    dnssec      boolean NOT NULL DEFAULT false,
    ds          text[] NOT NULL DEFAULT '{}',
    applied     boolean NOT NULL DEFAULT false,
    apply_error text NOT NULL DEFAULT '',
    changed_at  timestamptz NOT NULL DEFAULT now(),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE records (
    id      bigserial PRIMARY KEY,
    zone_id bigint NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name    text NOT NULL,
    type    text NOT NULL,
    ttl     int NOT NULL,
    content text NOT NULL,
    owner   text NOT NULL DEFAULT ''
);
CREATE INDEX records_zone ON records (zone_id);

CREATE TABLE databases (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name        text NOT NULL UNIQUE,
    size_b      bigint NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE db_users (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name        text NOT NULL UNIQUE,
    databases   text[] NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Usage samples (every 10 minutes) for graphs and the API.
CREATE TABLE usage_samples (
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    at          timestamptz NOT NULL,
    disk_kb     bigint NOT NULL,
    inodes      bigint NOT NULL,
    db_b        bigint NOT NULL,
    memory_b    bigint NOT NULL,
    cpu_usec    bigint NOT NULL,
    io_b        bigint NOT NULL,
    tasks       int NOT NULL,
    PRIMARY KEY (customer_id, at)
);
