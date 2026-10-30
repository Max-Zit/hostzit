-- Scheduled jobs of customers (systemd timers in the account's cage).
CREATE TABLE cron_jobs (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    schedule    text NOT NULL,
    command     text NOT NULL,
    enabled     boolean NOT NULL DEFAULT true,
    note        text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cron_jobs_customer ON cron_jobs (customer_id);

-- SSH keys of customers (written to ~/.ssh/authorized_keys).
CREATE TABLE ssh_keys (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name        text NOT NULL,
    key         text NOT NULL,
    fingerprint text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (customer_id, fingerprint)
);

-- Notifications already sent (no repeats within a day).
CREATE TABLE notices (
    key     text PRIMARY KEY,
    sent_at timestamptz NOT NULL
);
