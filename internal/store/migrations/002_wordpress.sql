-- WordPress installs found or made by the toolkit.
CREATE TABLE wp_installs (
    id          bigserial PRIMARY KEY,
    site_id     bigint NOT NULL UNIQUE REFERENCES sites(id) ON DELETE CASCADE,
    path        text NOT NULL,
    db_name     text NOT NULL DEFAULT '',
    admin_user  text NOT NULL DEFAULT '',
    version     text NOT NULL DEFAULT '',
    auto_update text NOT NULL DEFAULT 'minor' CHECK (auto_update IN ('off', 'minor', 'all')),
    updates     jsonb NOT NULL DEFAULT '{}',
    checked_at  timestamptz,
    updated_at  timestamptz,
    last_error  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Snapshots (files + database) made before updates or by hand.
CREATE TABLE wp_snapshots (
    id         bigserial PRIMARY KEY,
    install_id bigint NOT NULL REFERENCES wp_installs(id) ON DELETE CASCADE,
    file       text NOT NULL,
    size_b     bigint NOT NULL DEFAULT 0,
    note       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX wp_snapshots_install ON wp_snapshots (install_id);
