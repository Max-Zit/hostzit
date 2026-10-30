-- Four-eyes approval: a second administrator confirms dangerous actions.
CREATE TABLE approvals (
    id           bigserial PRIMARY KEY,
    action       text NOT NULL,
    target       text NOT NULL,
    summary      text NOT NULL,
    params       jsonb NOT NULL DEFAULT '{}',
    requested_by text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'done', 'failed')),
    decided_by   text NOT NULL DEFAULT '',
    decided_at   timestamptz,
    result       text NOT NULL DEFAULT ''
);
CREATE INDEX approvals_pending ON approvals (status) WHERE status = 'pending';
