-- Node.js and Python applications of the customers.
CREATE TABLE apps (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name        text NOT NULL,
    kind        text NOT NULL,
    root        text NOT NULL,
    command     text NOT NULL,
    env         jsonb NOT NULL DEFAULT '{}',
    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (customer_id, name)
);
ALTER TABLE sites ADD COLUMN app text NOT NULL DEFAULT '';
