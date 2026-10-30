ALTER TABLE sites
    ADD COLUMN ip_allow  text[] NOT NULL DEFAULT '{}',
    ADD COLUMN ip_deny   text[] NOT NULL DEFAULT '{}',
    ADD COLUMN hotlink   boolean NOT NULL DEFAULT false,
    ADD COLUMN waf       boolean NOT NULL DEFAULT false,
    ADD COLUMN protected jsonb NOT NULL DEFAULT '[]';
