-- Firewall per site: only log (detection mode) and rules switched off.
ALTER TABLE sites
    ADD COLUMN waf_detect  boolean NOT NULL DEFAULT false,
    ADD COLUMN waf_exclude int[] NOT NULL DEFAULT '{}';
