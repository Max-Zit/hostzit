-- Limit hits of an account: CPU time held back by the CPU limit and
-- processes ended by the memory limit (counters of the control group).
ALTER TABLE usage_samples ADD COLUMN throttled_usec bigint NOT NULL DEFAULT 0;
ALTER TABLE usage_samples ADD COLUMN oom bigint NOT NULL DEFAULT 0;
