-- A staging copy points to the live install it was made from.
ALTER TABLE wp_installs ADD COLUMN staging_of bigint REFERENCES wp_installs(id) ON DELETE SET NULL;
