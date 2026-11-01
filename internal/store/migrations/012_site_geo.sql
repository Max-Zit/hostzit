-- Access to a website by country or continent (block or allow only).
ALTER TABLE sites ADD COLUMN geo_mode text NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN geo_list text[] NOT NULL DEFAULT '{}';
