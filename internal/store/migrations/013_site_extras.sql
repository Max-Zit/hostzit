-- Own error pages, folder listings and file types of a website (hosting.SiteExtras).
ALTER TABLE sites ADD COLUMN extras jsonb NOT NULL DEFAULT '{}';
