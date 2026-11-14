-- Optional allowed addresses of an API token (IPv4 and IPv6 addresses or
-- networks); empty = from every address that may reach the admin port.
ALTER TABLE api_tokens ADD COLUMN allowed_ips text[] NOT NULL DEFAULT '{}';
