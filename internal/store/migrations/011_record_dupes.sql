-- The same DNS record twice (a staging copy made again) made the DNS
-- server refuse the whole zone: keep one of each, publish those zones again.
UPDATE zones SET applied = false WHERE id IN (
    SELECT zone_id FROM records GROUP BY zone_id, name, type, content HAVING count(*) > 1);
DELETE FROM records r USING records o
 WHERE r.zone_id = o.zone_id AND r.name = o.name AND r.type = o.type AND r.content = o.content AND r.id > o.id;
