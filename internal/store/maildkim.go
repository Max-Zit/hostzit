package store

import (
	"context"
	"time"
)

// DKIMKey is the signing key of a customer's domain for website mail.
type DKIMKey struct {
	Domain     string
	CustomerID int64
	Selector   string
	PrivateKey string // plain PEM (sealed in the database)
	Record     string // the DNS value: v=DKIM1; k=rsa; p=…
	CreatedAt  time.Time
}

// DKIMKeys lists a customer's keys.
func (s *Store) DKIMKeys(ctx context.Context, customerID int64) ([]DKIMKey, error) {
	rows, err := s.db.Query(ctx, `SELECT domain, customer_id, selector, private_key, record, created_at FROM mail_dkim WHERE customer_id=$1 ORDER BY domain`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DKIMKey
	for rows.Next() {
		var k DKIMKey
		var sealed string
		if err := rows.Scan(&k.Domain, &k.CustomerID, &k.Selector, &sealed, &k.Record, &k.CreatedAt); err != nil {
			return nil, err
		}
		if k.PrivateKey, err = s.OpenSecret("dkim."+k.Domain, sealed); err != nil {
			continue // a key of another server's secret: made again
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SaveDKIMKey stores a key; a key of the same domain (also of another
// customer, whose domain it no longer is) is replaced.
func (s *Store) SaveDKIMKey(ctx context.Context, k DKIMKey) error {
	_, err := s.db.Exec(ctx, `INSERT INTO mail_dkim(domain, customer_id, selector, private_key, record, created_at) VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT (domain) DO UPDATE SET customer_id=EXCLUDED.customer_id, selector=EXCLUDED.selector, private_key=EXCLUDED.private_key, record=EXCLUDED.record, created_at=EXCLUDED.created_at`,
		k.Domain, k.CustomerID, k.Selector, s.SealSecret("dkim."+k.Domain, k.PrivateKey), k.Record, s.now())
	return err
}

// DeleteDKIMKeys removes a customer's keys of domains not in keep.
func (s *Store) DeleteDKIMKeys(ctx context.Context, customerID int64, keep []string) error {
	if keep == nil {
		keep = []string{}
	}
	_, err := s.db.Exec(ctx, `DELETE FROM mail_dkim WHERE customer_id=$1 AND NOT (domain = ANY($2))`, customerID, keep)
	return err
}
