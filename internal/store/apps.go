package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/max-zit/hostzit/internal/hosting"
)

// App is a customer's Node.js or Python application.
type App struct {
	ID         int64
	CustomerID int64
	Name       string
	Kind       string
	Root       string
	Command    string
	Env        map[string]string
	Enabled    bool
	CreatedAt  time.Time
}

// Spec is the helper's view.
func (a *App) Spec() hosting.App {
	return hosting.App{Name: a.Name, Kind: a.Kind, Root: a.Root, Command: a.Command, Env: a.Env}
}

const appCols = `id, customer_id, name, kind, root, command, env, enabled, created_at`

func scanApp(row pgx.Row) (*App, error) {
	a := &App{}
	var env []byte
	err := row.Scan(&a.ID, &a.CustomerID, &a.Name, &a.Kind, &a.Root, &a.Command, &env, &a.Enabled, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(env, &a.Env)
	return a, nil
}

// Apps lists a customer's applications.
func (s *Store) Apps(ctx context.Context, customerID int64) ([]*App, error) {
	rows, err := s.db.Query(ctx, `SELECT `+appCols+` FROM apps WHERE customer_id=$1 ORDER BY name`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*App
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AppByID loads an application.
func (s *Store) AppByID(ctx context.Context, id int64) (*App, error) {
	return scanApp(s.db.QueryRow(ctx, `SELECT `+appCols+` FROM apps WHERE id=$1`, id))
}

// SaveApp creates or updates an application.
func (s *Store) SaveApp(ctx context.Context, a *App) error {
	if err := a.Spec().Validate(); err != nil {
		return err
	}
	if a.Env == nil {
		a.Env = map[string]string{}
	}
	env, _ := json.Marshal(a.Env)
	if a.ID == 0 {
		err := s.db.QueryRow(ctx, `INSERT INTO apps(customer_id, name, kind, root, command, env, enabled) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at`,
			a.CustomerID, a.Name, a.Kind, a.Root, a.Command, env, a.Enabled).Scan(&a.ID, &a.CreatedAt)
		if isUnique(err) {
			return errors.New("an application with this name exists already")
		}
		return err
	}
	_, err := s.db.Exec(ctx, `UPDATE apps SET kind=$2, root=$3, command=$4, env=$5, enabled=$6 WHERE id=$1`, a.ID, a.Kind, a.Root, a.Command, env, a.Enabled)
	return err
}

// DeleteApp removes an application and detaches its websites.
func (s *Store) DeleteApp(ctx context.Context, a *App) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE sites SET app='', applied=false WHERE customer_id=$1 AND app=$2`, a.CustomerID, a.Name); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM apps WHERE id=$1`, a.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetSiteApp sends a website to an application ("" = back to PHP).
func (s *Store) SetSiteApp(ctx context.Context, siteID int64, app string) error {
	_, err := s.db.Exec(ctx, `UPDATE sites SET app=$2, applied=false WHERE id=$1`, siteID, app)
	return err
}
