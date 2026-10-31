package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// GitRepo is a customer's repository.
type GitRepo struct {
	ID         int64
	CustomerID int64
	Name       string
	Branch     string
	Target     string
	Remote     string
	HookToken  string // secret of the deploy webhook
	DeployedAt *time.Time
	DeployOK   bool
	CreatedAt  time.Time
}

const gitCols = `id, customer_id, name, branch, target, remote, hook_token, deployed_at, deploy_ok, created_at`

func scanGit(row pgx.Row) (*GitRepo, error) {
	g := &GitRepo{}
	err := row.Scan(&g.ID, &g.CustomerID, &g.Name, &g.Branch, &g.Target, &g.Remote, &g.HookToken, &g.DeployedAt, &g.DeployOK, &g.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return g, err
}

// GitRepos lists a customer's repositories.
func (s *Store) GitRepos(ctx context.Context, customerID int64) ([]*GitRepo, error) {
	rows, err := s.db.Query(ctx, `SELECT `+gitCols+` FROM git_repos WHERE customer_id=$1 ORDER BY name`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*GitRepo
	for rows.Next() {
		g, err := scanGit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GitRepoByID loads a repository.
func (s *Store) GitRepoByID(ctx context.Context, id int64) (*GitRepo, error) {
	return scanGit(s.db.QueryRow(ctx, `SELECT `+gitCols+` FROM git_repos WHERE id=$1`, id))
}

// GitRepoByToken finds the repository of a webhook.
func (s *Store) GitRepoByToken(ctx context.Context, token string) (*GitRepo, error) {
	return scanGit(s.db.QueryRow(ctx, `SELECT `+gitCols+` FROM git_repos WHERE hook_token=$1`, token))
}

// SaveGitRepo creates or updates a repository.
func (s *Store) SaveGitRepo(ctx context.Context, g *GitRepo) error {
	if g.ID == 0 {
		err := s.db.QueryRow(ctx, `INSERT INTO git_repos(customer_id, name, branch, target, remote, hook_token) VALUES($1,$2,$3,$4,$5,$6) RETURNING id, created_at`,
			g.CustomerID, g.Name, g.Branch, g.Target, g.Remote, g.HookToken).Scan(&g.ID, &g.CreatedAt)
		if isUnique(err) {
			return errors.New("a repository with this name exists already")
		}
		return err
	}
	_, err := s.db.Exec(ctx, `UPDATE git_repos SET branch=$2, target=$3, remote=$4 WHERE id=$1`, g.ID, g.Branch, g.Target, g.Remote)
	return err
}

// MarkGitDeployed stores the result of a deployment.
func (s *Store) MarkGitDeployed(ctx context.Context, id int64, ok bool) error {
	_, err := s.db.Exec(ctx, `UPDATE git_repos SET deployed_at=now(), deploy_ok=$2 WHERE id=$1`, id, ok)
	return err
}

// DeleteGitRepo removes a repository.
func (s *Store) DeleteGitRepo(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM git_repos WHERE id=$1`, id)
	return err
}
