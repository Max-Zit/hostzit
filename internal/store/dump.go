package store

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5"
)

// A database dump is a stream of frames: a type byte, a 4-byte big-endian
// length and the payload. It holds the schema version, then each table (in
// an order that satisfies the foreign keys) as PostgreSQL binary COPY data,
// then the sequence values. A restore creates the schema of that version
// with the embedded migrations and copies the rows back, in one transaction.
const (
	dumpMagic    = "HZDB1"
	frameVersion = 'V' // schema version (decimal text)
	frameTable   = 'T' // table name; COPY data frames follow
	frameData    = 'D' // a piece of the current table's COPY data
	frameEnd     = 'E' // end of the current table
	frameSeqs    = 'S' // sequence values (JSON map name → value)
	frameDone    = 'Z' // end of the dump
	maxFrame     = 4 << 20
)

func writeFrame(w io.Writer, typ byte, p []byte) error {
	var h [5]byte
	h[0] = typ
	binary.BigEndian.PutUint32(h[1:], uint32(len(p))) // #nosec G115 -- frames are at most maxFrame
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > maxFrame {
		return 0, nil, errors.New("database dump: frame too large")
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return h[0], p, nil
}

// frameWriter cuts COPY output into data frames.
type frameWriter struct{ w io.Writer }

func (f frameWriter) Write(p []byte) (int, error) {
	for off := 0; off < len(p); {
		n := min(len(p)-off, 1<<20)
		if err := writeFrame(f.w, frameData, p[off:off+n]); err != nil {
			return off, err
		}
		off += n
	}
	return len(p), nil
}

// Dump writes the whole database as one consistent snapshot.
func (s *Store) Dump(ctx context.Context, w io.Writer) error {
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	bw := bufio.NewWriterSize(w, 1<<20)
	if _, err := bw.WriteString(dumpMagic); err != nil {
		return err
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		return err
	}
	if err := writeFrame(bw, frameVersion, fmt.Appendf(nil, "%d", version)); err != nil {
		return err
	}
	tables, err := tableOrder(ctx, tx)
	if err != nil {
		return err
	}
	for _, t := range tables {
		if err := writeFrame(bw, frameTable, []byte(t)); err != nil {
			return err
		}
		if _, err := tx.Conn().PgConn().CopyTo(ctx, frameWriter{bw}, `COPY public.`+pgx.Identifier{t}.Sanitize()+` TO STDOUT (FORMAT binary)`); err != nil {
			return fmt.Errorf("table %s: %w", t, err)
		}
		if err := writeFrame(bw, frameEnd, nil); err != nil {
			return err
		}
	}
	seqs := map[string]int64{}
	rows, err := tx.Query(ctx, `SELECT sequencename, last_value FROM pg_sequences WHERE schemaname='public' AND last_value IS NOT NULL`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n string
		var v int64
		if err := rows.Scan(&n, &v); err != nil {
			rows.Close()
			return err
		}
		seqs[n] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	raw, _ := json.Marshal(seqs)
	if err := writeFrame(bw, frameSeqs, raw); err != nil {
		return err
	}
	if err := writeFrame(bw, frameDone, nil); err != nil {
		return err
	}
	return bw.Flush()
}

// tableOrder lists the tables (without schema_migrations) so that every
// table comes after the tables its foreign keys point to.
func tableOrder(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'schema_migrations' ORDER BY tablename`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT c.relname, p.relname FROM pg_constraint k
		JOIN pg_class c ON c.oid=k.conrelid JOIN pg_class p ON p.oid=k.confrelid
		JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE k.contype='f' AND n.nspname='public' AND c.relname <> p.relname`)
	if err != nil {
		return nil, err
	}
	deps := map[string][]string{}
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			rows.Close()
			return nil, err
		}
		deps[child] = append(deps[child], parent)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []string
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(string) error
	visit = func(n string) error {
		switch state[n] {
		case 1:
			return fmt.Errorf("foreign keys form a cycle at %s", n)
		case 2:
			return nil
		}
		state[n] = 1
		for _, p := range deps[n] {
			if err := visit(p); err != nil {
				return err
			}
		}
		state[n] = 2
		out = append(out, n)
		return nil
	}
	for _, n := range names {
		if err := visit(n); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// copySource feeds the data frames of one table to COPY FROM.
type copySource struct {
	r    io.Reader
	buf  []byte
	done bool
}

func (c *copySource) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		if c.done {
			return 0, io.EOF
		}
		typ, data, err := readFrame(c.r)
		if err != nil {
			return 0, err
		}
		switch typ {
		case frameData:
			c.buf = data
		case frameEnd:
			c.done = true
		default:
			return 0, fmt.Errorf("database dump: unexpected frame %q in table data", typ)
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// RestoreDump replaces everything in the database at url with a dump: the
// tables are dropped, the schema of the dump's version is created, the rows
// are copied back and the sequences set, all in one transaction (nothing
// changes when it fails). The server migrates to its own version when it
// starts next.
func RestoreDump(ctx context.Context, url string, r io.Reader) error {
	br := bufio.NewReaderSize(r, 1<<20)
	magic := make([]byte, len(dumpMagic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != dumpMagic {
		return errors.New("not a HostZit database dump")
	}
	typ, v, err := readFrame(br)
	if err != nil || typ != frameVersion {
		return errors.New("database dump: no schema version")
	}
	var version int
	if _, err := fmt.Sscan(string(v), &version); err != nil || version <= 0 {
		return errors.New("database dump: bad schema version")
	}
	if version > SchemaVersion() {
		return fmt.Errorf("the backup is from a newer HostZit (database version %d, this program knows %d); install that version first", version, SchemaVersion())
	}
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLock); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public'`)
	if err != nil {
		return err
	}
	old, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if len(old) > 0 {
		ids := make([]string, len(old))
		for i, t := range old {
			ids[i] = "public." + pgx.Identifier{t}.Sanitize()
		}
		if _, err := tx.Exec(ctx, `DROP TABLE IF EXISTS `+strings.Join(ids, ", ")+` CASCADE`); err != nil {
			return fmt.Errorf("removing the current tables: %w", err)
		}
	}
	// Sequences of their own (not owned by a column) survive the tables.
	rows, err = tx.Query(ctx, `SELECT sequencename FROM pg_sequences WHERE schemaname='public'`)
	if err != nil {
		return err
	}
	seqs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, q := range seqs {
		if _, err := tx.Exec(ctx, `DROP SEQUENCE IF EXISTS public.`+pgx.Identifier{q}.Sanitize()+` CASCADE`); err != nil {
			return fmt.Errorf("removing sequence %s: %w", q, err)
		}
	}
	if err := migrateTx(ctx, tx, version); err != nil {
		return err
	}
	for {
		typ, p, err := readFrame(br)
		if err != nil {
			return fmt.Errorf("database dump: %w", err)
		}
		switch typ {
		case frameTable:
			t := string(p)
			src := &copySource{r: br}
			if _, err := tx.Conn().PgConn().CopyFrom(ctx, src, `COPY public.`+pgx.Identifier{t}.Sanitize()+` FROM STDIN (FORMAT binary)`); err != nil {
				return fmt.Errorf("table %s: %w", t, err)
			}
			for !src.done { // COPY may stop before reading the end frame
				if _, err := src.Read(make([]byte, 4096)); err != nil && !errors.Is(err, io.EOF) {
					return err
				}
			}
		case frameSeqs:
			var seqs map[string]int64
			if err := json.Unmarshal(p, &seqs); err != nil {
				return fmt.Errorf("database dump: sequences: %w", err)
			}
			for n, v := range seqs {
				if _, err := tx.Exec(ctx, `SELECT setval($1::regclass, $2, true)`, "public."+pgx.Identifier{n}.Sanitize(), v); err != nil {
					return fmt.Errorf("sequence %s: %w", n, err)
				}
			}
		case frameDone:
			return tx.Commit(ctx)
		default:
			return fmt.Errorf("database dump: unexpected frame %q", typ)
		}
	}
}
