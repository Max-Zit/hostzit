package web

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/store"
)

// The database manager of the customer panel (like phpMyAdmin): tables,
// their rows and structure, any SQL, export. The helper runs everything
// as a MariaDB user that can reach only this account's databases.

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("GET /databases/{name}/manage", s.handleDBManage)
		c("POST /databases/{name}/manage", s.handleDBManage)
		c("POST /databases/{name}/export", s.handleDBExport)
	})
}

type dbTable struct {
	Name   string
	Rows   string
	SizeB  int64
	Engine string
}

type dbManageData struct {
	DB     string
	Tables []dbTable
	Table  string
	View   string // rows | structure | sql
	Page   int
	Pages  int
	SQL    string
	Sets   []helper.ResultSet
	Error  string
	Ran    bool
}

const dbPageRows = 50

// dbQuery runs SQL in one of the customer's databases.
func (s *Server) dbQuery(r *http.Request, c *store.Customer, db, sql string) ([]helper.ResultSet, string, error) {
	dbs, err := s.store.Databases(r.Context(), c.ID)
	if err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(dbs))
	for _, d := range dbs {
		names = append(names, d.Name)
	}
	var res struct {
		Sets  []helper.ResultSet `json:"sets"`
		Error string             `json:"error"`
	}
	err = s.call(r.Context(), actor(r), "db.query", map[string]any{"account": c.Username, "dbs": names, "db": db, "sql": sql}, &res)
	return res.Sets, res.Error, err
}

// quoteIdent quotes a table name for MariaDB.
func quoteIdent(n string) string { return "`" + strings.ReplaceAll(n, "`", "``") + "`" }

func (s *Server) handleDBManage(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	db := r.PathValue("name")
	d := &dbManageData{DB: db, View: r.FormValue("view"), Table: r.URL.Query().Get("table")}
	dbs, err := s.store.Databases(r.Context(), c.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !slices.ContainsFunc(dbs, func(x *store.Database) bool { return x.Name == db }) {
		s.notFound(w, r)
		return
	}
	page := &Page{Title: db, Nav: "databases", Customer: c, Crumb: "Databases", CrumbURL: "/databases", Data: d}
	sets, qerr, err := s.dbQuery(r, c, db, "SELECT table_name, table_rows, data_length+index_length, engine FROM information_schema.tables WHERE table_schema=DATABASE() ORDER BY table_name")
	if err != nil {
		page.Error = storeErr(err)
		s.render(w, r, http.StatusOK, "dbmanage", page)
		return
	}
	if qerr != "" {
		d.Error = qerr
	}
	if len(sets) > 0 {
		for _, row := range sets[len(sets)-1].Rows {
			t := dbTable{}
			if len(row) >= 4 {
				t.Name, t.Rows, t.Engine = deref(row[0]), deref(row[1]), deref(row[3])
				t.SizeB, _ = strconv.ParseInt(deref(row[2]), 10, 64)
			}
			d.Tables = append(d.Tables, t)
		}
	}
	if r.Method == http.MethodPost {
		// SQL typed by the customer
		d.View, d.SQL, d.Ran = "sql", r.FormValue("sql"), true
		d.Sets, d.Error, err = s.dbQuery(r, c, db, d.SQL)
		if err != nil {
			d.Error = storeErr(err)
		}
		s.audit(r, "db.sql", "database:"+db, "SQL run (%d characters)", len(d.SQL))
		s.render(w, r, http.StatusOK, "dbmanage", page)
		return
	}
	if d.View == "" {
		d.View = "rows"
	}
	if d.Table != "" {
		var t *dbTable
		for i := range d.Tables {
			if d.Tables[i].Name == d.Table {
				t = &d.Tables[i]
			}
		}
		if t == nil {
			s.notFound(w, r)
			return
		}
		switch d.View {
		case "structure":
			d.Sets, d.Error, _ = s.dbQuery(r, c, db, "SHOW FULL COLUMNS FROM "+quoteIdent(t.Name)+"; SHOW INDEX FROM "+quoteIdent(t.Name))
		default:
			d.View = "rows"
			d.Page, _ = strconv.Atoi(r.URL.Query().Get("page"))
			d.Page = max(d.Page, 1)
			n, _ := strconv.Atoi(t.Rows)
			d.Pages = max((n+dbPageRows-1)/dbPageRows, 1)
			d.Sets, d.Error, _ = s.dbQuery(r, c, db, "SELECT * FROM "+quoteIdent(t.Name)+" LIMIT "+strconv.Itoa(dbPageRows)+" OFFSET "+strconv.Itoa((d.Page-1)*dbPageRows))
		}
	} else if d.View != "sql" {
		d.View = "tables"
	}
	s.render(w, r, http.StatusOK, "dbmanage", page)
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (s *Server) handleDBExport(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	db := r.PathValue("name")
	dbs, err := s.store.Databases(r.Context(), c.ID)
	if err != nil || !slices.ContainsFunc(dbs, func(x *store.Database) bool { return x.Name == db }) {
		s.notFound(w, r)
		return
	}
	var res struct {
		File string `json:"file"`
	}
	back := "/databases/" + url.PathEscape(db) + "/manage"
	if err := s.call(r.Context(), actor(r), "db.export", map[string]string{"account": c.Username, "name": db}, &res); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "db.export", "database:"+db, "exported to %s", res.File)
	s.redirect(w, r, back, "The export is in the folder backups (Files).")
}
