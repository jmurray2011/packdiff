// SPDX-License-Identifier: Apache-2.0

// Package report renders a result as a self-contained HTML page for a change board.
// The page loads nothing from the network and carries no timestamps, so identical
// results render to identical bytes.
package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/jmurray2011/packdiff/core"
)

//go:embed report.html.tmpl
var page string

var tmpl = template.Must(template.New("report").Parse(page))

// tags name the subject prefixes detectors use.
var tags = map[string]string{
	"file": "file", "script": "script", "user": "user", "group": "group", "requires": "requires",
	"provides": "provides", "unit": "unit", "listen": "port", "alg": "algorithm", "lib": "library",
	"store": "key material", "sdk": "SDK", "client": "client",
}

// collapseOver is the change count above which a category's table starts collapsed.
const collapseOver = 100

type category struct {
	Name       string
	Open       bool // the section starts expanded
	Added      int
	Removed    int
	Changed    int
	Suppressed int
	Values     bool // any row has a before or after value
	Rows       []row
}

type row struct {
	ID        string
	Kind      string
	Tag       string
	Primary   string
	Context   string
	Before    string
	After     string
	Note      string // reason of the suppressing rule
	Values    bool   // the table shows a value column
	Details   []detail
	Locations [][]string
	Search    string
}

type detail struct {
	Text  string
	Class string
}

type view struct {
	Title      string
	Product    string
	Base       core.Artifact
	Head       core.Artifact
	Categories []category
	Suppressed []row
	Tool       core.Tool
	Options    core.Options
}

// Write renders r as HTML.
func Write(w io.Writer, r core.Result) error {
	return tmpl.Execute(w, build(r))
}

func build(r core.Result) view {
	product := r.Head.Name
	if product == "" {
		product = r.Base.Name
	}
	v := view{
		Title:   fmt.Sprintf("%s %s to %s", product, r.Base.Version, r.Head.Version),
		Product: product,
		Base:    r.Base,
		Head:    r.Head,
		Tool:    r.Tool,
		Options: r.Options,
	}
	for _, c := range core.Categories {
		n := r.Summary[c]
		cat := category{Name: string(c), Added: n.Added, Removed: n.Removed, Changed: n.Changed, Suppressed: n.Suppressed}
		for _, ch := range r.Changes {
			if ch.Category == c {
				cat.Rows = append(cat.Rows, toRow(ch))
			}
		}
		cat.Open = len(cat.Rows) <= collapseOver
		for _, rw := range cat.Rows {
			cat.Values = cat.Values || rw.Before != "" || rw.After != ""
		}
		for i := range cat.Rows {
			cat.Rows[i].Values = cat.Values
		}
		v.Categories = append(v.Categories, cat)
	}
	for _, ch := range r.Suppressed {
		rw := toRow(ch)
		rw.Values = true
		v.Suppressed = append(v.Suppressed, rw)
	}
	return v
}

func toRow(c core.Change) row {
	rw := row{ID: c.ID, Kind: string(c.Kind), Note: c.Suppressed}
	subject := c.Subject
	if prefix, rest, ok := strings.Cut(subject, ":"); ok && tags[prefix] != "" {
		rw.Tag, subject = tags[prefix], rest
	}
	if i := strings.LastIndex(subject, "#"); i >= 0 {
		rw.Context, rw.Primary = subject[:i], subject[i+1:]
	} else {
		rw.Primary = subject
	}
	rw.Before, rw.After = value(c.Before), value(c.After)
	for _, d := range c.Details {
		class := ""
		switch {
		case strings.HasPrefix(d, "+ "):
			class = "diff add"
		case strings.HasPrefix(d, "- "):
			class = "diff del"
		}
		rw.Details = append(rw.Details, detail{d, class})
	}
	for _, l := range c.Locations {
		rw.Locations = append(rw.Locations, l.Chain)
	}
	rw.Search = strings.ToLower(strings.Join([]string{string(c.Category), string(c.Kind), c.Subject, rw.Before, rw.After}, " "))
	return rw
}

// value shortens what a table cell shows; multi-line values live in the details instead.
func value(p *string) string {
	if p == nil {
		return ""
	}
	s := *p
	if strings.Contains(s, "\n") {
		return ""
	}
	if rest, ok := strings.CutPrefix(s, "sha256:"); ok && len(rest) > 12 {
		return "sha256:" + rest[:12]
	}
	return s
}
