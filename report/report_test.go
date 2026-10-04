// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/jmurray2011/packdiff/core"
)

func str(s string) *string { return &s }

func result() core.Result {
	changes := []core.Change{
		{
			Category: core.Outbound, Kind: core.Added, Subject: "https://api.example.net", After: str(""),
			Details:   []string{"https://api.example.net/v2/geocode?q=<x>"},
			Locations: []core.Location{{Chain: []string{"app-1.2.4.rpm", "opt/app/app.war", "WEB-INF/classes/com/example/Geo.class"}}},
		},
		{
			Category: core.Config, Kind: core.Changed, Subject: "opt/app/conf/app.properties#timeout", Before: str("30"), After: str("60"),
			Locations: []core.Location{{Chain: []string{"app-1.2.4.rpm", "opt/app/conf/app.properties"}}},
		},
		{
			Category: core.Config, Kind: core.Added, Subject: `opt/app/x.properties#<script>alert(1)</script>`, After: str("1"),
			Locations: []core.Location{{Chain: []string{"app-1.2.4.rpm", "opt/app/x.properties"}}},
		},
		{
			Category: core.Schema, Kind: core.Changed, Subject: "opt/app/db/V1__init.sql",
			Before:  str("sha256:218e98c39bd97258e082df5eb96459a895216fe80e5cd82aa78249326e3f79a0"),
			After:   str("sha256:6d67a6daa4bbf848ad862ada42b5b164a0000000000000000000000000000000"),
			Details: []string{"applied migration modified: checksum validation fails on databases that ran the old version"},
		},
		{
			Category: core.Host, Kind: core.Changed, Subject: "script:preinstall", Before: str("groupadd app\n"), After: str("groupadd -r app\nuseradd app\n"),
			Details: []string{"- groupadd app", "+ groupadd -r app", "+ useradd app"},
		},
		{Category: core.Deps, Kind: core.Changed, Subject: "org.example:geo", Before: str("1.0"), After: str("1.1")},
		{Category: core.Config, Kind: core.Changed, Subject: "opt/app/git.properties#git.commit.id", Before: str("a"), After: str("b"), Suppressed: "built-in: build metadata"},
	}
	return core.Build(
		core.Artifact{Name: "app", Version: "1.2.3", Type: "rpm", SHA256: strings.Repeat("a", 64), Path: "/srv/app-1.2.3.rpm"},
		core.Artifact{Name: "app", Version: "1.2.4", Type: "rpm", SHA256: strings.Repeat("b", 64), Path: "/srv/app-1.2.4.rpm"},
		core.Options{FirstParty: []string{"com.example"}}, changes,
	)
}

func render(t *testing.T, r core.Result) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestWrite(t *testing.T) {
	t.Parallel()
	html := render(t, result())

	for _, want := range []string{
		"<!doctype html>",
		"<title>app 1.2.3 to 1.2.4</title>",
		"https://api.example.net",
		"applied migration modified",
		"sha256:218e98c39bd9",
		"WEB-INF/classes/com/example/Geo.class",
		"built-in: build metadata",
		strings.Repeat("b", 64),   // provenance keeps full digests
		"Content-Security-Policy", // offline, no external loads
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(html, "<script>alert(1)</script>") || !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("subject not escaped")
	}
	if strings.Contains(html, "6d67a6daa4bbf848ad862ada42b5b164a0000000000000000000000000000000</") {
		t.Error("long digest in change table not shortened")
	}
	if regexp.MustCompile(`(?i)(src|href)="(https?:)?//`).MatchString(html) {
		t.Error("report loads external resources")
	}
	for _, gone := range []string{"eview", "decision", "decided", "class=\"bar\"", "open-only", "class=\"blurb\"", "headline", "gated", "Gated"} {
		if strings.Contains(html, gone) {
			t.Errorf("review narrative still present: %q", gone)
		}
	}
	if !strings.Contains(html, `<li class="diff add">&#43; useradd app</li>`) {
		t.Error("script diff not styled")
	}
}

func TestWriteDeterministic(t *testing.T) {
	t.Parallel()
	first, second := render(t, result()), render(t, result())
	if first != second {
		t.Fatal("identical results rendered differently")
	}
}

func TestRowsInSubjectOrder(t *testing.T) {
	t.Parallel()
	html := render(t, result())
	if strings.Index(html, ">timeout<") > strings.Index(html, "&lt;script&gt;") {
		t.Error("rows not in subject order")
	}
}

func TestPresenceOnlyCategoryOmitsValueColumn(t *testing.T) {
	t.Parallel()
	html := render(t, result())
	start := strings.Index(html, `<section class="ledger" id="cat-outbound"`)
	end := strings.Index(html[start:], "</section>")
	if section := html[start : start+end]; strings.Contains(section, "Before and after") || strings.Contains(section, `<td class="values">`) {
		t.Error("outbound has no values but shows the column")
	}
	start = strings.Index(html, `<section class="ledger" id="cat-config"`)
	end = strings.Index(html[start:], "</section>")
	if !strings.Contains(html[start:start+end], "Before and after") {
		t.Error("config lost its value column")
	}
}

func TestLargeSectionsStartCollapsed(t *testing.T) {
	t.Parallel()
	var changes []core.Change
	for i := 0; i < 101; i++ {
		changes = append(changes, core.Change{Category: core.Deps, Kind: core.Added, Subject: fmt.Sprintf("org.example:lib%03d", i), After: str("1.0")})
	}
	changes = append(changes, core.Change{Category: core.Config, Kind: core.Added, Subject: "a.properties#k", After: str("v")})
	html := render(t, core.Build(core.Artifact{}, core.Artifact{}, core.Options{}, changes))
	section := func(name string) string {
		start := strings.Index(html, `<section class="ledger" id="cat-`+name+`"`)
		return html[start : start+strings.Index(html[start:], "</section>")]
	}
	if !strings.Contains(section("config"), `<details class="rows" open>`) {
		t.Error("small section not expanded")
	}
	if strings.Contains(section("deps"), `<details class="rows" open>`) {
		t.Error("101-change section not collapsed")
	}
}

func TestEmptyCategoriesOmitted(t *testing.T) {
	t.Parallel()
	r := core.Build(core.Artifact{}, core.Artifact{}, core.Options{}, []core.Change{
		{Category: core.Files, Kind: core.Changed, Subject: "usr/sbin/appd", Before: str("sha256:aa"), After: str("sha256:bb")},
		{Category: core.Config, Kind: core.Changed, Subject: "a#version", Before: str("1.0"), After: str("1.1"), Suppressed: "built-in: release version"},
	})
	html := render(t, r)
	if !strings.Contains(html, `id="cat-files"`) {
		t.Error("files section missing")
	}
	for _, c := range []string{"outbound", "crypto", "schema", "host", "deps", "config"} {
		if strings.Contains(html, `id="cat-`+c+`"`) || strings.Contains(html, `href="#cat-`+c+`"`) {
			t.Errorf("empty %s still has a section or link", c)
		}
	}
	if strings.Count(html, `class="cat"`) != len(core.Categories) {
		t.Errorf("strip should list all %d categories", len(core.Categories))
	}
	if !strings.Contains(html, "1 suppressed") {
		t.Error("suppressed-only category does not say so in the strip")
	}
}
