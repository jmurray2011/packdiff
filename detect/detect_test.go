// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jmurray2011/packdiff/core"
)

type file struct {
	path    string
	content string
	mode    uint32
	owner   string
	config  bool
}

func snap(name string, scripts map[string]string, requires []string, files ...file) core.Snapshot {
	s := core.Snapshot{
		Artifact: core.Artifact{Name: "app"},
		Package:  core.Package{Scripts: scripts, Requires: requires},
	}
	for _, f := range files {
		mode := f.mode
		if mode == 0 {
			mode = 0o100644
		}
		owner := f.owner
		if owner == "" {
			owner = "root:root"
		}
		u, g, _ := strings.Cut(owner, ":")
		cf := core.File{
			Chain: append([]string{name}, strings.Split(f.path, "!")...), Mode: mode, User: u, Group: g,
			Config: f.config, SHA256: fmt.Sprintf("%x", f.content),
		}
		if f.content != "" {
			cf.Content = []byte(f.content)
		}
		s.Files = append(s.Files, cf)
	}
	return s
}

func find(t *testing.T, cs []core.Change, cat core.Category, subject string) core.Change {
	t.Helper()
	for _, c := range cs {
		if c.Category == cat && c.Subject == subject {
			return c
		}
	}
	var got []string
	for _, c := range cs {
		got = append(got, fmt.Sprintf("%s %s %s", c.Category, c.Kind, c.Subject))
	}
	t.Fatalf("no %s change %q in:\n%s", cat, subject, strings.Join(got, "\n"))
	return core.Change{}
}

func absent(t *testing.T, cs []core.Change, cat core.Category, subject string) {
	t.Helper()
	for _, c := range cs {
		if c.Category == cat && strings.Contains(c.Subject, subject) {
			t.Fatalf("unexpected %s change %+v", cat, c)
		}
	}
}

func val(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func TestConfig(t *testing.T) {
	t.Parallel()
	base := snap(
		"app-1.2.3.rpm", nil, nil,
		file{path: "opt/app/conf/app.properties", content: "timeout = 30\nold.key=1\ndb.password=hunter2\nmulti=a \\\n  b\n"},
		file{path: "opt/app/app-1.2.3.war!WEB-INF/classes/application.yml", content: "server:\n  port: 8080\nfeature:\n  flags: [a, b]\n"},
		file{path: "opt/app/tomcat/bin/setenv.sh", content: "export CATALINA_OPTS=\"$CATALINA_OPTS -Xmx2g -Dapp.mode=prod\"\n"},
		file{path: "opt/app/lib/geo-1.0.jar!geo.properties", content: "endpoint=a\n"},
	)
	head := snap(
		"app-1.2.4.rpm", nil, nil,
		file{path: "opt/app/conf/app.properties", content: "timeout=60\nnew.key: 2\ndb.password=hunter3\nmulti=a b\n"},
		file{path: "opt/app/app-1.2.4.war!WEB-INF/classes/application.yml", content: "server:\n  port: 8443\nfeature:\n  flags: [a, c]\n"},
		file{path: "opt/app/tomcat/bin/setenv.sh", content: "export CATALINA_OPTS=\"$CATALINA_OPTS -Xmx4g -Dapp.mode=prod\"\n"},
		file{path: "opt/app/lib/geo-1.1.jar!geo.properties", content: "endpoint=b\n"},
		file{path: "etc/app/app.env", content: "# comment\nAPP_REGION=\"us-east\"\n"},
	)
	cs := Run(base, head, Options{})

	c := find(t, cs, core.Config, "opt/app/conf/app.properties#timeout")
	if c.Kind != core.Changed || val(c.Before) != "30" || val(c.After) != "60" {
		t.Fatalf("timeout = %+v", c)
	}
	if c.Locations[0].Chain[0] != "app-1.2.4.rpm" {
		t.Fatalf("changed key should locate in head: %v", c.Locations)
	}
	if c := find(t, cs, core.Config, "opt/app/conf/app.properties#old.key"); c.Kind != core.Removed || c.Locations[0].Chain[0] != "app-1.2.3.rpm" {
		t.Fatalf("old.key = %+v", c)
	}
	if c := find(t, cs, core.Config, "opt/app/conf/app.properties#new.key"); c.Kind != core.Added || val(c.After) != "2" {
		t.Fatalf("new.key = %+v", c)
	}
	pw := find(t, cs, core.Config, "opt/app/conf/app.properties#db.password")
	if !strings.HasPrefix(val(pw.Before), "<redacted:") || val(pw.Before) == val(pw.After) || strings.Contains(val(pw.After), "hunter") {
		t.Fatalf("secret not redacted: %+v", pw)
	}
	absent(t, cs, core.Config, "#multi")

	if c := find(t, cs, core.Config, "opt/app/app.war!WEB-INF/classes/application.yml#server.port"); val(c.After) != "8443" {
		t.Fatalf("yaml key = %+v", c)
	}
	if c := find(t, cs, core.Config, "opt/app/app.war!WEB-INF/classes/application.yml#feature.flags[1]"); val(c.Before) != "b" {
		t.Fatalf("yaml list = %+v", c)
	}
	if c := find(t, cs, core.Config, "opt/app/tomcat/bin/setenv.sh#-Xmx"); val(c.After) != "4g" {
		t.Fatalf("setenv jvm option = %+v", c)
	}
	absent(t, cs, core.Config, "app.mode")
	if c := find(t, cs, core.Config, "etc/app/app.env#APP_REGION"); c.Kind != core.Added || val(c.After) != "us-east" {
		t.Fatalf("env = %+v", c)
	}
	absent(t, cs, core.Config, "geo.properties")
}

func TestSchema(t *testing.T) {
	t.Parallel()
	base := snap(
		"app-1.2.3.rpm", nil, nil,
		file{path: "opt/app/db/V1__init.sql", content: "create table a (id int);"},
		file{path: "opt/app/db/V2__old.sql", content: "select 1;"},
		file{path: "opt/app/db/db-migrate-2.10.01.sql", content: "select 1;"},
	)
	head := snap(
		"app-1.2.4.rpm", nil, nil,
		file{path: "opt/app/db/V1__init.sql", content: "create table a (id bigint);"},
		file{path: "opt/app/db/db-migrate-2.10.01.sql", content: "select 1;"},
		file{path: "opt/app/db/V3__geo.sql", content: `-- adds geo
CREATE TABLE IF NOT EXISTS public.geo_cache (id bigint primary key);
ALTER TABLE accounts ADD COLUMN region text, DROP COLUMN legacy;
DROP TABLE old_stuff;
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
GRANT SELECT ON geo_cache TO reporting;
/* ALTER TABLE ignored DROP COLUMN x; */`},
		file{path: "opt/app/db/changelog/db.changelog-master.xml", content: "<databaseChangeLog/>"},
		file{path: "opt/app/lib/x-1.0.jar!db/migration/V1__lib.sql", content: "create table lib (id int);"},
	)
	cs := Run(base, head, Options{})

	mod := find(t, cs, core.Schema, "opt/app/db/V1__init.sql")
	if mod.Kind != core.Changed || !slices.ContainsFunc(mod.Details, func(d string) bool { return strings.Contains(d, "applied migration modified") }) {
		t.Fatalf("modified migration = %+v", mod)
	}
	if c := find(t, cs, core.Schema, "opt/app/db/V2__old.sql"); c.Kind != core.Removed {
		t.Fatalf("removed = %+v", c)
	}
	add := find(t, cs, core.Schema, "opt/app/db/V3__geo.sql")
	want := []string{
		"alter table accounts: add column region",
		"alter table accounts: drop column legacy",
		"create extension pgcrypto",
		"create table public.geo_cache",
		"drop table old_stuff",
		"grant select on geo_cache to reporting",
	}
	if add.Kind != core.Added || !slices.Equal(add.Details, want) {
		t.Fatalf("details:\n got %q\nwant %q", add.Details, want)
	}
	find(t, cs, core.Schema, "opt/app/db/changelog/db.changelog-master.xml")
	absent(t, cs, core.Schema, "db-migrate-2.10.01")
	absent(t, cs, core.Schema, "V1__lib")
}

func TestHost(t *testing.T) {
	t.Parallel()
	base := snap(
		"app-1.2.3.rpm",
		map[string]string{"preinstall": "groupadd -r app\n", "postuninstall": "rm -rf /opt/app\n"},
		[]string{"java-11-headless", "shadow-utils"},
		file{path: "opt/app/bin/run.sh", content: "#!/bin/sh", mode: 0o100755},
		file{path: "opt/app/conf/app.properties", content: "server.port=8080\n", mode: 0o100644, owner: "root:app", config: true},
		file{path: "opt/app/tomcat/conf/server.xml", content: `<Server port="8005"><Service><Connector port="8080" protocol="HTTP/1.1"/></Service></Server>`},
		file{path: "usr/lib/systemd/system/app.service", content: "[Service]\nUser=app\nExecStart=/opt/app/bin/run.sh\nNoNewPrivileges=true\n"},
		file{path: "opt/app/webapp/WEB-INF/classes/com/example/Old.class", content: "x"},
	)
	head := snap(
		"app-1.2.4.rpm",
		map[string]string{"preinstall": "getent group app || groupadd -r app\nuseradd -r -g app -d /opt/app -s /sbin/nologin app || :\n", "posttrans": "systemctl daemon-reload\n"},
		[]string{"java-17-headless", "shadow-utils"},
		file{path: "opt/app/bin/run.sh", content: "#!/bin/sh", mode: 0o104755},
		file{path: "opt/app/bin/admin.sh", content: "#!/bin/sh", mode: 0o100750},
		file{path: "opt/app/conf/app.properties", content: "server.port=9090\n", mode: 0o100640, owner: "root:app", config: true},
		file{path: "opt/app/tomcat/conf/server.xml", content: `<Server port="8005"><Service><Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"/><!-- <Connector port="8009"/> --></Service></Server>`},
		file{path: "usr/lib/systemd/system/app.service", content: "[Service]\nUser=root\nExecStart=/opt/app/bin/run.sh --debug\n"},
		file{path: "opt/app/webapp/WEB-INF/classes/com/example/New.class", content: "y"},
	)
	cs := Run(base, head, Options{})

	pre := find(t, cs, core.Host, "script:preinstall")
	if pre.Kind != core.Changed || !slices.Contains(pre.Details, "+ useradd -r -g app -d /opt/app -s /sbin/nologin app || :") ||
		!slices.Contains(pre.Details, "- groupadd -r app") {
		t.Fatalf("preinstall = %+v", pre)
	}
	if c := find(t, cs, core.Host, "script:postuninstall"); c.Kind != core.Removed {
		t.Fatalf("postuninstall = %+v", c)
	}
	find(t, cs, core.Host, "script:posttrans")
	if c := find(t, cs, core.Host, "user:app"); c.Kind != core.Added {
		t.Fatalf("user = %+v", c)
	}
	absent(t, cs, core.Host, "group:app")

	if c := find(t, cs, core.Host, "requires:java-17-headless"); c.Kind != core.Added {
		t.Fatalf("requires = %+v", c)
	}
	find(t, cs, core.Host, "requires:java-11-headless")

	run := find(t, cs, core.Host, "file:opt/app/bin/run.sh")
	if run.Kind != core.Changed || !strings.Contains(val(run.After), "mode=4755") || !slices.Contains(run.Details, "setuid added") {
		t.Fatalf("setuid = %+v", run)
	}
	if c := find(t, cs, core.Host, "file:opt/app/bin/admin.sh"); c.Kind != core.Added {
		t.Fatalf("new executable = %+v", c)
	}
	if c := find(t, cs, core.Host, "file:opt/app/conf/app.properties"); !strings.Contains(val(c.Before), "mode=0644") {
		t.Fatalf("config mode = %+v", c)
	}
	absent(t, cs, core.Host, ".class")

	for _, s := range []string{"listen:9090", "listen:8443"} {
		if c := find(t, cs, core.Host, s); c.Kind != core.Added {
			t.Fatalf("%s = %+v", s, c)
		}
	}
	for _, s := range []string{"listen:8080"} {
		if c := find(t, cs, core.Host, s); c.Kind != core.Removed {
			t.Fatalf("%s = %+v", s, c)
		}
	}
	absent(t, cs, core.Host, "listen:8005")
	absent(t, cs, core.Host, "listen:8009")

	if c := find(t, cs, core.Host, "unit:app.service#User"); val(c.Before) != "app" || val(c.After) != "root" {
		t.Fatalf("unit user = %+v", c)
	}
	find(t, cs, core.Host, "unit:app.service#ExecStart")
	if c := find(t, cs, core.Host, "unit:app.service#NoNewPrivileges"); c.Kind != core.Removed {
		t.Fatalf("sandboxing = %+v", c)
	}
}

func TestWants(t *testing.T) {
	t.Parallel()
	w := Wants(nil)
	for _, p := range []string{"opt/app/app.properties", "opt/app/db/V1__x.sql", "usr/lib/systemd/system/app.service", "opt/app/tomcat/conf/server.xml", "opt/app/tomcat/bin/setenv.sh"} {
		if !w([]string{"a.rpm", p}) {
			t.Errorf("not wanted: %s", p)
		}
	}
	for _, c := range [][]string{{"a.rpm", "opt/app/lib/x.jar", "x.properties"}, {"a.rpm", "opt/app/Big.class"}, {"a.rpm", "opt/app/web/index.html"}} {
		if w(c) {
			t.Errorf("wanted: %v", c)
		}
	}
}

func TestDeps(t *testing.T) {
	t.Parallel()
	loc := func(a, p string) core.Location { return core.Location{Chain: []string{a, p}} }
	base := core.Snapshot{Components: []core.Component{
		{Type: "java-archive", Name: "geo", Version: "1.0", PURL: "pkg:maven/org.example/geo@1.0", Group: "org.example", Location: loc("a-1.rpm", "opt/app/lib/geo-1.0.jar")},
		{Type: "java-archive", Name: "old", Version: "2.0", PURL: "pkg:maven/org.example/old@2.0", Group: "org.example", Location: loc("a-1.rpm", "opt/app/lib/old-2.0.jar")},
		{Type: "java-archive", Name: "same", Version: "3.0", PURL: "pkg:maven/org.example/same@3.0?type=jar", Group: "org.example", Location: loc("a-1.rpm", "opt/app/lib/same-3.0.jar")},
	}}
	head := core.Snapshot{Components: []core.Component{
		{Type: "java-archive", Name: "geo", Version: "1.1", PURL: "pkg:maven/org.example/geo@1.1", Group: "org.example", Location: loc("a-2.rpm", "opt/app/lib/geo-1.1.jar")},
		{Type: "java-archive", Name: "same", Version: "3.0", PURL: "pkg:maven/org.example/same@3.0?type=jar", Group: "org.example", Location: loc("a-2.rpm", "opt/app/lib/same-3.0.jar")},
		{Type: "npm", Name: "left-pad", Version: "1.3.0", PURL: "pkg:npm/left-pad@1.3.0", Location: loc("a-2.rpm", "opt/app/web/package.json")},
		{Type: "binary", Name: "mystery", Version: "", Location: loc("a-2.rpm", "opt/app/bin/x")},
	}}
	base.Components = append(base.Components,
		core.Component{Type: "java-archive", Name: "xmpcore", Version: "6.0.6", PURL: "pkg:maven/org.example.xmp/xmpcore@6.0.6", Group: "org.example.xmp", Location: loc("a-1.rpm", "opt/app/lib/xmpcore-6.0.6.jar")})
	head.Components = append(head.Components,
		// No pom.properties: syft guesses groups from manifest headers.
		core.Component{Type: "java-archive", Name: "xmpcore", Version: "6.1.11", PURL: "pkg:maven/org.example.xmp.xmpcore/xmpcore@6.1.11", Location: loc("a-2.rpm", "opt/app/lib/xmpcore-6.1.11.jar")},
		core.Component{Type: "java-archive", Name: "stax-asl", Version: "4.2.0", PURL: "pkg:maven/org.example.stax.osgi.Activator/stax-asl@4.2.0", Location: loc("a-2.rpm", "opt/app/lib/stax-asl-4.2.0.jar")})
	// No pom.properties in either release, but a plausible group syft guessed the same way twice.
	base.Components = append(base.Components,
		core.Component{Type: "java-archive", Name: "cryptoprov", Version: "1.72", PURL: "pkg:maven/org.example.crypto/cryptoprov@1.72", Location: loc("a-1.rpm", "opt/app/lib/cryptoprov-1.72.jar")})
	head.Components = append(head.Components,
		core.Component{Type: "java-archive", Name: "cryptoprov", Version: "1.85", PURL: "pkg:maven/org.example.crypto/cryptoprov@1.85", Location: loc("a-2.rpm", "opt/app/lib/cryptoprov-1.85.jar")})
	// Real groups often end in the artifact name; a generic artifact name must not pull an
	// unrelated jar into another group.
	for _, s := range []*core.Snapshot{&base, &head} {
		s.Components = append(s.Components,
			core.Component{Type: "java-archive", Name: "db", Version: "42.7", PURL: "pkg:maven/org.example.db/db@42.7", Location: loc("a.rpm", "opt/app/lib/db-42.7.jar")},
			core.Component{Type: "java-archive", Name: "annotations", Version: "12.0", PURL: "pkg:maven/annotations/annotations@12.0", Location: loc("a.rpm", "opt/app/lib/annotations-12.0.jar")})
	}
	base.Components = append(base.Components,
		core.Component{Type: "java-archive", Name: "annotations", Version: "2.31", Group: "org.example.sdk", PURL: "pkg:maven/org.example.sdk/annotations@2.31", Location: loc("a-1.rpm", "opt/app/lib/annotations-2.31.jar")})
	head.Components = append(head.Components,
		core.Component{Type: "java-archive", Name: "annotations", Version: "2.41", Group: "org.example.sdk", PURL: "pkg:maven/org.example.sdk/annotations@2.41", Location: loc("a-2.rpm", "opt/app/lib/annotations-2.41.jar")})
	cs := Run(base, head, Options{})
	if c := find(t, cs, core.Deps, "org.example.sdk:annotations"); val(c.Before) != "2.31" || val(c.After) != "2.41" {
		t.Fatalf("unrelated jar merged into confirmed group: %+v", c)
	}
	absent(t, cs, core.Deps, "org.example.db")
	if c := find(t, cs, core.Deps, "org.example.crypto:cryptoprov"); c.Kind != core.Changed || val(c.After) != "1.85" {
		t.Fatalf("consistent plausible guess dropped: %+v", c)
	}
	if c := find(t, cs, core.Deps, "org.example.xmp:xmpcore"); c.Kind != core.Changed || val(c.Before) != "6.0.6" || val(c.After) != "6.1.11" {
		t.Fatalf("guessed group not resolved to confirmed one: %+v", c)
	}
	absent(t, cs, core.Deps, "org.example.xmp.xmpcore")
	if c := find(t, cs, core.Deps, "stax-asl"); c.Kind != core.Added {
		t.Fatalf("unconfirmed group should key by artifact: %+v", c)
	}
	absent(t, cs, core.Deps, "Activator")
	if c := find(t, cs, core.Deps, "org.example:geo"); c.Kind != core.Changed || val(c.Before) != "1.0" || val(c.After) != "1.1" {
		t.Fatalf("geo = %+v", c)
	}
	if c := find(t, cs, core.Deps, "org.example:old"); c.Kind != core.Removed {
		t.Fatalf("old = %+v", c)
	}
	if c := find(t, cs, core.Deps, "npm/left-pad"); c.Kind != core.Added {
		t.Fatalf("npm = %+v", c)
	}
	find(t, cs, core.Deps, "binary/mystery")
	absent(t, cs, core.Deps, "same")
}

func TestVersionedRootDirectory(t *testing.T) {
	t.Parallel()
	base := snap("app-1.2.3.tar.gz", nil, nil,
		file{path: "app-1.2.3/conf/app.properties", content: "timeout=30\nsame=1\n"},
		file{path: "app-1.2.3/bin/run.sh", content: "#!/bin/sh", mode: 0o100755})
	head := snap("app-1.2.4.tar.gz", nil, nil,
		file{path: "app-1.2.4/conf/app.properties", content: "timeout=60\nsame=1\n"},
		file{path: "app-1.2.4/bin/run.sh", content: "#!/bin/sh", mode: 0o100755})
	cs := Run(base, head, Options{})
	if c := find(t, cs, core.Config, "app/conf/app.properties#timeout"); c.Kind != core.Changed {
		t.Fatalf("timeout = %+v", c)
	}
	if len(cs) != 1 {
		t.Fatalf("versioned root produced spurious changes: %d", len(cs))
	}
}

func TestBulkAttributeChangesGrouped(t *testing.T) {
	t.Parallel()
	var bf, hf []file
	for i := 0; i < 30; i++ {
		p := fmt.Sprintf("opt/app/web/page%02d.html", i)
		bf = append(bf, file{path: p, content: "x", mode: 0o100644})
		hf = append(hf, file{path: p, content: "x", mode: 0o100664})
	}
	bf = append(bf, file{path: "opt/app/bin/run.sh", content: "#!", mode: 0o100755})
	hf = append(hf, file{path: "opt/app/bin/run.sh", content: "#!", mode: 0o104755})
	cs := Run(snap("app-1.rpm", nil, nil, bf...), snap("app-2.rpm", nil, nil, hf...), Options{})

	var host []core.Change
	for _, c := range cs {
		if c.Category == core.Host {
			host = append(host, c)
		}
	}
	if len(host) != 2 {
		t.Fatalf("want 1 grouped change + 1 single change, got %d", len(host))
	}
	g := find(t, cs, core.Host, "files:mode=0644 owner=root:root -> mode=0664 owner=root:root")
	if g.Kind != core.Changed || len(g.Locations) != 30 || !slices.Contains(g.Details, "30 files") || !slices.Contains(g.Details, "opt/app/web/page07.html") {
		t.Fatalf("grouped = %+v", g)
	}
	find(t, cs, core.Host, "file:opt/app/bin/run.sh")
}

func TestINIAndSysconfig(t *testing.T) {
	t.Parallel()
	base := snap("app-1.rpm", nil, nil,
		file{path: "usr/share/app/conf/defaults.ini", content: "; c\n[server]\nhttp_port = 3000\n[security]\nadmin_password = old\n"},
		file{path: "etc/sysconfig/app-server", content: "APP_HOME=/usr/share/app\nMAX_OPEN_FILES=10000\n"},
		file{path: "etc/default/app", content: "export APP_OPTS=\"-Xmx1g\"\n"})
	head := snap("app-2.rpm", nil, nil,
		file{path: "usr/share/app/conf/defaults.ini", content: "; c\n[server]\nhttp_port = 3001\n[security]\nadmin_password = new\n"},
		file{path: "etc/sysconfig/app-server", content: "APP_HOME=/usr/share/app\nMAX_OPEN_FILES=20000\n"},
		file{path: "etc/default/app", content: "export APP_OPTS=\"-Xmx2g\"\n"})
	cs := Run(base, head, Options{})
	if c := find(t, cs, core.Config, "usr/share/app/conf/defaults.ini#server.http_port"); val(c.After) != "3001" {
		t.Fatalf("ini = %+v", c)
	}
	if c := find(t, cs, core.Config, "usr/share/app/conf/defaults.ini#security.admin_password"); !strings.HasPrefix(val(c.After), "<redacted:") {
		t.Fatalf("ini secret not redacted: %+v", c)
	}
	if c := find(t, cs, core.Config, "etc/sysconfig/app-server#MAX_OPEN_FILES"); val(c.After) != "20000" {
		t.Fatalf("sysconfig = %+v", c)
	}
	if c := find(t, cs, core.Config, "etc/default/app#-Xmx"); val(c.After) != "2g" {
		t.Fatalf("default = %+v", c)
	}
	if !Wants(nil)([]string{"a.rpm", "etc/sysconfig/app-server"}) || !Wants(nil)([]string{"a.rpm", "usr/share/app/conf/defaults.ini"}) {
		t.Fatal("new config files not captured")
	}
}

func TestFiles(t *testing.T) {
	t.Parallel()
	base := []file{
		{path: "usr/sbin/appd", content: "elf-v1", mode: 0o100755},
		{path: "usr/share/app/old.dat", content: "gone"},
		{path: "usr/share/app/same.dat", content: "same"},
		{path: "etc/app/app.properties", content: "timeout=30\n"},
		{path: "etc/app/notes.properties", content: "# v1\nk=v\n"},
		{path: "opt/app/lib/geo-1.0.jar!com/example/A.class", content: "a1"},
	}
	head := []file{
		{path: "usr/sbin/appd", content: "elf-v2", mode: 0o100755},
		{path: "usr/share/app/new.dat", content: "new"},
		{path: "usr/share/app/same.dat", content: "same"},
		{path: "etc/app/app.properties", content: "timeout=60\n"},
		{path: "etc/app/notes.properties", content: "# v2\nk=v\n"},
		{path: "opt/app/lib/geo-1.0.jar!com/example/A.class", content: "a2"},
	}
	for i := 0; i < 25; i++ {
		base = append(base, file{path: fmt.Sprintf("usr/share/app/static/p%02d.js", i), content: "old"})
		head = append(head, file{path: fmt.Sprintf("usr/share/app/static/p%02d.js", i), content: "new"})
	}
	cs := Run(snap("app-1.rpm", nil, nil, base...), snap("app-2.rpm", nil, nil, head...), Options{})

	d := find(t, cs, core.Files, "usr/sbin/appd")
	if d.Kind != core.Changed || !strings.HasPrefix(val(d.Before), "sha256:") || val(d.Before) == val(d.After) {
		t.Fatalf("binary = %+v", d)
	}
	if c := find(t, cs, core.Files, "usr/share/app/new.dat"); c.Kind != core.Added {
		t.Fatalf("added = %+v", c)
	}
	if c := find(t, cs, core.Files, "usr/share/app/old.dat"); c.Kind != core.Removed {
		t.Fatalf("removed = %+v", c)
	}
	find(t, cs, core.Files, "etc/app/notes.properties") // comment-only edit: no config change
	absent(t, cs, core.Files, "app.properties")         // reported under config
	absent(t, cs, core.Files, "same.dat")
	absent(t, cs, core.Files, "A.class") // inside a jar
	g := find(t, cs, core.Files, "usr/share/app/static/*")
	if g.Kind != core.Changed || !slices.Contains(g.Details, "25 files") || !slices.Contains(g.Details, "usr/share/app/static/p07.js") || len(g.Locations) != 25 {
		t.Fatalf("roll-up = %+v", g)
	}
	absent(t, cs, core.Files, "p07.js")
}

func TestFilesRollUps(t *testing.T) {
	t.Parallel()
	base := []file{{path: "usr/share/app/keep.dat", content: "k"}}
	head := []file{{path: "usr/share/app/keep.dat", content: "k"}}
	for _, d := range []string{"a", "b", "c"} { // a whole tree removed, spread over subdirectories
		base = append(base, file{path: "usr/share/app/old/" + d + "/x.gif", content: "x"}, file{path: "usr/share/app/old/" + d + "/y.gif", content: "y"})
	}
	for _, d := range []string{"en", "de"} { // a whole tree added
		head = append(head, file{path: "opt/app/plugins/ner/" + d + "/model.bin", content: d})
	}
	head = append(head, file{path: "usr/share/app/extra/one.dat", content: "1"}) // new directory, one file
	for i := 0; i < 5; i++ {                                                     // recompiled classes, one per package
		p := fmt.Sprintf("opt/app/WEB-INF/classes/com/example/p%d/Svc.class", i)
		base = append(base, file{path: p, content: "v1"})
		head = append(head, file{path: p, content: "v2"})
	}
	base = append(base, file{path: "opt/app/WEB-INF/classes/com/example/Main.class", content: "m1"})
	head = append(head, file{path: "opt/app/WEB-INF/classes/com/example/Main.class", content: "m1"})
	cs := Run(snap("app-1.rpm", nil, nil, base...), snap("app-2.rpm", nil, nil, head...), Options{})

	var files []core.Change
	for _, c := range cs {
		if c.Category == core.Files {
			files = append(files, c)
		}
	}
	if len(files) != 4 {
		for _, c := range files {
			t.Logf("%s %s", c.Kind, c.Subject)
		}
		t.Fatalf("want 4 files changes, got %d", len(files))
	}
	if c := find(t, cs, core.Files, "usr/share/app/old/**"); c.Kind != core.Removed || !slices.Contains(c.Details, "6 files") || len(c.Locations) != 6 {
		t.Fatalf("removed tree = %+v", c)
	}
	if c := find(t, cs, core.Files, "opt/app/plugins/**"); c.Kind != core.Added || !slices.Contains(c.Details, "2 files") {
		t.Fatalf("added tree = %+v", c)
	}
	if c := find(t, cs, core.Files, "usr/share/app/extra/one.dat"); c.Kind != core.Added {
		t.Fatalf("single new file = %+v", c)
	}
	if c := find(t, cs, core.Files, "opt/app/WEB-INF/classes/**/*.class"); c.Kind != core.Changed || !slices.Contains(c.Details, "5 files") ||
		!slices.Contains(c.Details, "opt/app/WEB-INF/classes/com/example/p3/Svc.class") {
		t.Fatalf("classes = %+v", c)
	}
}
