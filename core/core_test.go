// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func str(s string) *string { return &s }

func sample() []Change {
	return []Change{
		{
			Category: Outbound, Kind: Added, Subject: "https://api.example.net", After: str("https://api.example.net"),
			Locations: []Location{{Chain: []string{"app-1.2.4.rpm", "opt/app/lib/geo-2.0.jar", "com/example/Geo.class"}}},
		},
		{
			Category: Config, Kind: Changed, Subject: "opt/app/app.properties#timeout", Before: str("30"), After: str("60"),
			Locations: []Location{{Chain: []string{"app-1.2.4.rpm", "opt/app/app.properties"}}},
		},
		{Category: Deps, Kind: Added, Subject: "org.example:lib", After: str("1.0")},
	}
}

func TestIDStableAcrossVersions(t *testing.T) {
	t.Parallel()
	a := Change{
		Category: Outbound, Subject: "https://api.example.net",
		Locations: []Location{{Chain: []string{"app-1.2.3.rpm", "opt/app/lib/geo-1.9.jar", "com/example/Geo.class"}}},
	}
	b := a
	b.Locations = []Location{{Chain: []string{"app-1.2.4.rpm", "opt/app/lib/geo-2.0.jar", "com/example/Geo.class"}}}
	if a.StableID() != b.StableID() {
		t.Fatalf("id changed with artifact versions: %s vs %s", a.StableID(), b.StableID())
	}
	c := a
	c.Subject = "https://other.example.net"
	if a.StableID() == c.StableID() {
		t.Fatal("different subjects share an id")
	}
	if !strings.HasPrefix(a.StableID(), "outbound:") {
		t.Fatalf("id lacks category prefix: %s", a.StableID())
	}
}

func TestBuildSortsAndSummarizes(t *testing.T) {
	t.Parallel()
	r := Build(Artifact{Name: "app", Version: "1.2.3"}, Artifact{Name: "app", Version: "1.2.4"}, Options{}, sample())
	if r.Changes[0].Category != Config || r.Changes[2].Category != Deps || r.Changes[0].ID == "" {
		t.Fatalf("changes not sorted by category or missing ids: %+v", r.Changes)
	}
	if s := r.Summary[Config]; s.Changed != 1 || s.Added != 0 {
		t.Fatalf("config summary = %+v", s)
	}
	if s := r.Summary[Deps]; s.Added != 1 {
		t.Fatalf("deps summary = %+v", s)
	}
}

func TestJSONDeterministic(t *testing.T) {
	t.Parallel()
	in := sample()
	rev := []Change{in[2], in[0], in[1]}
	a, err := json.Marshal(Build(Artifact{}, Artifact{}, Options{}, in))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(Build(Artifact{}, Artifact{}, Options{}, rev))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("output depends on input order")
	}
	if !bytes.Contains(a, []byte(`"before":null`)) {
		t.Fatalf("null fields missing: %s", a)
	}
	for _, gone := range []string{`"review"`, `"verdict"`, `"stale_reviews"`, `"unreviewed"`, `"gate"`} {
		if bytes.Contains(a, []byte(gone)) {
			t.Errorf("review field %s still in JSON", gone)
		}
	}
}

func TestTerminal(t *testing.T) {
	t.Parallel()
	r := Build(Artifact{Name: "app", Version: "1.2.3"}, Artifact{Name: "app", Version: "1.2.4"},
		Options{}, sample())
	var buf bytes.Buffer
	if err := r.WriteTerminal(&buf, "summary"); err != nil {
		t.Fatal(err)
	}
	want := "app 1.2.3 -> 1.2.4 | config ~1 | outbound +1 | crypto 0 | schema 0 | host 0 | deps +1 | files 0\n" +
		"config changed opt/app/app.properties#timeout  (30 -> 60)\n" +
		"outbound added https://api.example.net\n" +
		"deps added org.example:lib\n"
	if buf.String() != want {
		t.Fatalf("summary:\n got %q\nwant %q", buf.String(), want)
	}
	buf.Reset()
	mig := Build(Artifact{}, Artifact{}, Options{}, []Change{{
		Category: Schema, Kind: Changed, Subject: "db/V1__init.sql",
		Before: str("sha256:218e98c39bd97258e082df5eb96459a895216fe80e5cd82aa78249326e3f79a0"),
		After:  str("sha256:6d67a6daa4bbf848ad862ada42b5b164a0000000000000000000000000000000"),
	}})
	if err := mig.WriteTerminal(&buf, "summary"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "db/V1__init.sql  (sha256:218e98c39bd9 -> sha256:6d67a6daa4bb)\n") {
		t.Fatalf("hashes not shortened:\n%s", buf.String())
	}
	buf.Reset()
	if err := r.WriteTerminal(&buf, "full"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "deps added org.example:lib") || !strings.Contains(buf.String(), "    at app-1.2.4.rpm > opt/app/app.properties") {
		t.Fatalf("full view:\n%s", buf.String())
	}
}

func TestUnversioned(t *testing.T) {
	t.Parallel()
	got := Unversioned([]string{"app-1.2.4.rpm", "opt/app/app-1.2.4.war", "WEB-INF/lib/geo-2.0.1-SNAPSHOT.jar", "db/V3__x.sql"})
	if want := "opt/app/app.war!WEB-INF/lib/geo.jar!db/V3__x.sql"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	for in, want := range map[string]string{
		"apache-tomcat-10.1.30/conf/server.xml":     "apache-tomcat/conf/server.xml",
		"kafka_2.13-3.7.0/config/server.properties": "kafka/config/server.properties",
		"keycloak-25.0.0/bin/kc.sh":                 "keycloak/bin/kc.sh",
		"usr/share/doc/openssh-server-9.2p1/x":      "usr/share/doc/openssh-server/x",
		"usr/lib/python3.11/site.py":                "usr/lib/python3.11/site.py",
		"usr/lib/x86_64-linux-gnu/libz.so.1":        "usr/lib/x86_64-linux-gnu/libz.so.1",
		"opt/app/v2/handler.js":                     "opt/app/v2/handler.js",
	} {
		if got := Unversioned([]string{"a.tar.gz", in}); got != want {
			t.Errorf("Unversioned(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSuppressedChangesListedSeparately(t *testing.T) {
	t.Parallel()
	cs := sample()
	cs[0].Suppressed = "build metadata"
	cs[1].Suppressed = "build metadata"
	r := Build(Artifact{}, Artifact{}, Options{}, cs)
	if len(r.Changes) != 1 || len(r.Suppressed) != 2 || r.Suppressed[0].ID == "" {
		t.Fatalf("changes=%d suppressed=%+v", len(r.Changes), r.Suppressed)
	}
	if s := r.Summary[Outbound]; s.Suppressed != 1 || s.Added != 0 {
		t.Fatalf("outbound summary = %+v", s)
	}
	var buf bytes.Buffer
	if err := r.WriteTerminal(&buf, "summary"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "2 suppressed by rules") {
		t.Fatalf("suppressed count not shown:\n%s", buf.String())
	}
}
