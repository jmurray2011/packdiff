// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestCatalogFindsNestedJar(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	lib := filepath.Join(dir, "opt", "app", "lib")
	if err := os.MkdirAll(lib, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(lib, "geo-1.0.jar"))
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range map[string]string{
		"META-INF/MANIFEST.MF":                          "Manifest-Version: 1.0\n",
		"META-INF/maven/org.example/geo/pom.properties": "groupId=org.example\nartifactId=geo\nversion=1.0\n",
	} {
		e, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := Catalog(context.Background(), dir, "app-1.0.rpm")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if c.Name == "geo" && c.Version == "1.0" {
			if want := []string{"app-1.0.rpm", "opt/app/lib/geo-1.0.jar"}; len(c.Location.Chain) != 2 || c.Location.Chain[1] != want[1] || c.Location.Chain[0] != want[0] {
				t.Fatalf("location = %v", c.Location.Chain)
			}
			if c.PURL == "" {
				t.Fatal("missing purl")
			}
			if c.Group != "org.example" {
				t.Fatalf("group from pom.properties = %q", c.Group)
			}
			return
		}
	}
	t.Fatalf("geo not cataloged: %+v", got)
}

func TestChainStopsAtMavenCoordinates(t *testing.T) {
	t.Parallel()
	for vp, want := range map[string][]string{
		"/opt/app/tool-all-1.0.jar:org.example:shaded": {"app.rpm", "opt/app/tool-all-1.0.jar"},
		"/opt/app/app.war:WEB-INF/lib/geo-1.0.jar":     {"app.rpm", "opt/app/app.war", "WEB-INF/lib/geo-1.0.jar"},
	} {
		got := chain("app.rpm", pkg.Package{Metadata: pkg.JavaArchive{VirtualPath: vp}})
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %v want %v", vp, got, want)
		}
	}
}

func TestGroupOnlyFromPomProperties(t *testing.T) {
	t.Parallel()
	guessed := pkg.Package{PURL: "pkg:maven/org.example.stax.osgi.Activator/stax-asl@4.2.0", Metadata: pkg.JavaArchive{}}
	if g := group(guessed); g != "" {
		t.Fatalf("guessed group kept: %q", g)
	}
	real := pkg.Package{Metadata: pkg.JavaArchive{PomProperties: &pkg.JavaPomProperties{GroupID: "org.example", ArtifactID: "geo"}}}
	if g := group(real); g != "org.example" {
		t.Fatalf("pom group = %q", g)
	}
}
