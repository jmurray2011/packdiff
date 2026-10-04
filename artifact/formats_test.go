// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"context"
	"encoding/hex"
	"testing"
)

// appTarBz2 is app/app.properties ("a=1\n") as a bzip2 tar, made with the bzip2 tool
// because the standard library cannot write bzip2.
const appTarBz2 = "425a68393141592653593cb349cf00008f7f80c99000044001f7820001000462" +
	"20de00040820007412936aa6d4604c4d901941254d0d0f486400683e9b42302b" +
	"4806b12422449ec1697d4e1e21140a2e62638ed944880d29c405e89be05d6163" +
	"89f570595c909a44d3fcb5a1c402b2dde86be3ec9a96b770150a943dd4c8660f" +
	"e2ee48a70a1207966939e0"

func TestOpenTarFormats(t *testing.T) {
	t.Parallel()
	plain := tarBytes(t, map[string][]byte{"app/app.properties": []byte("a=1\n")})
	bz2, err := hex.DecodeString(appTarBz2)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, typ string
		data      []byte
	}{
		{"app-1.0.tar", "tar", plain},
		{"app-1.0.tar.xz", "tar.xz", compress(t, "xz", plain)},
		{"app-1.0.tar.zst", "tar.zst", compress(t, "zst", plain)},
		{"app-1.0.tar.bz2", "tar.bz2", bz2},
		{"app-1.0.tar.gz", "tar.gz", tarGz(t, map[string][]byte{"app/app.properties": []byte("a=1\n")}, 0o644)},
	} {
		s, err := Open(context.Background(), writeFile(t, c.name, c.data), Options{Want: wantProps})
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if s.Artifact.Type != c.typ || s.Artifact.Name != "app" || s.Artifact.Version != "1.0" {
			t.Errorf("%s: artifact = %+v", c.name, s.Artifact)
		}
		if f := byKey(s)["app/app.properties"]; string(f.Content) != "a=1\n" {
			t.Errorf("%s: content = %q", c.name, f.Content)
		}
	}
}

func TestOpenSelfExtractingJar(t *testing.T) {
	t.Parallel()
	// Spring Boot "fully executable" jars and similar put a launch script before the zip.
	data := append([]byte("#!/bin/sh\nexec java -jar \"$0\" \"$@\"\n"), jar(t)...)
	s, err := Open(context.Background(), writeFile(t, "server-3.4.0-exec.jar", data), Options{Want: wantProps})
	if err != nil {
		t.Fatal(err)
	}
	if s.Artifact.Type != "jar" {
		t.Fatalf("type = %q", s.Artifact.Type)
	}
	if _, ok := byKey(s)["com/example/Geo.class"]; !ok {
		t.Fatal("zip after the launch script not walked")
	}
}

func TestNestedTarballsWalked(t *testing.T) {
	t.Parallel()
	inner := tarGz(t, map[string][]byte{"bundle/conf/app.properties": []byte("b=2\n")}, 0o644)
	xzInner := compress(t, "xz", tarBytes(t, map[string][]byte{"tools/run.properties": []byte("c=3\n")}))
	p := writeFile(t, "app-1.0.zip", zipBytes(t, map[string][]byte{
		"dist/bundle-1.0.tar.gz": inner,
		"dist/tools.tar.xz":      xzInner,
	}))
	s, err := Open(context.Background(), p, Options{Want: wantProps})
	if err != nil {
		t.Fatal(err)
	}
	files := byKey(s)
	if f := files["dist/bundle-1.0.tar.gz!bundle/conf/app.properties"]; string(f.Content) != "b=2\n" {
		t.Errorf("nested tar.gz entry = %+v", f)
	}
	if f := files["dist/tools.tar.xz!tools/run.properties"]; string(f.Content) != "c=3\n" {
		t.Errorf("nested tar.xz entry = %+v", f)
	}
}
