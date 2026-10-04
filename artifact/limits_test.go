// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// nestedZips wraps a properties file in depth levels of jars.
func nestedZips(t *testing.T, depth int) []byte {
	t.Helper()
	inner := zipBytes(t, map[string][]byte{"app.properties": []byte("a=1\n")})
	for i := 0; i < depth; i++ {
		inner = zipBytes(t, map[string][]byte{fmt.Sprintf("lib/level%d.jar", i): inner})
	}
	return inner
}

func TestWalkDepthLimit(t *testing.T) {
	t.Parallel()
	lim := defaultLimits
	lim.depth = 3
	ok := writeFile(t, "ok-1.0.zip", nestedZips(t, 3))
	if _, err := open(context.Background(), ok, Options{Want: wantProps}, lim); err != nil {
		t.Fatalf("depth at the limit: %v", err)
	}
	deep := writeFile(t, "deep-1.0.zip", nestedZips(t, 4))
	if _, err := open(context.Background(), deep, Options{Want: wantProps}, lim); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("err = %v", err)
	}
}

func TestWalkLiveBudget(t *testing.T) {
	t.Parallel()
	lim := defaultLimits
	// Incompressible padding so the jar sizes are predictable: inner ~2.1 KB, outer ~2.3 KB.
	var pad []byte
	for sum := sha256.Sum256(nil); len(pad) < 2000; sum = sha256.Sum256(sum[:]) {
		pad = append(pad, sum[:]...)
	}
	p := writeFile(t, "app-1.0.zip", zipBytes(t, map[string][]byte{
		"lib/outer.jar": zipBytes(t, map[string][]byte{
			"lib/inner.jar": zipBytes(t, map[string][]byte{"pad.bin": pad}),
		}),
	}))
	lim.live = 3000 // the outer jar fits alone; outer plus inner held together does not
	_, err := open(context.Background(), p, Options{Want: func([]string) bool { return false }}, lim)
	if !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "inner.jar") {
		t.Fatalf("err = %v", err)
	}
	lim.live = 10000
	if _, err := open(context.Background(), p, Options{Want: func([]string) bool { return false }}, lim); err != nil {
		t.Fatalf("within budget: %v", err)
	}
}

func TestWalkKeptBudget(t *testing.T) {
	t.Parallel()
	lim := defaultLimits
	lim.kept = 100
	files := map[string][]byte{}
	for i := 0; i < 5; i++ {
		files[fmt.Sprintf("conf/%d.properties", i)] = []byte(strings.Repeat("k=v\n", 10)) // 40 bytes each
	}
	p := writeFile(t, "app-1.0.zip", zipBytes(t, files))
	if _, err := open(context.Background(), p, Options{Want: wantProps}, lim); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestKeptEntryReadsOnlyToCaptureLimit(t *testing.T) {
	t.Parallel()
	lim := defaultLimits
	lim.keep = 64
	lim.nested = 1 << 20
	// The entry is wanted but not an archive, and larger than the capture limit:
	// it must be hashed and recorded without its content, not buffered up to the nested limit.
	p := writeFile(t, "app-1.0.zip", zipBytes(t, map[string][]byte{"big.properties": []byte(strings.Repeat("k=v\n", 1000))}))
	s, err := open(context.Background(), p, Options{Want: wantProps}, lim)
	if err != nil {
		t.Fatal(err)
	}
	f := byKey(s)["big.properties"]
	if f.Content != nil || f.Size != 4000 || f.SHA256 == "" {
		t.Fatalf("oversized wanted entry = size %d content %d", f.Size, len(f.Content))
	}
}
