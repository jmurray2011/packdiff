// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func lines(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s %d", prefix, i)
	}
	return out
}

func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestLineDiffBoundedMemory(t *testing.T) {
	// Not parallel: measures allocations.
	a, b := lines("old", 5000), lines("new", 5000) // nothing in common: a full table would be 25M cells
	var got []string
	if n := allocated(func() { got = lineDiff(a, b) }); n > 64<<20 {
		t.Fatalf("lineDiff allocated %d MB", n>>20)
	}
	if len(got) != 10000 || got[0] != "- old 0" || got[len(got)-1] != "+ new 4999" {
		t.Fatalf("fallback diff wrong: %d lines, first %q last %q", len(got), got[0], got[len(got)-1])
	}
}

func TestLineDiffTrimsCommonEnds(t *testing.T) {
	t.Parallel()
	a := append(append(lines("same", 30000), "groupadd app"), lines("tail", 30000)...)
	b := append(append(lines("same", 30000), "groupadd -r app", "useradd app"), lines("tail", 30000)...)
	got := lineDiff(a, b)
	if want := []string{"+ groupadd -r app", "+ useradd app", "- groupadd app"}; !slices.Equal(sortedCopy(got), sortedCopy(want)) {
		t.Fatalf("got %q", got)
	}
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

func TestYAMLAliasesNotExpanded(t *testing.T) {
	t.Parallel()
	var doc strings.Builder
	doc.WriteString("l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 9; i++ {
		fmt.Fprintf(&doc, "l%d: &l%d [*l%d, *l%d, *l%d, *l%d, *l%d, *l%d, *l%d, *l%d, *l%d, *l%d]\n", i, i, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1)
	}
	keys := yamlKeys([]byte(doc.String()))
	if len(keys) > 200 {
		t.Fatalf("aliases expanded: %d keys", len(keys))
	}
	if keys["l1[0]"] != "*l0" || keys["l0[3]"] != "x" {
		t.Fatalf("l1[0]=%q l0[3]=%q", keys["l1[0]"], keys["l0[3]"])
	}
}
