// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
)

// classBytes builds a minimal class file whose constant pool holds the given UTF-8
// strings, a long (two slots), and a String constant pointing at the first string.
func classBytes(strs ...string) []byte {
	var b bytes.Buffer
	w := func(v any) { _ = binary.Write(&b, binary.BigEndian, v) }
	w(uint32(0xCAFEBABE))
	w(uint16(0))
	w(uint16(61))
	w(uint16(len(strs) + 4)) // utf8s + long(2) + string(1) + 1
	for _, s := range strs {
		w(uint8(1))
		w(uint16(len(s)))
		b.WriteString(s)
	}
	w(uint8(5))
	w(uint64(1 << 40))
	w(uint8(8))
	w(uint16(1))
	b.Write(make([]byte, 16)) // access, this, super, counts: ignored by the parser
	return b.Bytes()
}

func TestClassStrings(t *testing.T) {
	t.Parallel()
	got, err := ClassStrings(classBytes("https://api.example.net/v1", "${geo.timeout:30}", "AES/GCM/NoPadding"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://api.example.net/v1", "${geo.timeout:30}", "AES/GCM/NoPadding"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestClassStringsRejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := ClassStrings([]byte("not a class")); !errors.Is(err, ErrClassFormat) {
		t.Fatalf("err = %v", err)
	}
	trunc := classBytes("abc")
	if _, err := ClassStrings(trunc[:14]); !errors.Is(err, ErrClassFormat) {
		t.Fatalf("truncated err = %v", err)
	}
	bad := classBytes("abc")
	bad[10] = 99 // unknown tag
	if _, err := ClassStrings(bad); !errors.Is(err, ErrClassFormat) {
		t.Fatalf("bad tag err = %v", err)
	}
}
