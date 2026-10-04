// SPDX-License-Identifier: Apache-2.0

package core

import "testing"

func FuzzClassStrings(f *testing.F) {
	f.Add(classBytes("https://geo.example.net", "AES/GCM/NoPadding"))
	f.Add([]byte("\xca\xfe\xba\xbe\x00\x00\x00\x3d\xff\xff"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		strs, err := ClassStrings(data)
		if err != nil {
			return
		}
		n := 0
		for _, s := range strs {
			n += len(s)
		}
		if n > len(data) {
			t.Fatalf("returned %d bytes of strings from %d bytes of input", n, len(data))
		}
	})
}
