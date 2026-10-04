// SPDX-License-Identifier: Apache-2.0

package core

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrClassFormat reports bytes that are not a parseable class file constant pool.
var ErrClassFormat = errors.New("bad class file")

// Fixed payload sizes of constant pool entries after the tag byte; Utf8 is variable.
var cpSize = map[byte]int{
	3: 4, 4: 4, 5: 8, 6: 8, // Integer, Float, Long, Double
	7: 2, 8: 2, 16: 2, 19: 2, 20: 2, // Class, String, MethodType, Module, Package
	9: 4, 10: 4, 11: 4, 12: 4, 17: 4, 18: 4, // refs, NameAndType, Dynamic, InvokeDynamic
	15: 3, // MethodHandle
}

// ClassStrings returns every CONSTANT_Utf8 entry in pool order. Literal strings, annotation
// values, and names all live there; callers filter for what they need.
func ClassStrings(data []byte) ([]string, error) {
	if len(data) < 10 || binary.BigEndian.Uint32(data) != 0xCAFEBABE {
		return nil, fmt.Errorf("%w: missing magic", ErrClassFormat)
	}
	count := int(binary.BigEndian.Uint16(data[8:]))
	pos := 10
	var out []string
	for i := 1; i < count; i++ {
		if pos >= len(data) {
			return nil, fmt.Errorf("%w: truncated at entry %d", ErrClassFormat, i)
		}
		tag := data[pos]
		pos++
		if tag == 1 {
			if pos+2 > len(data) {
				return nil, fmt.Errorf("%w: truncated utf8 length", ErrClassFormat)
			}
			n := int(binary.BigEndian.Uint16(data[pos:]))
			pos += 2
			if pos+n > len(data) {
				return nil, fmt.Errorf("%w: truncated utf8", ErrClassFormat)
			}
			out = append(out, string(data[pos:pos+n]))
			pos += n
			continue
		}
		size, ok := cpSize[tag]
		if !ok {
			return nil, fmt.Errorf("%w: unknown constant tag %d", ErrClassFormat, tag)
		}
		pos += size
		if tag == 5 || tag == 6 {
			i++ // long and double take two slots
		}
	}
	if pos > len(data) {
		return nil, fmt.Errorf("%w: truncated pool", ErrClassFormat)
	}
	return out, nil
}
