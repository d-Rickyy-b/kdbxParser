package kdbx

import "fmt"

type MagicBytes uint32

const (
	KeepassMagicBytes MagicBytes = 0x9AA2D903
)

func (m MagicBytes) String() string {
	return fmt.Sprintf("0x%X", uint32(m))
}
