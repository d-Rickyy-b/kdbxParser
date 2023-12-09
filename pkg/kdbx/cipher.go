package kdbx

import "fmt"

type Cipher [16]byte

var (
	AES128CBC Cipher = [16]byte{0x61, 0xAB, 0x05, 0xA1, 0x94, 0x64, 0x41, 0xC3, 0x8D, 0x74, 0x3A, 0x56, 0x3D, 0xF8, 0xDD, 0x35}
	AES256CBC Cipher = [16]byte{0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF}
	CHACHA20  Cipher = [16]byte{0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A}
	SALSA20   Cipher = [16]byte{0x71, 0x6E, 0x1C, 0x8A, 0xEE, 0x17, 0x4B, 0xDC, 0x93, 0xAE, 0xA9, 0x77, 0xB8, 0x82, 0x83, 0x3A}
	SERPENT   Cipher = [16]byte{0x09, 0x85, 0x63, 0xFF, 0xDD, 0xF7, 0x4F, 0x98, 0x86, 0x19, 0x80, 0x79, 0xF6, 0xDB, 0x89, 0x7A}
	TWOFISH   Cipher = [16]byte{0xAD, 0x68, 0xF2, 0x9F, 0x57, 0x6F, 0x4B, 0xB9, 0xA3, 0x6A, 0xD4, 0x7A, 0xF9, 0x65, 0x34, 0x6C}
)

func (c Cipher) String() string {
	switch c {
	case AES128CBC:
		return "AES128_CBC"
	case AES256CBC:
		return "AES256_CBC"
	case SALSA20:
		return "Salsa20"
	case SERPENT:
		return "Serpent"
	case CHACHA20:
		return "ChaCha20"
	case TWOFISH:
		return "Twofish"
	default:
		return fmt.Sprintf("Unknown (0x%X)\n", c)
	}
}
