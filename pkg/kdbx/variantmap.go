package kdbx

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/google/uuid"
)

type VariantMap struct {
	FormatVersion uint16
	Variants      []Variant
	EndOfMap      byte
}

func (v VariantMap) String() string {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("\t\tFormatVersion: %d\n", v.FormatVersion))
	for i, variant := range v.Variants {
		buffer.WriteString(fmt.Sprintf("\t\t%s", variant.String()))
		if i == len(v.Variants)-1 {
			break
		}
		buffer.WriteString("\n")
	}
	return buffer.String()
}

func (v VariantMap) MarshalJSON() ([]byte, error) {
	vmap := make(map[string]interface{})
	for _, variant := range v.Variants {
		switch variant.Type {
		case t_uint32:
			variantValue := binary.LittleEndian.Uint32(variant.Value)
			vmap[string(variant.Key)] = variantValue
		case t_uint64:
			variantValue := binary.LittleEndian.Uint64(variant.Value)
			vmap[string(variant.Key)] = variantValue
		case t_bool:
			variantValue := binary.LittleEndian.Uint32(variant.Value) != 0
			vmap[string(variant.Key)] = variantValue
		case t_int32:
			variantValue := binary.LittleEndian.Uint32(variant.Value)
			vmap[string(variant.Key)] = variantValue
		case t_string:
			vmap[string(variant.Key)] = fmt.Sprintf("%s", variant.Value)
		case t_bytearr:
			if string(variant.Key) == "$UUID" {
				parsedUUID, err := uuid.FromBytes(variant.Value)
				if err != nil {
					return nil, err
				}

				value := KDFAlgorithm(variant.Value)
				switch value {
				case AESKDF:
					vmap[string(variant.Key)] = parsedUUID.String() + " (AES-KDF)"
				case Argon2d:
					vmap[string(variant.Key)] = parsedUUID.String() + " (Argon2d)"
				case Argon2id:
					vmap[string(variant.Key)] = parsedUUID.String() + " (Argon2id)"
				default:
					vmap[string(variant.Key)] = parsedUUID.String() + " (Unknown)"
				}
			} else {
				vmap[string(variant.Key)] = fmt.Sprintf("0x%X", variant.Value)
			}
		}
	}

	return json.Marshal(vmap)
}

type VariantMapEntryType byte

const (
	t_end     VariantMapEntryType = 0x00
	t_uint32  VariantMapEntryType = 0x04
	t_uint64  VariantMapEntryType = 0x05
	t_bool    VariantMapEntryType = 0x08
	t_int32   VariantMapEntryType = 0x0C
	t_string  VariantMapEntryType = 0x18
	t_bytearr VariantMapEntryType = 0x42
)

type KDFAlgorithm [16]byte

var (
	EndOfVariantMap              = errors.New("end of variant map")
	AESKDF          KDFAlgorithm = [16]byte{0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA}
	Argon2d         KDFAlgorithm = [16]byte{0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C}
	Argon2id        KDFAlgorithm = [16]byte{0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6}
)

func (v VariantMapEntryType) String() string {
	switch v {
	case t_end:
		return "End"
	case t_uint32:
		return "Uint32"
	case t_uint64:
		return "Uint64"
	case t_bool:
		return "Bool"
	case t_int32:
		return "Int32"
	case t_string:
		return "String"
	case t_bytearr:
		return "ByteArray"
	default:
		return "Unknown"
	}
}

type Variant struct {
	Type      VariantMapEntryType
	KeySize   uint32
	Key       []byte
	ValueSize uint32
	Value     []byte
}

func (v Variant) String() string {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("%s  \t| KeySize: %d bytes | Key: '%s' | ValueSize: %d bytes | Value: ", v.Type, v.KeySize, v.Key, v.ValueSize))

	switch v.Type {
	case t_uint32:
		variantValue := binary.LittleEndian.Uint32(v.Value)
		buffer.WriteString(fmt.Sprintf("%d", variantValue))
	case t_uint64:
		variantValue := binary.LittleEndian.Uint64(v.Value)
		buffer.WriteString(fmt.Sprintf("%d", variantValue))
	case t_bool:
		variantValue := binary.LittleEndian.Uint32(v.Value) != 0
		buffer.WriteString(fmt.Sprintf("%t", variantValue))
	case t_int32:
		variantValue := binary.LittleEndian.Uint32(v.Value)
		buffer.WriteString(fmt.Sprintf("%d", variantValue))
	case t_string:
		buffer.WriteString(fmt.Sprintf("%s", v.Value))
	case t_bytearr:
		if string(v.Key) == "$UUID" {
			parsedUUID, err := uuid.FromBytes(v.Value)
			if err != nil {
				return ""
			}
			buffer.WriteString(parsedUUID.String())

			value := KDFAlgorithm(v.Value)
			switch value {
			case AESKDF:
				buffer.WriteString(" (AES-KDF)")
			case Argon2d:
				buffer.WriteString(" (Argon2d)")
			case Argon2id:
				buffer.WriteString(" (Argon2id)")
			default:
				buffer.WriteString(" (Unknown)")
			}
		} else {
			buffer.WriteString(fmt.Sprintf("0x%X", v.Value))
		}
	}
	return buffer.String()
}

func ParseVariantMap(r io.Reader) VariantMap {
	var variantMap VariantMap

	err := binary.Read(r, binary.LittleEndian, &variantMap.FormatVersion)
	if err != nil {
		log.Fatal(err)
	}

	for {
		variant, err := ParseVariant(r)
		if err != nil {
			break
		}
		variantMap.Variants = append(variantMap.Variants, variant)
	}

	return variantMap
}

func ParseVariant(r io.Reader) (Variant, error) {
	var variant Variant
	err := binary.Read(r, binary.LittleEndian, &variant.Type)
	if err != nil {
		log.Fatal(err)
	}

	if variant.Type == t_end {
		return variant, EndOfVariantMap
	}

	err = binary.Read(r, binary.LittleEndian, &variant.KeySize)
	if err != nil {
		log.Fatal(err)
	}

	variant.Key = make([]byte, variant.KeySize)
	err = binary.Read(r, binary.LittleEndian, &variant.Key)
	if err != nil {
		log.Fatal(err)
	}

	err = binary.Read(r, binary.LittleEndian, &variant.ValueSize)
	if err != nil {
		log.Fatal(err)
	}

	variant.Value = make([]byte, variant.ValueSize)
	err = binary.Read(r, binary.LittleEndian, &variant.Value)
	if err != nil {
		log.Fatal(err)
	}

	//switch variant.Type {
	//case t_uint32:
	//	variant.Value = ReadUint32(r)
	//case t_uint64:
	//	variant.Value = ReadUint64(r)
	//case t_bool:
	//	variant.Value = ReadBool(r)
	//case t_int32:
	//	variant.Value = ReadInt32(r)
	//case t_string:
	//	variant.Value = ReadString(r, variant.ValueSize)
	//case t_bytearr:
	//	variant.Value = ReadByteArray(r, variant.ValueSize)
	//}
	return variant, nil
}
