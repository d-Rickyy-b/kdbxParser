package kdbx

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
)

type (
	HeaderSHA256     uint32
	HeaderHMACSHA256 uint32
)

type HeaderType byte

const (
	EndOfHeader      HeaderType = 0x00
	Comment          HeaderType = 0x01
	CipherID         HeaderType = 0x02
	CompressionFlags HeaderType = 0x03
	MasterSeed       HeaderType = 0x04
	TransformSeed    HeaderType = 0x05
	TransformRounds  HeaderType = 0x06
	EncryptionIV     HeaderType = 0x07
	StreamKey        HeaderType = 0x08
	StreamStartBytes HeaderType = 0x09
	RandomStreamID   HeaderType = 0x0A
	KDFParameters    HeaderType = 0x0B
	PublicCustomData HeaderType = 0x0C
)

func (ht HeaderType) String() string {
	switch ht {
	case EndOfHeader:
		return "EndOfHeader"
	case Comment:
		return "Comment"
	case CipherID:
		return "Cipher"
	case CompressionFlags:
		return "CompressionFlags"
	case MasterSeed:
		return "MasterSeed"
	case TransformSeed:
		return "TransformSeed"
	case TransformRounds:
		return "TransformRounds"
	case EncryptionIV:
		return "EncryptionIV"
	case StreamKey:
		return "StreamKey"
	case StreamStartBytes:
		return "StreamStartBytes"
	case RandomStreamID:
		return "RandomStreamID"
	case KDFParameters:
		return "KDFParameters"
	default:
		return "Unknown header type:"
	}
}

func (ht HeaderType) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}{
		ID:   int(ht),
		Name: ht.String(),
	})
}

type Header struct {
	Type   HeaderType
	Length uint32
	Value  []byte

	// Optional fields
	Comment          *string     `json:",omitempty"`
	CipherID         *Cipher     `json:",omitempty"`
	CompressionFlags *uint32     `json:",omitempty"`
	MasterSeed       *[]byte     `json:",omitempty"`
	TransformSeed    *[]byte     `json:",omitempty"`
	TransformRounds  *uint64     `json:",omitempty"`
	EncryptionIV     *[]byte     `json:",omitempty"`
	StreamKey        *[]byte     `json:",omitempty"`
	StreamStartBytes *[]byte     `json:",omitempty"`
	RandomStreamID   *uint32     `json:",omitempty"`
	KDFParameters    *VariantMap `json:",omitempty"`
	PublicCustomData *VariantMap `json:",omitempty"`
}

func (h Header) String() string {
	var buffer bytes.Buffer

	if h.Type == EndOfHeader {
		return ""
	}

	switch h.Type {
	case EndOfHeader:
		break
	case Comment:
		buffer.WriteString(fmt.Sprintf("Comment:\t%s", *h.Comment))
	case CipherID:
		buffer.WriteString(fmt.Sprintf("Cipher:\t\t%s", h.CipherID))
	case CompressionFlags:
		buffer.WriteString(fmt.Sprintf("CompressionFlags:\t0x%X", *h.CompressionFlags))
	case MasterSeed:
		buffer.WriteString(fmt.Sprintf("MasterSeed:\t0x%X", *h.MasterSeed))
	case TransformSeed:
		buffer.WriteString(fmt.Sprintf("TransformSeed:\t0x%X", *h.TransformSeed))
	case TransformRounds:
		buffer.WriteString(fmt.Sprintf("TransformRounds:\t%d", *h.TransformRounds))
	case EncryptionIV:
		buffer.WriteString(fmt.Sprintf("EncryptionIV:\t0x%X", *h.EncryptionIV))
	case StreamKey:
		buffer.WriteString(fmt.Sprintf("StreamKey:\t0x%X", *h.StreamKey))
	case StreamStartBytes:
		buffer.WriteString(fmt.Sprintf("StreamStartBytes:\t0x%X", *h.StreamStartBytes))
	case RandomStreamID:
		buffer.WriteString(fmt.Sprintf("RandomStreamID:\t%d", *h.RandomStreamID))
	case KDFParameters:
		buffer.WriteString(fmt.Sprintf("KDFParameters:\n%s", *h.KDFParameters))
	case PublicCustomData:
		buffer.WriteString(fmt.Sprintf("PublicCustomData:\n%s", *h.PublicCustomData))
	default:
		buffer.WriteString(fmt.Sprintf("Unknown header type: 0x%X", h.Type))
	}

	return buffer.String()
}

func ParseHeader(r io.Reader, kdbxVersion uint16) Header {
	var header Header
	err := binary.Read(r, binary.LittleEndian, &header.Type)
	if err != nil {
		log.Fatal(err)
	}

	// The length field is 2 bytes in kdbx3 and 4 bytes in kdbx4
	switch kdbxVersion {
	case 3:
		var length uint16
		lenErr := binary.Read(r, binary.LittleEndian, &length)
		if lenErr != nil {
			log.Fatal(lenErr)
		}
		header.Length = uint32(length)
	case 4:
		lenErr := binary.Read(r, binary.LittleEndian, &header.Length)
		if lenErr != nil {
			log.Fatal(lenErr)
		}
	default:
		log.Fatalf("Unknown kdbx version %d", kdbxVersion)
	}

	header.Value = make([]byte, header.Length)
	err = binary.Read(r, binary.LittleEndian, &header.Value)
	if err != nil {
		log.Fatal(err)
	}

	if header.Type == EndOfHeader {
		return header
	}

	// Set Header optional fields
	switch header.Type {
	case Comment:
		comment := string(header.Value)
		header.Comment = &comment
	case CipherID:
		c := Cipher(header.Value)
		header.CipherID = &c
	case CompressionFlags:
		compFlags := binary.LittleEndian.Uint32(header.Value)
		header.CompressionFlags = &compFlags
	case MasterSeed:
		header.MasterSeed = &header.Value
	case TransformSeed:
		header.TransformSeed = &header.Value
	case TransformRounds:
		transformRounds := binary.LittleEndian.Uint64(header.Value)
		header.TransformRounds = &transformRounds
	case EncryptionIV:
		header.EncryptionIV = &header.Value
	case StreamKey:
		header.StreamKey = &header.Value
	case StreamStartBytes:
		header.StreamStartBytes = &header.Value
	case RandomStreamID:
		randomStreamID := binary.LittleEndian.Uint32(header.Value)
		header.RandomStreamID = &randomStreamID
	case KDFParameters:
		valueReader := bytes.NewReader(header.Value)
		kdfParametersMap := ParseVariantMap(valueReader)
		header.KDFParameters = &kdfParametersMap
	case PublicCustomData:
		valueReader := bytes.NewReader(header.Value)
		publicCustomDataMap := ParseVariantMap(valueReader)
		header.PublicCustomData = &publicCustomDataMap
	}

	return header
}
