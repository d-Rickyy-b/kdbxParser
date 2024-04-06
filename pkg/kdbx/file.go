package kdbx

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
)

type KeePassFile struct {
	MagicBytes          MagicBytes `json:"-"`
	Signature           KeePassSignature
	Version             Version
	Headers             []Header
	HeaderSHA256        HeaderSHA256
	HeaderHMACSHA256    HeaderHMACSHA256
	EncryptedData       []byte `json:"-"`
	EncryptedDataLength int
}

func (k KeePassFile) String() string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("MagicBytes:\t%s\n", k.MagicBytes))
	buffer.WriteString(fmt.Sprintf("Signature:\t%s\n", k.Signature))
	buffer.WriteString(fmt.Sprintf("Version:\t%s\n", k.Version))
	buffer.WriteString("Headers:\n")
	for _, header := range k.Headers {
		buffer.WriteString(fmt.Sprintf("\t%s\n", header))
	}

	buffer.WriteString(fmt.Sprintf("HeaderSHA256:\t\t0x%X\n", k.HeaderSHA256))
	buffer.WriteString(fmt.Sprintf("HeaderHMACSHA256:\t0x%X\n", k.HeaderHMACSHA256))
	buffer.WriteString(fmt.Sprintf("EncryptedData:\t\t%d bytes\n", len(k.EncryptedData)))

	return buffer.String()
}

// JSON returns the json encoded KeePassFile as string.
func (k KeePassFile) JSON() string {
	jsonString, err := json.Marshal(k)
	if err != nil {
		log.Fatal(err)
	}
	return string(jsonString)
}

// JSON returns the json encoded KeePassFile as string.
func (k KeePassFile) JSONPretty() string {
	jsonString, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	return string(jsonString)
}

type KeePassMetadata struct {
	MagicBytes MagicBytes
	Signature  KeePassSignature
	Version    Version
}

func Parse(r io.Reader) KeePassFile {
	var keepassFile KeePassFile

	err := binary.Read(r, binary.LittleEndian, &keepassFile.MagicBytes)
	if err != nil {
		log.Fatal(err)
	}

	err = binary.Read(r, binary.LittleEndian, &keepassFile.Signature)
	if err != nil {
		log.Fatal(err)
	}

	err = binary.Read(r, binary.LittleEndian, &keepassFile.Version)
	if err != nil {
		log.Fatal(err)
	}

	keepassFile.Headers = readHeaders(r, keepassFile.Version.Major)

	if keepassFile.Version.Major >= 4 {
		err = binary.Read(r, binary.LittleEndian, &keepassFile.HeaderSHA256)
		if err != nil {
			log.Fatal(err)
		}

		err = binary.Read(r, binary.LittleEndian, &keepassFile.HeaderHMACSHA256)
		if err != nil {
			log.Fatal(err)
		}
	}

	data, readErr := io.ReadAll(r)
	if readErr != nil {
		log.Fatal(readErr)
	}
	keepassFile.EncryptedData = data
	keepassFile.EncryptedDataLength = len(data)

	return keepassFile
}

func ParseFromBytes(b []byte) KeePassFile {
	byteReader := bytes.NewReader(b)

	return Parse(byteReader)
}

func readHeaders(r io.Reader, kdbxVersion uint16) []Header {
	var headers []Header

	for {
		header := ParseHeader(r, kdbxVersion)
		headers = append(headers, header)

		if header.Type == EndOfHeader {
			break
		}
	}

	return headers
}
