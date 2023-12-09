package kdbx

type KeePassSignature uint32

const (
	Signaturev1    KeePassSignature = 0xB54BFB65
	Signaturev2pre KeePassSignature = 0xB54BFB66
	Signaturev2    KeePassSignature = 0xB54BFB67
)

func (s KeePassSignature) String() string {
	switch s {
	case Signaturev1:
		return "v1"
	case Signaturev2pre:
		return "v2pre"
	case Signaturev2:
		return "v2"
	default:
		return "unknown"
	}
}
