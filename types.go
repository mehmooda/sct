package sct

type SignedCertificateTimestamp struct {
	SCTVersion Version    // The version of the protocol to which the SCT conforms
	LogID      SHA256Hash // the SHA-256 hash of the log's public key, calculated over
	// the DER encoding of the key represented as SubjectPublicKeyInfo.
	Timestamp  uint64          // Timestamp (in ms since unix epoc) at which the SCT was issued
	Extensions CTExtensions    // For future extensions to the protocol
	Signature  DigitallySigned // The Log's signature for this SCT
}

type Version uint8

type SHA256Hash [32]byte

type CTExtensions []byte

type DigitallySigned struct {
	HashAlgorithm      HashAlgorithm
	SignatureAlgorithm SignatureAlgorithm
	Signature          []byte
}

type HashAlgorithm byte

// HashAlgorithm constants
const (
	None   HashAlgorithm = 0
	MD5    HashAlgorithm = 1
	SHA1   HashAlgorithm = 2
	SHA224 HashAlgorithm = 3
	SHA256 HashAlgorithm = 4
	SHA384 HashAlgorithm = 5
	SHA512 HashAlgorithm = 6
)

type SignatureAlgorithm byte

// SignatureAlgorithm constants
const (
	Anonymous SignatureAlgorithm = 0
	RSA       SignatureAlgorithm = 1
	DSA       SignatureAlgorithm = 2
	ECDSA     SignatureAlgorithm = 3
)

type Error int

//Preallocate Errors
var (
	INVALID_VERSION   error = Error(1)
	SCT_TOO_LARGE     error = Error(2)
	NOT_ENOUGH_BUFFER error = Error(3)
	NO_SCTS_GIVEN     error = Error(4)
)

func (e Error) Error() string {
	switch e {
	case INVALID_VERSION:
		return "Unable to serialize SignedCertificateTimestamp: invalid version"
	case SCT_TOO_LARGE:
		return "Unable to serialize SignedCertificateTimestamp: SCT too large"
	case NOT_ENOUGH_BUFFER:
		return "Unable to serialize SignedCertificateTimestamp: not enough buffer"
	case NO_SCTS_GIVEN:
	}
	return "Unknown error occured in sct"
}
