package sct

import "fmt"
import "testing"
import "bytes"
import "github.com/google/certificate-transparency/go"

var WriteOutExpOutput []byte = []byte{0x00, 0x68, 0xF6, 0x98, 0xF8, 0x1F, 0x64, 0x82, 0xBE, 0x3A, 0x8C, 0xEE, 0xB9, 0x28, 0x1D, 0x4C, 0xFC, 0x71, 0x51, 0x5D, 0x67, 0x93, 0xD4, 0x44, 0xD1, 0x0A, 0x67, 0xAC, 0xBB, 0x4F, 0x4F, 0xFB, 0xC4, 0x00, 0x00, 0x01,
	0x45, 0x98, 0xAB, 0x34, 0x02, 0x00, 0x00, 0x04, 0x03, 0x00, 0x46, 0x30, 0x44, 0x02, 0x20, 0x19, 0xAA, 0x26, 0xAF, 0xC0, 0x2C, 0x92, 0xB1, 0xDD, 0x71, 0x75, 0x1E, 0xAE, 0x16, 0x0C, 0x9B, 0x4E, 0x8A, 0x23, 0x90, 0xE4, 0x75, 0xA1, 0x90, 0x3C,
	0xE5, 0x69, 0xEF, 0xEE, 0x9B, 0xAD, 0x2D, 0x02, 0x20, 0x20, 0xFB, 0x14, 0xDB, 0x1E, 0x3E, 0x09, 0x09, 0x51, 0x74, 0x1A, 0x97, 0x68, 0x38, 0x0E, 0x64, 0x18, 0x2A, 0xFA, 0xF6, 0x5F, 0x2A, 0x5C, 0x77, 0xEB, 0x73, 0x3B, 0x0D, 0xD6, 0x4D, 0xCF,
	0xBB}

var sct SignedCertificateTimestamp = SignedCertificateTimestamp{
	SCTVersion: 0,
	LogID:      [32]byte{0x68, 0xF6, 0x98, 0xF8, 0x1F, 0x64, 0x82, 0xBE, 0x3A, 0x8C, 0xEE, 0xB9, 0x28, 0x1D, 0x4C, 0xFC, 0x71, 0x51, 0x5D, 0x67, 0x93, 0xD4, 0x44, 0xD1, 0x0A, 0x67, 0xAC, 0xBB, 0x4F, 0x4F, 0xFB, 0xC4},
	Timestamp:  0x0000014598AB3402,
	Extensions: nil,
	Signature: DigitallySigned{
		HashAlgorithm:      SHA256,
		SignatureAlgorithm: ECDSA,
		Signature: []byte{0x30, 0x44, 0x02, 0x20, 0x19, 0xAA, 0x26, 0xAF, 0xC0, 0x2C, 0x92, 0xB1, 0xDD, 0x71, 0x75, 0x1E, 0xAE, 0x16, 0x0C, 0x9B, 0x4E, 0x8A, 0x23, 0x90, 0xE4, 0x75, 0xA1, 0x90, 0x3C,
			0xE5, 0x69, 0xEF, 0xEE, 0x9B, 0xAD, 0x2D, 0x02, 0x20, 0x20, 0xFB, 0x14, 0xDB, 0x1E, 0x3E, 0x09, 0x09, 0x51, 0x74, 0x1A, 0x97, 0x68, 0x38, 0x0E, 0x64, 0x18, 0x2A, 0xFA, 0xF6,
			0x5F, 0x2A, 0x5C, 0x77, 0xEB, 0x73, 0x3B, 0x0D, 0xD6, 0x4D, 0xCF, 0xBB},
	},
}

func TestWriteOut(t *testing.T) {
	b, err := WriteOut(sct)
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}

	if bytes.Compare(b, WriteOutExpOutput) != 0 {
		fmt.Println(b)
		fmt.Println("expected:")
		fmt.Println(WriteOutExpOutput)
		t.Fail()
	}
}

func BenchmarkSCTSerializeOld(b *testing.B) {
	b.ReportAllocs()
	gsct := ct.SignedCertificateTimestamp{
		LogID:     ct.SHA256Hash(sct.LogID),
		Timestamp: sct.Timestamp,
		Signature: ct.DigitallySigned{
			HashAlgorithm:      ct.SHA256,
			SignatureAlgorithm: ct.ECDSA,
			Signature:          sct.Signature.Signature,
		},
	}
	for i := 0; i < b.N; i++ {
		_, err := ct.SerializeSCT(gsct)
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkSCTSerializeNew(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := WriteOut(sct)
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkSCTSerializeDump(b *testing.B) {
	b.ReportAllocs()

	n, _ := WriteOutHere(sct, nil)
	bs := make([]byte, n)
	for i := 0; i < b.N; i++ {
		_, err := WriteOutHere(sct, bs)
		if err != nil {
			b.Fail()
		}
	}
}
