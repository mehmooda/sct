package sct

import "crypto/x509/pkix"
import "encoding/binary"

var OCSPSCToid []int = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}

func CreateOCSPResponse(scts []SignedCertificateTimestamp) (ocspret pkix.Extension, errorret error) {
	if len(scts) == 0 {
		errorret = NO_SCTS_GIVEN
		return
	}

	// Determine required length
	sctoutlen := 6
	for _, ct := range scts {
		n, err := WriteOutHere(ct, nil)
		if n == 0 {
			errorret = err
			return
		}
		sctoutlen += 2 + n
	}

	if (sctoutlen - 4) > 0xFFFF {
		errorret = SCT_TOO_LARGE
		return
	}

	output := make([]byte, sctoutlen)
	binary.BigEndian.PutUint16(output[4:6], uint16(sctoutlen-6))

	sctpos := 6
	for _, ct := range scts {
		n, _ := WriteOutHere(ct, nil)
		binary.BigEndian.PutUint16(output[sctpos:sctpos+2], uint16(n))
		sctpos += 2
		_, err := WriteOutHere(ct, output[sctpos:sctpos+n])
		if err != nil {
			errorret = err
			return
		}
		sctpos += n
	}

	//Save 10 Allocations by performing a super simple version of ASN1 encoding
	if (sctoutlen - 4) <= 0x7F {
		output[2] = 4
		output[3] = byte(sctoutlen - 4)
		output = output[2:]
	} else if (sctoutlen - 4) <= 0xFF {
		output[1] = 4
		output[2] = 0x81
		output[3] = byte(sctoutlen - 4)
		output = output[1:]
	} else {
		output[0] = 4
		output[1] = 0x82
		binary.BigEndian.PutUint16(output[2:4], uint16(sctoutlen-4))
	}

	ocspret.Id = OCSPSCToid
	ocspret.Value = output

	return
}
