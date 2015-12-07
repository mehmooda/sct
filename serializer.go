package sct

import "encoding/binary"

func WriteOutHere(sct SignedCertificateTimestamp, here []byte) (int, error) {
	if sct.SCTVersion != 0 {
		return 0, INVALID_VERSION
	}

	//Determine Lenth of Serialized Output
	ctxlen := len(sct.Extensions)
	siglen := len(sct.Signature.Signature)
	sctoutput := 1 + 32 + 8 + 2 + ctxlen + 2 + 2 + siglen

	if sctoutput > 0xFFFF {
		return 0, SCT_TOO_LARGE
	}
	if len(here) < sctoutput {
		return sctoutput, NOT_ENOUGH_BUFFER
	}

	//Write Version
	here[0] = byte(sct.SCTVersion)

	//Write LogID
	copy(here[1:33], sct.LogID[:])

	//Write Timestamp
	binary.BigEndian.PutUint64(here[33:41], sct.Timestamp)

	//Write Extensions
	binary.BigEndian.PutUint16(here[41:43], uint16(ctxlen))
	n := 43 + ctxlen
	copy(here[43:n], sct.Extensions)

	//Write Signature Algorithm
	here[n] = byte(sct.Signature.HashAlgorithm)
	here[n+1] = byte(sct.Signature.SignatureAlgorithm)
	n += 2

	//Write Signature
	binary.BigEndian.PutUint16(here[n:n+2], uint16(siglen))
	n += 2
	copy(here[n:n+siglen], sct.Signature.Signature)

	return sctoutput, nil
}

func WriteOut(sct SignedCertificateTimestamp) ([]byte, error) {
	n, err := WriteOutHere(sct, nil)
	if n == 0 {
		return nil, err
	}
	v := make([]byte, n)

	_, err = WriteOutHere(sct, v)
	return v, err
}
