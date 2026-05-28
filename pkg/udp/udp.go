package udp

import (
	"encoding/binary"
	"errors"

	"github.com/rykth/tcp-ip-stack/pkg/ip"
)

const HeaderLen = 8

var ErrHeaderTooShort = errors.New("udp: header too short")

// Header represents a parsed UDP header
type Header struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16 // total segment length: header (8) + payload
	Checksum uint16
}

// Parse decodes a UDP header
func Parse(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, ErrHeaderTooShort
	}

	var h Header
	h.SrcPort = binary.BigEndian.Uint16(b[0:2])
	h.DstPort = binary.BigEndian.Uint16(b[2:4])
	h.Length = binary.BigEndian.Uint16(b[4:6])
	h.Checksum = binary.BigEndian.Uint16(b[6:8])
	if int(h.Length) < HeaderLen {
		return Header{}, ErrHeaderTooShort
	}

	return h, nil
}

// Payload returns the payload slice
func Payload(b []byte) []byte {
	if len(b) <= HeaderLen {
		return nil
	}
	return b[HeaderLen:]
}

// Marshal encodes h into dst
func Marshal(dst []byte, h Header) error {
	if len(dst) < HeaderLen {
		return ErrHeaderTooShort
	}
	binary.BigEndian.PutUint16(dst[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(dst[2:4], h.DstPort)
	binary.BigEndian.PutUint16(dst[4:6], h.Length)
	binary.BigEndian.PutUint16(dst[6:8], h.Checksum)
	return nil
}

// ComputeChecksum calculates the UDP checksum per RFC 768
func ComputeChecksum(src, dst [4]byte, h Header, payload []byte) uint16 {
	var hdrBuf [HeaderLen]byte
	binary.BigEndian.PutUint16(hdrBuf[0:], h.SrcPort)
	binary.BigEndian.PutUint16(hdrBuf[2:], h.DstPort)
	binary.BigEndian.PutUint16(hdrBuf[4:], h.Length)
	// hdrBuf[6:8] = 0 (checksum field zeroed for computation)

	pseudoCS := ip.PseudoHeaderChecksum(src, dst, ip.ProtocolUDP, h.Length)
	udpCS := ip.Add16(ip.Checksum(hdrBuf[:]), ip.Checksum(payload))
	return ip.Add16(pseudoCS, udpCS)
}
