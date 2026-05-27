package ip

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const MinHeaderLen = 20

var (
	ErrHeaderTooShort = errors.New("ip: header too short")
	ErrBadVersion     = errors.New("ip: not an IPv4 packet")
	ErrBadChecksum    = errors.New("ip: bad header checksum")
)

type Protocol uint8

const (
	ProtocolICMP Protocol = 1
	ProtocolTCP  Protocol = 6
	ProtocolUDP  Protocol = 17
)

// IP header flag bits (stored in the top 3 bits of the Flags+FragOffset word).
// In the 3-bit flags field: bit 1 = DF, bit 0 = MF (bit 2 is reserved).
const (
	FlagDF uint8 = 0x02 // don't fragment
	FlagMF uint8 = 0x01 // more fragments
)

// Header represents a parsed IPv4 header
type Header struct {
	Version    uint8
	IHL        uint8  // in 32-bit words; min 5 (20 bytes)
	TOS        uint8  // type of service
	TotalLen   uint16 // full datagram size including header and payload
	ID         uint16
	Flags      uint8  // 3-bit field: FlagDF | FlagMF
	FragOffset uint16 // in 8-byte units
	TTL        uint8
	Protocol   Protocol
	Checksum   uint16
	Src        [4]byte
	Dst        [4]byte
	Options    []byte // (IHL-5)*4 bytes; nil when IHL == 5
}

// Parse decodes an IPv4 header
func Parse(b []byte) (Header, error) {
	if len(b) < MinHeaderLen {
		return Header{}, ErrHeaderTooShort
	}

	version := b[0] >> 4
	if version != 4 {
		return Header{}, ErrBadVersion
	}

	ihl := b[0] & 0x0F
	headerLen := int(ihl) * 4
	if headerLen < MinHeaderLen || headerLen > len(b) {
		return Header{}, ErrHeaderTooShort
	}

	if Checksum(b[:headerLen]) != 0 {
		return Header{}, ErrBadChecksum
	}

	fo := binary.BigEndian.Uint16(b[6:8])
	var h Header
	h.Version = version
	h.IHL = ihl
	h.TOS = b[1]
	h.TotalLen = binary.BigEndian.Uint16(b[2:4])
	h.ID = binary.BigEndian.Uint16(b[4:6])
	h.Flags = uint8(fo >> 13)
	h.FragOffset = fo & 0x1FFF
	h.TTL = b[8]
	h.Protocol = Protocol(b[9])
	h.Checksum = binary.BigEndian.Uint16(b[10:12])
	copy(h.Src[:], b[12:16])
	copy(h.Dst[:], b[16:20])
	if headerLen > MinHeaderLen {
		h.Options = make([]byte, headerLen-MinHeaderLen)
		copy(h.Options, b[20:headerLen])
	}
	return h, nil
}

// Marshal encodes h and payload into dst
func Marshal(dst []byte, h Header, payload []byte) error {
	headerLen := int(h.IHL) * 4
	need := headerLen + len(payload)
	if len(dst) < need {
		return fmt.Errorf("ip: marshal buffer too small: need %d have %d", need, len(dst))
	}

	dst[0] = (h.Version << 4) | h.IHL
	dst[1] = h.TOS
	binary.BigEndian.PutUint16(dst[2:4], h.TotalLen)
	binary.BigEndian.PutUint16(dst[4:6], h.ID)
	fo := (uint16(h.Flags) << 13) | h.FragOffset
	binary.BigEndian.PutUint16(dst[6:8], fo)
	dst[8] = h.TTL
	dst[9] = uint8(h.Protocol)
	dst[10], dst[11] = 0, 0 // zero before checksum computation
	copy(dst[12:16], h.Src[:])
	copy(dst[16:20], h.Dst[:])
	if len(h.Options) > 0 {
		copy(dst[20:headerLen], h.Options)
	}
	check := Checksum(dst[:headerLen])
	binary.BigEndian.PutUint16(dst[10:12], check)
	copy(dst[headerLen:], payload)
	return nil
}

// Payload returns the payload portion of b given a parsed header h
func Payload(b []byte, h Header) []byte {
	headerLen := int(h.IHL) * 4
	if len(b) <= headerLen {
		return nil
	}

	end := int(h.TotalLen)
	if end > len(b) {
		end = len(b)
	}
	if end <= headerLen {
		return nil
	}

	return b[headerLen:end]
}
