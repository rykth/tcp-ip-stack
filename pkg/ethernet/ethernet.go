package ethernet

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HeaderLen is the byte length of an Ethernet II frame header
const HeaderLen = 14 // 6 bytes dst + 6 bytes src + 2 bytes EtherType.

type EtherType uint16

const (
	EtherTypeIPv4 EtherType = 0x0800
	EtherTypeARP  EtherType = 0x0806
	EtherTypeIPv6 EtherType = 0x86DD
)

var ErrFrameTooShort = errors.New("ethernet: frame too short")

// Header is the fixed 14-byte Ethernet II frame header.
type Header struct {
	Dst       Addr
	Src       Addr
	EtherType EtherType
}

// Frame is a parsed Ethernet frame.
type Frame struct {
	Header
	Payload []byte
}

// Parse decodes an Ethernet II frame from b.
func Parse(b []byte) (Frame, error) {
	if len(b) < HeaderLen {
		return Frame{}, ErrFrameTooShort
	}
	var f Frame
	copy(f.Dst[:], b[0:6])
	copy(f.Src[:], b[6:12])
	f.EtherType = EtherType(binary.BigEndian.Uint16(b[12:14]))
	f.Payload = b[14:]
	return f, nil
}

// Marshal encodes an Ethernet II frame into dst and returns the number of bytes
// written. The caller must ensure len(dst) >= HeaderLen + len(payload).
func Marshal(dst []byte, h Header, payload []byte) (int, error) {
	need := HeaderLen + len(payload)
	if len(dst) < need {
		return 0, fmt.Errorf("ethernet: marshal buffer too small: need %d, have %d", need, len(dst))
	}
	copy(dst[0:6], h.Dst[:])
	copy(dst[6:12], h.Src[:])
	binary.BigEndian.PutUint16(dst[12:14], uint16(h.EtherType))
	copy(dst[14:], payload)
	return need, nil
}
