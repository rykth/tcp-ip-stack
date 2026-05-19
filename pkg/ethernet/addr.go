package ethernet

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrInvalidAddr = errors.New("ethernet: invalid MAC address")

// Addr is a 6-byte IEEE 802 MAC address.
type Addr [6]byte

// Broadcast is the all-ones MAC address used to reach every node on a segment.
var Broadcast = Addr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// String returns the colon-separated lowercase hex representation.
// e.g. "aa:bb:cc:dd:ee:ff".
func (a Addr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		a[0], a[1], a[2], a[3], a[4], a[5])
}

// IsMulticast reports whether the low-order bit of the first octet is set.
// Both unicast multicast and the broadcast address satisfy this condition.
func (a Addr) IsMulticast() bool {
	return a[0]&0x01 != 0
}

// IsBroadcast reports whether a equals the all-ones broadcast address.
func (a Addr) IsBroadcast() bool {
	return a == Broadcast
}

// ParseAddr parses a colon-separated hex MAC address such as "aa:bb:cc:dd:ee:ff".
func ParseAddr(s string) (Addr, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return Addr{}, ErrInvalidAddr
	}
	var a Addr
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return Addr{}, ErrInvalidAddr
		}
		a[i] = byte(v)
	}
	return a, nil
}
