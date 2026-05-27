package ip

import (
	"errors"
	stdnet "net"
	"sort"
	"sync"

	netpkg "github.com/rykth/tcp-ip-stack/pkg/net"
)

var ErrNoRoute = errors.New("ip: no route to host")

// Network represents an IPv4 CIDR network as fixed-size arrays
type Network struct {
	IP     [4]byte // network address (host bits zeroed)
	Mask   [4]byte // subnet mask (e.g., 255.255.255.0)
	Prefix uint8   // prefix length in bits (0-32)
}

// ParseNetwork parses a CIDR string such as 192.168.1.0/24 or 0.0.0.0/0
func ParseNetwork(cidr string) (Network, error) {
	_, ipNet, err := stdnet.ParseCIDR(cidr)
	if err != nil {
		return Network{}, err
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return Network{}, errors.New("ip: not an IPv4 CIDR")
	}

	prefix, _ := ipNet.Mask.Size()
	var n Network
	copy(n.IP[:], ip4)
	copy(n.Mask[:], []byte(ipNet.Mask))
	n.Prefix = uint8(prefix)
	return n, nil
}

// Contains reports whether ip falls within the network
func (n Network) Contains(ip [4]byte) bool {
	for i := 0; i < 4; i++ {
		if ip[i]&n.Mask[i] != n.IP[i] {
			return false
		}
	}
	return true
}

// Route is a single entry in the routing table.
type Route struct {
	Network Network
	Gateway [4]byte           // next-hop IP; [4]byte{} means directly connected
	Dev     netpkg.LinkDevice // outbound interface
	Metric  int               // lower value = preferred; used to break ties at same prefix length
}

// Table is a longest-prefix-match routing table
type Table struct {
	mu     sync.RWMutex
	routes []Route // sorted by Prefix descending, then Metric ascending
}

// NewTable returns an empty routing table.
func NewTable() *Table {
	return &Table{}
}

// Add inserts r into the table and re-sorts so that longest-prefix matches
// are tried first. If two routes have equal prefix length, lower Metric wins.
func (t *Table) Add(r Route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.routes = append(t.routes, r)
	sort.SliceStable(t.routes, func(i, j int) bool {
		pi, pj := t.routes[i].Network.Prefix, t.routes[j].Network.Prefix
		if pi != pj {
			return pi > pj // longest prefix first
		}
		return t.routes[i].Metric < t.routes[j].Metric
	})
}

// Delete removes the first route whose Network matches n exactly
func (t *Table) Delete(n Network) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, r := range t.routes {
		if r.Network == n {
			t.routes = append(t.routes[:i], t.routes[i+1:]...)
			return
		}
	}
}

// Lookup returns the best matching Route for dst using longest-prefix matching
func (t *Table) Lookup(dst [4]byte) (Route, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, r := range t.routes {
		if r.Network.Contains(dst) {
			return r, nil
		}
	}
	return Route{}, ErrNoRoute
}
