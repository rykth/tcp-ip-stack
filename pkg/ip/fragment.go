package ip

import (
	"context"
	"sort"
	"sync"
	"time"
)

const defaultReassemblyTimeout = 30 * time.Second

type fragKey struct {
	Src   [4]byte
	Dst   [4]byte
	ID    uint16
	Proto Protocol
}

// fragment is a single received piece of a fragmented datagram
type fragment struct {
	offset uint32 // byte offset within the reassembled payload
	data   []byte // payload bytes for this fragment
}

// fragGroup accumulates fragments for one datagram until all arrive or
// the reassembly deadline passes
type fragGroup struct {
	frags    []fragment
	deadline time.Time
	totalLen int  // total payload length; known once the last fragment arrives
	known    bool // true once totalLen is known
}

// Reassembler reassembles IPv4 fragments back into complete datagrams
type Reassembler struct {
	mu      sync.Mutex
	groups  map[fragKey]*fragGroup
	timeout time.Duration
}

type ReassemblerOption func(*Reassembler)

// WithReassemblyTimeout sets how long to wait for missing fragments before
// discarding an incomplete group. Default is 30 seconds.
func WithReassemblyTimeout(d time.Duration) ReassemblerOption {
	return func(r *Reassembler) {
		r.timeout = d
	}
}

func NewReassembler(opts ...ReassemblerOption) *Reassembler {
	r := &Reassembler{
		groups:  make(map[fragKey]*fragGroup),
		timeout: defaultReassemblyTimeout,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Add incorporates fragment (h, payload) into the reassembly buffer
func (r *Reassembler) Add(h Header, payload []byte) ([]byte, bool) {
	key := fragKey{Src: h.Src, Dst: h.Dst, ID: h.ID, Proto: h.Protocol}
	offset := uint32(h.FragOffset) * 8 // convert 8-byte units to bytes
	hasMore := h.Flags&FlagMF != 0

	cp := make([]byte, len(payload))
	copy(cp, payload)

	r.mu.Lock()
	defer r.mu.Unlock()

	g, ok := r.groups[key]
	if !ok {
		g = &fragGroup{deadline: time.Now().Add(r.timeout)}
		r.groups[key] = g
	}
	g.frags = append(g.frags, fragment{offset: offset, data: cp})
	if !hasMore {
		g.totalLen = int(offset) + len(payload)
		g.known = true
	}

	if !g.known {
		return nil, false
	}

	result, complete := tryReassemble(g)
	if complete {
		delete(r.groups, key)
	}
	return result, complete
}

// GC drops all incomplete fragGroups whose deadline has passed
func (r *Reassembler) GC() {
	now := time.Now()
	r.mu.Lock()
	for k, g := range r.groups {
		if now.After(g.deadline) {
			delete(r.groups, k)
		}
	}
	r.mu.Unlock()
}

// Start runs the background GC goroutine until ctx is cancelled
func (r *Reassembler) Start(ctx context.Context) {
	tick := time.NewTicker(r.timeout / 2)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.GC()
		}
	}
}

// tryReassemble attempts to build the complete datagram from g.frags
func tryReassemble(g *fragGroup) ([]byte, bool) {
	// sort fragments by byte offset so we can walk them in order
	sort.Slice(g.frags, func(i, j int) bool {
		return g.frags[i].offset < g.frags[j].offset
	})

	// walk the sorted fragments to check for gaps
	var covered uint32
	for _, f := range g.frags {
		if f.offset > covered {
			return nil, false // gap between covered and this fragment
		}
		end := f.offset + uint32(len(f.data))
		if end > covered {
			covered = end
		}
	}
	if int(covered) < g.totalLen {
		return nil, false // not all bytes have arrived yet
	}

	// all data is present -> assemble
	out := make([]byte, g.totalLen)
	for _, f := range g.frags {
		end := f.offset + uint32(len(f.data))
		if int(end) > g.totalLen {
			end = uint32(g.totalLen)
		}
		copy(out[f.offset:end], f.data[:end-f.offset])
	}
	return out, true
}
