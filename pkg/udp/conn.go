package udp

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrConnClosed   = errors.New("udp: connection closed")
	ErrNotConnected = errors.New("udp: Read/Write require a connected Conn (use Dial); use ReadFrom/WriteTo instead")
)

type Addr struct {
	IP   [4]byte
	Port uint16
}

// String returns "a.b.c.d:port"
func (a Addr) String() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", a.IP[0], a.IP[1], a.IP[2], a.IP[3], a.Port)
}

// Datagram is a received UDP message with full addressing information
type Datagram struct {
	Src     Addr
	Dst     Addr
	Payload []byte
}

// Conn is a UDP endpoint created by Handler.Listen or Handler.Dial
//
// Unconnected Conns (from Listen) accept datagrams from any source; use
// ReadFrom and WriteTo for peer-addressed I/O
//
// Connected Conns (from Dial) filter to a single remote; use Read and Write
// for simple byte-oriented I/O in addition to ReadFrom/WriteTo
type Conn struct {
	rxCh    chan Datagram
	done    chan struct{}
	local   Addr
	remote  *Addr
	handler *Handler
	once    sync.Once
}

func newConn(local Addr, remote *Addr, h *Handler) *Conn {
	return &Conn{
		rxCh:    make(chan Datagram, 64),
		done:    make(chan struct{}),
		local:   local,
		remote:  remote,
		handler: h,
	}
}

// LocalAddr returns the local address bound to this Conn
func (c *Conn) LocalAddr() Addr {
	return c.local
}

// RemoteAddr returns the connected remote address, or nil if unconnected
func (c *Conn) RemoteAddr() *Addr {
	return c.remote
}

// if the receive buffer is full or the Conn is closed the datagram is silently
// dropped (non-blocking and acceptable for UDP)
func (c *Conn) deliver(dg Datagram) {
	select {
	case <-c.done:
		return // conn closed (discard)
	default:
	}

	select {
	case c.rxCh <- dg:
	case <-c.done:
	default:
		// backpressure: drop
	}
}

// ReadFrom blocks until a datagram arrives, ctx is cancelled, or the Conn
// is closed
func (c *Conn) ReadFrom(ctx context.Context) (Datagram, error) {
	select {
	case dg := <-c.rxCh:
		return dg, nil
	case <-c.done:
		return Datagram{}, ErrConnClosed
	case <-ctx.Done():
		return Datagram{}, ctx.Err()
	}
}

// WriteTo sends payload to addr from this Conn's local address
func (c *Conn) WriteTo(ctx context.Context, payload []byte, addr Addr) error {
	select {
	case <-c.done:
		return ErrConnClosed
	default:
	}

	return c.handler.send(ctx, c.local, addr, payload)
}

// Read blocks until a datagram arrives and returns its payload
func (c *Conn) Read(ctx context.Context) ([]byte, error) {
	if c.remote == nil {
		return nil, ErrNotConnected
	}
	dg, err := c.ReadFrom(ctx)
	if err != nil {
		return nil, err
	}

	return dg.Payload, nil
}

// Write sends payload to the connected remote address
func (c *Conn) Write(ctx context.Context, payload []byte) error {
	if c.remote == nil {
		return ErrNotConnected
	}
	return c.WriteTo(ctx, payload, *c.remote)
}

// Close deregisters the Conn from the handler and unblocks all callers
func (c *Conn) Close() error {
	c.once.Do(func() {
		c.handler.deregister(c.local.Port)
		close(c.done)
	})
	return nil
}
