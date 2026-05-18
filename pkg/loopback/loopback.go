package loopback

import (
	"errors"
	"fmt"
)

const (
	defaultMTU        = 65535
	defaultBufferSize = 256
)

var ErrClosed = errors.New("loopback: device closed")

// Device is an in-process loopback virtual network device.
type Device struct {
	name   string
	mtu    int
	ch     chan []byte
	closed chan struct{}
}

// Option is a functional option for Device configuration.
type Option func(*Device)

// WithMTU sets the maximum transmission unit reported by MTU().
func WithMTU(mtu int) Option {
	return func(d *Device) {
		d.mtu = mtu
	}
}

// WithBufferSize sets the number of frames the internal channel can buffer
// before Write blocks.
func WithBufferSize(n int) Option {
	return func(d *Device) {
		d.ch = make(chan []byte, n)
	}
}

// WithName sets the device name returned by Name().
func WithName(name string) Option {
	return func(d *Device) {
		d.name = name
	}
}

// New returns an initialised loopback Device ready for immediate use.
func New(opts ...Option) *Device {
	d := &Device{
		name:   "lo",
		mtu:    defaultMTU,
		ch:     make(chan []byte, defaultBufferSize),
		closed: make(chan struct{}),
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Name returns the device name (default: "lo").
func (d *Device) Name() string {
	return d.name
}

// MTU returns the maximum transmission unit in bytes (default: 65535).
func (d *Device) MTU() int {
	return d.mtu
}

// Read blocks until a frame is available.
func (d *Device) Read(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, ErrClosed
	case frame, ok := <-d.ch:
		if !ok {
			return 0, ErrClosed
		}
		if len(p) < len(frame) {
			return 0, fmt.Errorf("loopback: read buffer too small: need %d, have %d", len(frame), len(p))
		}
		return copy(p, frame), nil
	}
}

// Write enqueues a copy of p for delivery to the next Read call.
func (d *Device) Write(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, ErrClosed
	default:
	}

	// copy before enqueue so the caller can reuse p without a data race
	frame := make([]byte, len(p))
	copy(frame, p)

	select {
	case <-d.closed:
		return 0, ErrClosed
	case d.ch <- frame:
		return len(p), nil
	}
}

// Close signals shutdown to all goroutines blocked in Read or Write.
func (d *Device) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}
