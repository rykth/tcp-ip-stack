//go:build linux

package tuntap

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

type DeviceType uint16

const (
	DeviceTAP DeviceType = unix.IFF_TAP // raw Ethernet frames are exchanged
	DeviceTUN DeviceType = unix.IFF_TUN // raw IP packets are exchanged.
)

// defaultMTU is 1500, matching a standard Ethernet interface.
const defaultMTU = 1500

// tunFd wraps a /dev/net/tun file descriptor with poll-based blocking I/O.
type tunFd struct {
	fd         int
	shutdownFd int
	readPoll   [2]unix.PollFd // {tun POLLIN, shutdownFd POLLIN}
	writePoll  [2]unix.PollFd // {tun POLLOUT, shutdownFd POLLIN}
}

// newTunFd sets the FD non-blocking, creates the eventfd, and returns a tunFd.
func newTunFd(fd int) (tunFd, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return tunFd{}, fmt.Errorf("tuntap: set non-blocking: %w", err)
	}

	shutdownFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return tunFd{}, fmt.Errorf("tuntap: create eventfd: %w", err)
	}

	return tunFd{
		fd:         fd,
		shutdownFd: shutdownFd,
		readPoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
		writePoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLOUT},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
	}, nil
}

// blockOnRead sleeps in poll until the tun fd is readable or shutdown is
// signalled.  Retries automatically on EINTR (signal interrupt).
func (t *tunFd) blockOnRead() error {
	return t.blockOnPoll(t.readPoll[:])
}

// blockOnWrite sleeps in poll until the tun fd is writable or shutdown is signalled.
func (t *tunFd) blockOnWrite() error {
	return t.blockOnPoll(t.writePoll[:])
}

func (t *tunFd) blockOnPoll(fds []unix.PollFd) error {
	const problemFlags = unix.POLLHUP | unix.POLLNVAL | unix.POLLERR
	for {
		_, err := unix.Poll(fds, -1)
		if err == unix.EINTR {
			continue // signal interrupted - retry
		}

		// Always reset Revents before trusting them.
		tunRevents := fds[0].Revents
		shutRevents := fds[1].Revents
		fds[0].Revents = 0
		fds[1].Revents = 0

		if err != nil {
			return err
		}
		if shutRevents&(unix.POLLIN|problemFlags) != 0 || tunRevents&problemFlags != 0 {
			return os.ErrClosed
		}
		return nil
	}
}

// wakeForShutdown writes to the eventfd, unblocking every goroutine in Poll.
func (t *tunFd) wakeForShutdown() {
	var buf [8]byte
	binary.NativeEndian.PutUint64(buf[:], 1)
	_, _ = unix.Write(t.shutdownFd, buf[:])
}

// Device is a Linux TUN or TAP virtual network device.
type Device struct {
	tfd    tunFd
	name   string
	kind   DeviceType
	mtu    int
	ctlFd  int    // AF_INET SOCK_DGRAM socket for MTU/flags ioctls
	closed uint32 // atomic; 0=open, 1=closed
}

// Option is a functional option for Device configuration.
type Option func(*Device)

// WithMTU sets the interface MTU (default: 1500).
func WithMTU(mtu int) Option {
	return func(d *Device) {
		d.mtu = mtu
	}
}

// New opens or creates a TUN or TAP virtual device.
func New(name string, kind DeviceType, opts ...Option) (*Device, error) {
	d := &Device{
		kind: kind,
		mtu:  defaultMTU,
	}
	for _, o := range opts {
		o(d)
	}

	// open the clone device.
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tuntap: open /dev/net/tun: %w", err)
	}

	// 2. Configure the interface via TUNSETIFF.
	var req ifReq
	req.Flags = uint16(kind) | unix.IFF_NO_PI // IFF_NO_PI suppresses the 4-byte packet-info header so we get raw frames.
	if len(name) >= unix.IFNAMSIZ {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tuntap: interface name too long (max %d): %q", unix.IFNAMSIZ-1, name)
	}
	copy(req.Name[:], name)

	if err = ioctlTUNSETIFF(uintptr(fd), &req); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tuntap: TUNSETIFF: %w", err)
	}

	// read back the kernel-assigned name (may differ from the requested name).
	d.name = strings.TrimRight(string(req.Name[:]), "\x00")

	// wrap the FD with poll-based blocking I/O.
	tfd, err := newTunFd(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	d.tfd = tfd

	// open a control socket for subsequent ioctl calls (MTU, flags).
	ctlFd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_IP)
	if err != nil {
		_ = unix.Close(tfd.shutdownFd)
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tuntap: open control socket: %w", err)
	}
	d.ctlFd = ctlFd

	if err = d.setMTU(d.mtu); err != nil {
		d.closeAll()
		return nil, err
	}

	if err = d.setUp(); err != nil {
		d.closeAll()
		return nil, err
	}

	return d, nil
}

// Name returns the interface name (e.g. "tap0").
func (d *Device) Name() string {
	return d.name
}

// MTU returns the configured maximum transmission unit.
func (d *Device) MTU() int { return d.mtu }

// Read reads one raw frame from the device into p.
func (d *Device) Read(p []byte) (int, error) {
	for {
		n, err := unix.Read(d.tfd.fd, p)
		if err == nil {
			return n, nil
		}
		switch err {
		case unix.EAGAIN:
			if pollErr := d.tfd.blockOnRead(); pollErr != nil {
				return 0, pollErr
			}
		case unix.EINTR:
			// Signal interrupted the syscall - retry immediately.
		case unix.EBADF:
			return 0, os.ErrClosed
		default:
			return 0, fmt.Errorf("tuntap: read: %w", err)
		}
	}
}

// Write transmits one raw frame through the device.
func (d *Device) Write(p []byte) (int, error) {
	for {
		n, err := unix.Write(d.tfd.fd, p)
		if err == nil {
			return n, nil
		}
		switch err {
		case unix.EAGAIN:
			if pollErr := d.tfd.blockOnWrite(); pollErr != nil {
				return 0, pollErr
			}
		case unix.EINTR:
			// Signal interrupted the syscall - retry immediately.
		case unix.EBADF:
			return 0, os.ErrClosed
		default:
			return 0, fmt.Errorf("tuntap: write: %w", err)
		}
	}
}

// Close shuts down the device.
func (d *Device) Close() error {
	if !atomic.CompareAndSwapUint32(&d.closed, 0, 1) {
		return nil // already closed
	}
	d.tfd.wakeForShutdown() // unblock any goroutines in Read or Write
	d.closeAll()
	return nil
}

// setMTU applies mtu to the kernel interface via SIOCSIFMTU.
func (d *Device) setMTU(mtu int) error {
	req := ifreqMTU{MTU: int32(mtu)}
	copy(req.Name[:], d.name)
	if err := ioctlSIOCSIFMTU(uintptr(d.ctlFd), &req); err != nil {
		return fmt.Errorf("tuntap: SIOCSIFMTU: %w", err)
	}
	return nil
}

// setUp brings the interface to the UP state via SIOCGIFFLAGS + SIOCSIFFLAGS.
func (d *Device) setUp() error {
	req := ifreqFlags{}
	copy(req.Name[:], d.name)

	if err := ioctlSIOCGIFFLAGS(uintptr(d.ctlFd), &req); err != nil {
		return fmt.Errorf("tuntap: SIOCGIFFLAGS: %w", err)
	}
	req.Flags |= unix.IFF_UP
	if err := ioctlSIOCSIFFLAGS(uintptr(d.ctlFd), &req); err != nil {
		return fmt.Errorf("tuntap: SIOCSIFFLAGS: %w", err)
	}
	return nil
}

// closeAll closes all file descriptors. Called by Close and by New on error.
func (d *Device) closeAll() {
	_ = unix.Close(d.tfd.shutdownFd)
	_ = unix.Close(d.ctlFd)
	_ = unix.Close(d.tfd.fd)
}
