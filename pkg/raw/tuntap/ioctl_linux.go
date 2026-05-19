//go:build linux

package tuntap

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// the ifreq struct layout expected by TUNSETIFF.
type ifReq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

// ifreq layout for SIOCSIFMTU and SIOCGIFMTU.
type ifreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
	_    [20]byte
}

// ifreq layout for SIOCGIFFLAGS and SIOCSIFFLAGS.
type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [22]byte
}

func ioctlTUNSETIFF(fd uintptr, req *ifReq) error {
	return ioctl(fd, unix.TUNSETIFF, uintptr(unsafe.Pointer(req)))
}

func ioctlSIOCSIFMTU(fd uintptr, req *ifreqMTU) error {
	return ioctl(fd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(req)))
}

func ioctlSIOCSIFFLAGS(fd uintptr, req *ifreqFlags) error {
	return ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(req)))
}

func ioctlSIOCGIFFLAGS(fd uintptr, req *ifreqFlags) error {
	return ioctl(fd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(req)))
}

// ioctl is the raw syscall wrapper shared by all ioctl helpers.
func ioctl(fd, req, arg uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, req, arg)
	if errno != 0 {
		return errno
	}
	return nil
}
