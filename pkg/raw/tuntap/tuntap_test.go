//go:build linux

package tuntap

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestIfReqSize(t *testing.T) {
	// TUNSETIFF requires exactly 40 bytes - mismatched size causes EINVAL.
	const want = 40
	if got := unsafe.Sizeof(ifReq{}); got != want {
		t.Errorf("ifReq size = %d, want %d", got, want)
	}
}

func TestIfreqMTUSize(t *testing.T) {
	const want = 40
	if got := unsafe.Sizeof(ifreqMTU{}); got != want {
		t.Errorf("ifreqMTU size = %d, want %d", got, want)
	}
}

func TestIfreqFlagsSize(t *testing.T) {
	const want = 40
	if got := unsafe.Sizeof(ifreqFlags{}); got != want {
		t.Errorf("ifreqFlags size = %d, want %d", got, want)
	}
}

func TestDeviceType_Constants(t *testing.T) {
	if uint16(DeviceTAP) != unix.IFF_TAP {
		t.Errorf("DeviceTAP = %#x, want %#x (unix.IFF_TAP)", uint16(DeviceTAP), unix.IFF_TAP)
	}
	if uint16(DeviceTUN) != unix.IFF_TUN {
		t.Errorf("DeviceTUN = %#x, want %#x (unix.IFF_TUN)", uint16(DeviceTUN), unix.IFF_TUN)
	}
}

func TestNew_NameTooLong(t *testing.T) {
	longName := "thisinterfacenameiswaytoolong" // > IFNAMSIZ-1 characters
	_, err := New(longName, DeviceTAP)
	if err == nil {
		t.Fatal("expected error for long interface name, got nil")
	}
}

func TestWithMTU_SetsField(t *testing.T) {
	d := &Device{mtu: defaultMTU}
	WithMTU(9000)(d)
	if d.mtu != 9000 {
		t.Errorf("WithMTU: got %d, want 9000", d.mtu)
	}
}
