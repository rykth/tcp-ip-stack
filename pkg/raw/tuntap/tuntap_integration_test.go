//go:build linux && integration

package tuntap

import (
	"testing"
)

func TestNew_TAP(t *testing.T) {
	d, err := New("", DeviceTAP)
	if err != nil {
		t.Skipf("cannot open TAP device (need CAP_NET_ADMIN): %v", err)
	}
	defer d.Close()

	if d.Name() == "" {
		t.Error("Name() returned empty string")
	}
	if d.MTU() != defaultMTU {
		t.Errorf("MTU() = %d, want %d", d.MTU(), defaultMTU)
	}
	t.Logf("opened TAP device %q MTU=%d", d.Name(), d.MTU())
}

func TestNew_TUN(t *testing.T) {
	d, err := New("", DeviceTUN)
	if err != nil {
		t.Skipf("cannot open TUN device (need CAP_NET_ADMIN): %v", err)
	}
	defer d.Close()

	if d.Name() == "" {
		t.Error("Name() returned empty string")
	}
	t.Logf("opened TUN device %q", d.Name())
}

func TestClose_Idempotent(t *testing.T) {
	d, err := New("", DeviceTAP)
	if err != nil {
		t.Skipf("cannot open TAP device: %v", err)
	}

	if err := d.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
