package ethernet_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
)

// buildFrame assembles a raw Ethernet II frame byte slice for testing.
func buildFrame(dst, src ethernet.Addr, et ethernet.EtherType, payload []byte) []byte {
	b := make([]byte, ethernet.HeaderLen+len(payload))
	copy(b[0:6], dst[:])
	copy(b[6:12], src[:])
	binary.BigEndian.PutUint16(b[12:14], uint16(et))
	copy(b[14:], payload)
	return b
}

var (
	addrA = ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	addrB = ethernet.Addr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
)

func TestParse_roundtrip(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	raw := buildFrame(addrA, addrB, ethernet.EtherTypeIPv4, payload)

	f, err := ethernet.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.Dst != addrA {
		t.Errorf("Dst: got %v, want %v", f.Dst, addrA)
	}
	if f.Src != addrB {
		t.Errorf("Src: got %v, want %v", f.Src, addrB)
	}
	if f.EtherType != ethernet.EtherTypeIPv4 {
		t.Errorf("EtherType: got %#x, want %#x", f.EtherType, ethernet.EtherTypeIPv4)
	}
	if len(f.Payload) != len(payload) {
		t.Fatalf("Payload len: got %d, want %d", len(f.Payload), len(payload))
	}
	for i, b := range payload {
		if f.Payload[i] != b {
			t.Errorf("Payload[%d]: got %#x, want %#x", i, f.Payload[i], b)
		}
	}
}

func TestParse_tooShort(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		make([]byte, ethernet.HeaderLen-1),
	}
	for _, b := range cases {
		_, err := ethernet.Parse(b)
		if !errors.Is(err, ethernet.ErrFrameTooShort) {
			t.Errorf("len=%d: got %v, want ErrFrameTooShort", len(b), err)
		}
	}
}

func TestParse_payloadAliasesInput(t *testing.T) {
	raw := buildFrame(addrA, addrB, ethernet.EtherTypeIPv4, []byte{0xde, 0xad})

	f, err := ethernet.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	raw[14] = 0xff
	if f.Payload[0] != 0xff {
		t.Errorf("Payload[0] = %#x; want 0xff - Parse must not copy payload", f.Payload[0])
	}
}

func TestMarshal_roundtrip(t *testing.T) {
	h := ethernet.Header{
		Dst:       addrA,
		Src:       addrB,
		EtherType: ethernet.EtherTypeARP,
	}
	payload := []byte{0x10, 0x20, 0x30}

	dst := make([]byte, ethernet.HeaderLen+len(payload))
	n, err := ethernet.Marshal(dst, h, payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if n != len(dst) {
		t.Fatalf("Marshal returned %d, want %d", n, len(dst))
	}

	f, err := ethernet.Parse(dst)
	if err != nil {
		t.Fatalf("Parse after Marshal: %v", err)
	}
	if f.Dst != h.Dst {
		t.Errorf("Dst: got %v, want %v", f.Dst, h.Dst)
	}
	if f.Src != h.Src {
		t.Errorf("Src: got %v, want %v", f.Src, h.Src)
	}
	if f.EtherType != h.EtherType {
		t.Errorf("EtherType: got %#x, want %#x", f.EtherType, h.EtherType)
	}
	for i, b := range payload {
		if f.Payload[i] != b {
			t.Errorf("Payload[%d]: got %#x, want %#x", i, f.Payload[i], b)
		}
	}
}

func TestMarshal_bufferTooSmall(t *testing.T) {
	h := ethernet.Header{EtherType: ethernet.EtherTypeIPv4}
	payload := []byte{0x01, 0x02}

	dst := make([]byte, ethernet.HeaderLen)
	_, err := ethernet.Marshal(dst, h, payload)
	if err == nil {
		t.Fatal("expected error for too-small buffer, got nil")
	}
}

func TestAddr_IsMulticast(t *testing.T) {
	cases := []struct {
		addr ethernet.Addr
		want bool
	}{
		{ethernet.Addr{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, true},  // multicast
		{ethernet.Broadcast, true},                                 // broadcast has bit set
		{ethernet.Addr{0x00, 0xff, 0xff, 0xff, 0xff, 0xff}, false}, // unicast (bit 0 clear)
		{ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, false}, // unicast (0xaa = 0b10101010)
		{ethernet.Addr{0x03, 0x00, 0x00, 0x00, 0x00, 0x00}, true},  // multicast (0x03 = 0b00000011)
	}
	for _, tc := range cases {
		if got := tc.addr.IsMulticast(); got != tc.want {
			t.Errorf("Addr(%v).IsMulticast() = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestAddr_IsBroadcast(t *testing.T) {
	if !ethernet.Broadcast.IsBroadcast() {
		t.Error("Broadcast.IsBroadcast() = false, want true")
	}
	if addrA.IsBroadcast() {
		t.Errorf("%v.IsBroadcast() = true, want false", addrA)
	}
}

func TestParseAddr(t *testing.T) {
	cases := []struct {
		input   string
		want    ethernet.Addr
		wantErr bool
	}{
		{"aa:bb:cc:dd:ee:ff", ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, false},
		{"00:00:00:00:00:00", ethernet.Addr{}, false},
		{"ff:ff:ff:ff:ff:ff", ethernet.Broadcast, false},
		{"AA:BB:CC:DD:EE:FF", ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, false},
		{"aa:bb:cc:dd:ee", ethernet.Addr{}, true},       // too few groups
		{"aa:bb:cc:dd:ee:ff:00", ethernet.Addr{}, true}, // too many groups
		{"aa:bb:cc:dd:ee:gg", ethernet.Addr{}, true},    // invalid hex
		{"", ethernet.Addr{}, true},
	}
	for _, tc := range cases {
		got, err := ethernet.ParseAddr(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseAddr(%q): expected error, got nil", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAddr(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseAddr(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestEtherType_constants(t *testing.T) {
	if ethernet.EtherTypeIPv4 != 0x0800 {
		t.Errorf("EtherTypeIPv4 = %#x, want 0x0800", ethernet.EtherTypeIPv4)
	}
	if ethernet.EtherTypeARP != 0x0806 {
		t.Errorf("EtherTypeARP = %#x, want 0x0806", ethernet.EtherTypeARP)
	}
	if ethernet.EtherTypeIPv6 != 0x86DD {
		t.Errorf("EtherTypeIPv6 = %#x, want 0x86DD", ethernet.EtherTypeIPv6)
	}
}

func TestAddr_String(t *testing.T) {
	a := ethernet.Addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	if got := a.String(); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("String() = %q, want %q", got, "aa:bb:cc:dd:ee:ff")
	}
}

func BenchmarkParse(b *testing.B) {
	frame := make([]byte, 1514) // 14-byte header + 1500-byte payload
	binary.BigEndian.PutUint16(frame[12:], uint16(ethernet.EtherTypeIPv4))
	b.ReportAllocs()
	for b.Loop() {
		_, _ = ethernet.Parse(frame)
	}
}

func BenchmarkMarshal(b *testing.B) {
	dst := make([]byte, 1514)
	h := ethernet.Header{EtherType: ethernet.EtherTypeIPv4}
	payload := make([]byte, 1500)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = ethernet.Marshal(dst, h, payload)
	}
}
