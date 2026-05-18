package loopback_test

import (
	"sync"
	"testing"
	"time"

	"github.com/rykth/tcp-ip-stack/pkg/loopback"
)

func TestLoopback_ReadWrite(t *testing.T) {
	d := loopback.New()
	defer d.Close()

	frames := [][]byte{
		{0x01, 0x02, 0x03},
		{0xaa, 0xbb},
		make([]byte, 1500),
	}

	for i, want := range frames {
		if _, err := d.Write(want); err != nil {
			t.Fatalf("frame %d: Write: %v", i, err)
		}
	}

	for i, want := range frames {
		buf := make([]byte, d.MTU())
		n, err := d.Read(buf)
		if err != nil {
			t.Fatalf("frame %d: Read: %v", i, err)
		}
		got := buf[:n]
		if len(got) != len(want) {
			t.Fatalf("frame %d: length mismatch: got %d, want %d", i, len(got), len(want))
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("frame %d byte %d: got %#x, want %#x", i, j, got[j], want[j])
			}
		}
	}
}

func TestLoopback_WriteCopiesData(t *testing.T) {
	d := loopback.New()
	defer d.Close()

	src := []byte{0x01, 0x02, 0x03}
	if _, err := d.Write(src); err != nil {
		t.Fatal(err)
	}
	src[0] = 0xff // mutate after write

	buf := make([]byte, 64)
	n, err := d.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x01 {
		t.Fatalf("Write did not copy: got %#x, want 0x01 (mutation leaked after n=%d)", buf[0], n)
	}
}

func TestLoopback_ConcurrentReadWrite(t *testing.T) {
	const numFrames = 100
	d := loopback.New(loopback.WithBufferSize(numFrames))
	defer d.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := range numFrames {
			frame := []byte{byte(i)}
			if _, err := d.Write(frame); err != nil {
				t.Errorf("Write %d: %v", i, err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 64)
		for range numFrames {
			if _, err := d.Read(buf); err != nil {
				t.Errorf("Read: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}

func TestLoopback_CloseUnblocksRead(t *testing.T) {
	d := loopback.New()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := d.Read(buf)
		done <- err
	}()

	time.Sleep(10 * time.Millisecond) // let the goroutine block in Read
	d.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after Close, got nil")
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after Close")
	}
}

func TestLoopback_WriteAfterClose(t *testing.T) {
	d := loopback.New()
	d.Close()

	_, err := d.Write([]byte{0x01})
	if err == nil {
		t.Fatal("expected error writing to closed device")
	}
}

func TestLoopback_ReadAfterClose(t *testing.T) {
	d := loopback.New()
	d.Close()

	buf := make([]byte, 64)
	_, err := d.Read(buf)
	if err == nil {
		t.Fatal("expected error reading from closed device")
	}
}

func TestLoopback_CloseIsIdempotent(t *testing.T) {
	d := loopback.New()
	if err := d.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestLoopback_NameAndMTU(t *testing.T) {
	d := loopback.New(loopback.WithName("test0"), loopback.WithMTU(9000))
	if got := d.Name(); got != "test0" {
		t.Errorf("Name: got %q, want %q", got, "test0")
	}
	if got := d.MTU(); got != 9000 {
		t.Errorf("MTU: got %d, want %d", got, 9000)
	}
}
