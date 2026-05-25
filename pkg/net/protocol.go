package net

import (
	"context"

	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
)

// Frame is a received Ethernet frame delivered to a ProtocolHandler.
type Frame struct {
	Dst     ethernet.Addr
	Src     ethernet.Addr
	Payload []byte
	Dev     LinkDevice
}

// ProtocolHandler processes received Ethernet frames for a single EtherType.
type ProtocolHandler interface {
	EtherType() ethernet.EtherType
	RxChan() chan Frame
	Start(ctx context.Context, errCh chan<- error)
}
