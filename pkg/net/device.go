package net

// LinkDevice is the interface satisfied by all network devices in this stack.
type LinkDevice interface {
	Name() string
	MTU() int
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}
