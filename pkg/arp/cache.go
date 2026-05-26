package arp

import (
	"context"
	"sync"
	"time"

	"github.com/rykth/tcp-ip-stack/pkg/ethernet"
)

const (
	defaultTTL        = 20 * time.Minute // linux kernel default
	defaultGCInterval = time.Minute
)

// Entry is a single ARP cache record
type Entry struct {
	MAC     ethernet.Addr
	Expires time.Time
}

// Cache is a TTL-based ARP cache mapping IPv4 addresses to Ethernet MAC
// addresses
type Cache struct {
	mu         sync.RWMutex
	entries    map[[4]byte]Entry
	ttl        time.Duration
	gcInterval time.Duration
}

// CacheOption configures a Cache
type CacheOption func(*Cache)

// WithTTL sets how long an entry remains valid after being stored
func WithTTL(d time.Duration) CacheOption {
	return func(c *Cache) {
		c.ttl = d
	}
}

// WithGCInterval sets how often expired entries are collected
func WithGCInterval(d time.Duration) CacheOption {
	return func(c *Cache) {
		c.gcInterval = d
	}
}

// NewCache returns an initialised, empty Cache
func NewCache(opts ...CacheOption) *Cache {
	c := &Cache{
		entries:    make(map[[4]byte]Entry),
		ttl:        defaultTTL,
		gcInterval: defaultGCInterval,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Lookup returns the MAC address for ip if a non-expired entry exists
func (c *Cache) Lookup(ip [4]byte) (ethernet.Addr, bool) {
	c.mu.RLock()
	e, ok := c.entries[ip]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.Expires) {
		return ethernet.Addr{}, false
	}
	return e.MAC, true
}

// Store inserts or refreshes the cache entry for ip, resetting its TTL
func (c *Cache) Store(ip [4]byte, mac ethernet.Addr) {
	c.mu.Lock()
	c.entries[ip] = Entry{MAC: mac, Expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

// Delete removes the entry for ip
func (c *Cache) Delete(ip [4]byte) {
	c.mu.Lock()
	delete(c.entries, ip)
	c.mu.Unlock()
}

// Start runs the background GC goroutine until ctx is cancelled
func (c *Cache) Start(ctx context.Context) {
	tick := time.NewTicker(c.gcInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c.gc()
		}
	}
}

func (c *Cache) gc() {
	now := time.Now()
	c.mu.Lock()
	for ip, e := range c.entries {
		if now.After(e.Expires) {
			delete(c.entries, ip)
		}
	}
	c.mu.Unlock()
}
