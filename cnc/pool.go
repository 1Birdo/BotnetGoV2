package main

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type connPool struct {
	entries map[string]*poolEntry
	mu      sync.RWMutex
	limit   int
	count   int32
}

type poolEntry struct {
	c    *tls.Conn
	used time.Time
}

func newConnPool(limit int) *connPool {
	return &connPool{entries: make(map[string]*poolEntry), limit: limit}
}

func (p *connPool) Fetch(addr string) (*tls.Conn, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if e, ok := p.entries[addr]; ok && e.c != nil {
		e.used = time.Now()
		return e.c, true
	}
	return nil, false
}

func (p *connPool) Store(addr string, c *tls.Conn) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if atomic.LoadInt32(&p.count) >= int32(p.limit) {
		return fmt.Errorf("pool full")
	}
	if old, ok := p.entries[addr]; ok {
		old.c.Close()
	}
	p.entries[addr] = &poolEntry{c: c, used: time.Now()}
	atomic.AddInt32(&p.count, 1)
	return nil
}

func (p *connPool) Drop(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[addr]; ok {
		e.c.Close()
		delete(p.entries, addr)
		atomic.AddInt32(&p.count, -1)
	}
}

func (p *connPool) gc() {
	p.mu.Lock()
	defer p.mu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	for addr, e := range p.entries {
		if e.used.Before(cutoff) {
			e.c.Close()
			delete(p.entries, addr)
			atomic.AddInt32(&p.count, -1)
		}
	}
}

func (p *connPool) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		e.c.Close()
	}
	p.entries = make(map[string]*poolEntry)
}

func (p *connPool) StartGC(every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			p.gc()
		}
	}()
}
