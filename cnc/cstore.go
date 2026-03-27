package main

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type smap struct {
	m   map[string]interface{}
	cap int
	mu  sync.RWMutex
}

func makeSmap(cap int) *smap {
	return &smap{m: make(map[string]interface{}), cap: cap}
}

func (s *smap) Set(k string, v interface{}) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= s.cap && s.m[k] == nil {
		return false
	}
	s.m[k] = v
	return true
}

func (s *smap) Get(k string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[k]
	return v, ok
}

func (s *smap) Del(k string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
}

func (s *smap) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

func (s *smap) Put(k string, v interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= s.cap && s.m[k] == nil {
		return
	}
	s.m[k] = v
}

func (s *smap) Range(fn func(string, interface{}) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, v := range s.m {
		if !fn(k, v) {
			break
		}
	}
}

func (s *smap) Sweep(drop func(string, interface{}) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if drop(k, v) {
			delete(s.m, k)
		}
	}
}

type slist struct {
	data []interface{}
	cap  int
	mu   sync.RWMutex
}

func makeSlist(cap int) *slist {
	return &slist{data: make([]interface{}, 0, cap), cap: cap}
}

func (l *slist) Push(v interface{}) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.data) >= l.cap {
		return false
	}
	l.data = append(l.data, v)
	return true
}

func (l *slist) At(i int) (interface{}, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if i < 0 || i >= len(l.data) {
		return nil, false
	}
	return l.data[i], true
}

func (l *slist) Remove(i int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i < 0 || i >= len(l.data) {
		return false
	}
	l.data = append(l.data[:i], l.data[i+1:]...)
	return true
}

func (l *slist) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.data)
}

func (l *slist) Sweep(drop func(interface{}) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := make([]interface{}, 0, l.cap)
	for _, v := range l.data {
		if !drop(v) {
			kept = append(kept, v)
		}
	}
	l.data = kept
}

type connCache struct {
	entries map[string]*cachedConn
	mu      sync.RWMutex
	limit   int
	count   int32
}

type cachedConn struct {
	c    *tls.Conn
	used time.Time
}

func newConnCache(limit int) *connCache {
	return &connCache{entries: make(map[string]*cachedConn), limit: limit}
}

func (cc *connCache) Get(addr string) (*tls.Conn, bool) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	if e, ok := cc.entries[addr]; ok && e.c != nil {
		e.used = time.Now()
		return e.c, true
	}
	return nil, false
}

func (cc *connCache) Put(addr string, c *tls.Conn) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if atomic.LoadInt32(&cc.count) >= int32(cc.limit) {
		return fmt.Errorf("pool full")
	}
	if old, ok := cc.entries[addr]; ok {
		old.c.Close()
	}
	cc.entries[addr] = &cachedConn{c: c, used: time.Now()}
	atomic.AddInt32(&cc.count, 1)
	return nil
}

func (cc *connCache) Remove(addr string) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if e, ok := cc.entries[addr]; ok {
		e.c.Close()
		delete(cc.entries, addr)
		atomic.AddInt32(&cc.count, -1)
	}
}

func (cc *connCache) cleanup() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	for addr, e := range cc.entries {
		if e.used.Before(cutoff) {
			e.c.Close()
			delete(cc.entries, addr)
			atomic.AddInt32(&cc.count, -1)
		}
	}
}

func (cc *connCache) Close() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	for _, e := range cc.entries {
		e.c.Close()
	}
	cc.entries = make(map[string]*cachedConn)
}

func (cc *connCache) RunGC(every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			cc.cleanup()
		}
	}()
}
