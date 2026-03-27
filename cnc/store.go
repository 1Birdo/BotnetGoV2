package main

import "sync"

// cmap is a size-capped thread-safe map.
type cmap struct {
	m   map[string]interface{}
	cap int
	mu  sync.RWMutex
}

func newCmap(cap int) *cmap {
	return &cmap{m: make(map[string]interface{}), cap: cap}
}

func (c *cmap) Set(k string, v interface{}) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.cap && c.m[k] == nil {
		return false
	}
	c.m[k] = v
	return true
}

func (c *cmap) Get(k string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.m[k]
	return v, ok
}

func (c *cmap) Del(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, k)
}

func (c *cmap) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}

func (c *cmap) Put(k string, v interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.cap && c.m[k] == nil {
		return
	}
	c.m[k] = v
}

func (c *cmap) Each(fn func(string, interface{}) bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for k, v := range c.m {
		if !fn(k, v) {
			break
		}
	}
}

func (c *cmap) Prune(shouldRemove func(string, interface{}) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.m {
		if shouldRemove(k, v) {
			delete(c.m, k)
		}
	}
}

// cslice is a size-capped thread-safe slice.
type cslice struct {
	data []interface{}
	cap  int
	mu   sync.RWMutex
}

func newCslice(cap int) *cslice {
	return &cslice{data: make([]interface{}, 0, cap), cap: cap}
}

func (s *cslice) Add(v interface{}) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data) >= s.cap {
		return false
	}
	s.data = append(s.data, v)
	return true
}

func (s *cslice) At(i int) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if i < 0 || i >= len(s.data) {
		return nil, false
	}
	return s.data[i], true
}

func (s *cslice) Remove(i int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i < 0 || i >= len(s.data) {
		return false
	}
	s.data = append(s.data[:i], s.data[i+1:]...)
	return true
}

func (s *cslice) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

func (s *cslice) Prune(drop func(interface{}) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]interface{}, 0, s.cap)
	for _, v := range s.data {
		if !drop(v) {
			kept = append(kept, v)
		}
	}
	s.data = kept
}
