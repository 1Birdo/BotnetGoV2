package main

import (
	"context"
	"strconv"
	"sync"
	"time"
)

type throttleKind int

const (
	throttleAuth throttleKind = iota
	throttleAtk
	throttleAPI
	throttleCmd
	throttleConn
)

func (t throttleKind) String() string {
	switch t {
	case throttleAuth:
		return "auth"
	case throttleAtk:
		return "attack"
	case throttleAPI:
		return "api"
	case throttleCmd:
		return "command"
	case throttleConn:
		return "connection"
	default:
		return "?"
	}
}

type throttleCfg struct {
	Max     int
	Window  time.Duration
	Block   time.Duration
}

type throttleEntry struct {
	Count   int
	Start   time.Time
	Last    time.Time
	Until   time.Time
	Lock    sync.Mutex
}

type throttler struct {
	cfgs    map[throttleKind]throttleCfg
	buckets map[throttleKind]*cmap
	gmu     sync.RWMutex
}

var (
	limiter     *throttler
	defaultCfgs = map[throttleKind]throttleCfg{
		throttleAuth: {Max: 3, Window: 5 * time.Minute, Block: 15 * time.Minute},
		throttleAtk:  {Max: 10, Window: 1 * time.Hour, Block: 30 * time.Minute},
		throttleAPI:  {Max: 100, Window: 1 * time.Minute, Block: 5 * time.Minute},
		throttleCmd:  {Max: 50, Window: 1 * time.Minute, Block: 2 * time.Minute},
		throttleConn: {Max: 10, Window: 10 * time.Second, Block: 1 * time.Minute},
	}
)

func setupThrottle() {
	limiter = &throttler{
		cfgs:    defaultCfgs,
		buckets: make(map[throttleKind]*cmap),
	}
	for k := range defaultCfgs {
		limiter.buckets[k] = newCmap(capThrottle)
	}
	go limiter.gc()
}

func checkThrottle(kind throttleKind, key string) (bool, time.Duration) {
	if limiter == nil {
		return true, 0
	}
	limiter.gmu.Lock()
	defer limiter.gmu.Unlock()
	cfg, ok := limiter.cfgs[kind]
	if !ok {
		return true, 0
	}
	bkt := limiter.buckets[kind]
	raw, ok := bkt.Get(key)
	if !ok {
		e := &throttleEntry{Start: time.Now(), Last: time.Now()}
		bkt.Set(key, e)
		raw = e
	}
	e := raw.(*throttleEntry)
	e.Lock.Lock()
	defer e.Lock.Unlock()
	if time.Now().Before(e.Until) {
		return false, time.Until(e.Until)
	}
	if time.Since(e.Start) > cfg.Window {
		e.Count = 0
		e.Start = time.Now()
	}
	if e.Count >= cfg.Max {
		e.Until = time.Now().Add(cfg.Block)
		logRateHit(key, strconv.Itoa(int(kind)))
		return false, cfg.Block
	}
	e.Count++
	e.Last = time.Now()
	return true, 0
}

func throttleRemaining(kind throttleKind, key string) int {
	if limiter == nil {
		return -1
	}
	limiter.gmu.RLock()
	defer limiter.gmu.RUnlock()
	cfg, ok := limiter.cfgs[kind]
	if !ok {
		return -1
	}
	raw, ok := limiter.buckets[kind].Get(key)
	if !ok {
		return cfg.Max
	}
	e := raw.(*throttleEntry)
	e.Lock.Lock()
	defer e.Lock.Unlock()
	if time.Since(e.Start) > cfg.Window {
		return cfg.Max
	}
	return cfg.Max - e.Count
}

func isBlocked(kind throttleKind, key string) bool {
	if limiter == nil {
		return false
	}
	limiter.gmu.RLock()
	defer limiter.gmu.RUnlock()
	raw, ok := limiter.buckets[kind].Get(key)
	if !ok {
		return false
	}
	e := raw.(*throttleEntry)
	e.Lock.Lock()
	defer e.Lock.Unlock()
	return time.Now().Before(e.Until)
}

func resetThrottle(kind throttleKind, key string) {
	if limiter == nil {
		return
	}
	limiter.gmu.Lock()
	defer limiter.gmu.Unlock()
	limiter.buckets[kind].Del(key)
}

func (t *throttler) gc() {
	tick := time.NewTicker(1 * time.Minute)
	defer tick.Stop()
	for range tick.C {
		t.gmu.Lock()
		now := time.Now()
		for kind, bkt := range t.buckets {
			bkt.Prune(func(k string, v interface{}) bool {
				e := v.(*throttleEntry)
				e.Lock.Lock()
				defer e.Lock.Unlock()
				return now.After(e.Until) && now.Sub(e.Last) > t.cfgs[kind].Window*2
			})
		}
		t.gmu.Unlock()
	}
}

func (t *throttler) WithCtx(ctx context.Context) {
	go func() {
		<-ctx.Done()
		t.gmu.Lock()
		for kind := range t.buckets {
			t.buckets[kind] = newCmap(capThrottle)
		}
		t.gmu.Unlock()
	}()
}

func throttleStats() map[string]interface{} {
	if limiter == nil {
		return nil
	}
	limiter.gmu.RLock()
	defer limiter.gmu.RUnlock()
	out := make(map[string]interface{})
	for k, bkt := range limiter.buckets {
		out[k.String()] = map[string]interface{}{"entries": bkt.Len(), "cfg": limiter.cfgs[k]}
	}
	return out
}
