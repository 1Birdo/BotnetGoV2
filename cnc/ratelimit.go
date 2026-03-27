package main

import (
	"context"
	"strconv"
	"sync"
	"time"
)

type rlKind int

const (
	rlAuth rlKind = iota
	rlAtk
	rlAPI
	rlCmd
	rlConn
)

func (k rlKind) String() string {
	switch k {
	case rlAuth:
		return "auth"
	case rlAtk:
		return "attack"
	case rlAPI:
		return "api"
	case rlCmd:
		return "command"
	case rlConn:
		return "connection"
	default:
		return "?"
	}
}

type rlRule struct {
	Max    int
	Window time.Duration
	Block  time.Duration
}

type rlBucket struct {
	Count int
	Start time.Time
	Last  time.Time
	Until time.Time
	Lock  sync.Mutex
}

type rateLimiter struct {
	cfgs    map[rlKind]rlRule
	buckets map[rlKind]*smap
	gmu     sync.RWMutex
}

var (
	rl         *rateLimiter
	defaultRules = map[rlKind]rlRule{
		rlAuth: {Max: 3, Window: 5 * time.Minute, Block: 15 * time.Minute},
		rlAtk:  {Max: 10, Window: 1 * time.Hour, Block: 30 * time.Minute},
		rlAPI:  {Max: 100, Window: 1 * time.Minute, Block: 5 * time.Minute},
		rlCmd:  {Max: 50, Window: 1 * time.Minute, Block: 2 * time.Minute},
		rlConn: {Max: 10, Window: 10 * time.Second, Block: 1 * time.Minute},
	}
)

func initRL() {
	rl = &rateLimiter{
		cfgs:    defaultRules,
		buckets: make(map[rlKind]*smap),
	}
	for k := range defaultRules {
		rl.buckets[k] = makeSmap(maxRL)
	}
	go rl.gc()
}

func rlCheck(kind rlKind, key string) (bool, time.Duration) {
	if rl == nil {
		return true, 0
	}
	rl.gmu.Lock()
	defer rl.gmu.Unlock()
	cfg, ok := rl.cfgs[kind]
	if !ok {
		return true, 0
	}
	bkt := rl.buckets[kind]
	raw, ok := bkt.Get(key)
	if !ok {
		e := &rlBucket{Start: time.Now(), Last: time.Now()}
		bkt.Set(key, e)
		raw = e
	}
	e := raw.(*rlBucket)
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
		rateLog(key, strconv.Itoa(int(kind)))
		return false, cfg.Block
	}
	e.Count++
	e.Last = time.Now()
	return true, 0
}

func rlLeft(kind rlKind, key string) int {
	if rl == nil {
		return -1
	}
	rl.gmu.RLock()
	defer rl.gmu.RUnlock()
	cfg, ok := rl.cfgs[kind]
	if !ok {
		return -1
	}
	raw, ok := rl.buckets[kind].Get(key)
	if !ok {
		return cfg.Max
	}
	e := raw.(*rlBucket)
	e.Lock.Lock()
	defer e.Lock.Unlock()
	if time.Since(e.Start) > cfg.Window {
		return cfg.Max
	}
	return cfg.Max - e.Count
}

func rlBlocked(kind rlKind, key string) bool {
	if rl == nil {
		return false
	}
	rl.gmu.RLock()
	defer rl.gmu.RUnlock()
	raw, ok := rl.buckets[kind].Get(key)
	if !ok {
		return false
	}
	e := raw.(*rlBucket)
	e.Lock.Lock()
	defer e.Lock.Unlock()
	return time.Now().Before(e.Until)
}

func rlReset(kind rlKind, key string) {
	if rl == nil {
		return
	}
	rl.gmu.Lock()
	defer rl.gmu.Unlock()
	rl.buckets[kind].Del(key)
}

func (r *rateLimiter) gc() {
	tick := time.NewTicker(1 * time.Minute)
	defer tick.Stop()
	for range tick.C {
		r.gmu.Lock()
		now := time.Now()
		for kind, bkt := range r.buckets {
			bkt.Sweep(func(k string, v interface{}) bool {
				e := v.(*rlBucket)
				e.Lock.Lock()
				defer e.Lock.Unlock()
				return now.After(e.Until) && now.Sub(e.Last) > r.cfgs[kind].Window*2
			})
		}
		r.gmu.Unlock()
	}
}

func (r *rateLimiter) WithCtx(ctx context.Context) {
	go func() {
		<-ctx.Done()
		r.gmu.Lock()
		for kind := range r.buckets {
			r.buckets[kind] = makeSmap(maxRL)
		}
		r.gmu.Unlock()
	}()
}

func rlStats() map[string]interface{} {
	if rl == nil {
		return nil
	}
	rl.gmu.RLock()
	defer rl.gmu.RUnlock()
	out := make(map[string]interface{})
	for k, bkt := range rl.buckets {
		out[k.String()] = map[string]interface{}{"entries": bkt.Len(), "cfg": rl.cfgs[k]}
	}
	return out
}
