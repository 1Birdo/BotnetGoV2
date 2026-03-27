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

type hive struct {
	bots   map[string]*tls.Conn
	byAddr map[string]string
	mu     sync.RWMutex
}

func newHive() *hive {
	return &hive{
		bots:   make(map[string]*tls.Conn),
		byAddr: make(map[string]string),
	}
}

func (h *hive) Register(id string, c *tls.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, ok := h.bots[id]; ok && old != nil {
		old.Close()
		for k, v := range h.byAddr {
			if v == id {
				delete(h.byAddr, k)
			}
		}
	}
	h.bots[id] = c
	h.byAddr[c.RemoteAddr().String()] = id
	heartbeats.ping(id, time.Now(), 0)
}

func (h *hive) Unregister(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.bots[id]; ok {
		delete(h.bots, id)
		for k, v := range h.byAddr {
			if v == id {
				delete(h.byAddr, k)
				break
			}
		}
		if c != nil {
			c.Close()
		}
		heartbeats.drop(id)
	}
}

func (h *hive) Find(c net.Conn) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.byAddr[c.RemoteAddr().String()]
}

func (h *hive) Conn(id string) (*tls.Conn, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	c, ok := h.bots[id]
	return c, ok
}

func (h *hive) Conns() map[string]*tls.Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	cp := make(map[string]*tls.Conn, len(h.bots))
	for id, c := range h.bots {
		cp[id] = c
	}
	return cp
}

func (h *hive) Size() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.bots)
}

func (h *hive) Cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, c := range h.bots {
		if c == nil {
			delete(h.bots, id)
			heartbeats.drop(id)
			for k, v := range h.byAddr {
				if v == id {
					delete(h.byAddr, k)
					break
				}
			}
			continue
		}
		c.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if _, err := c.Write([]byte{}); err != nil {
			delete(h.bots, id)
			heartbeats.drop(id)
			for k, v := range h.byAddr {
				if v == id {
					delete(h.byAddr, k)
					break
				}
			}
			c.Close()
		}
		c.SetWriteDeadline(time.Time{})
	}
}

const (
	lagThresh  = 1 * time.Minute
	deadThresh = 2 * time.Minute
)

type beat struct {
	At   time.Time
	Ping time.Duration
	Tag  string
}

type heartbeatMon struct {
	data map[string]*beat
	mu   sync.RWMutex
}

var heartbeats = &heartbeatMon{data: make(map[string]*beat)}

func (m *heartbeatMon) ping(id string, t time.Time, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.data[id]; ok {
		e.At = t
		if d > 0 {
			e.Ping = d
		}
	} else {
		m.data[id] = &beat{At: t, Ping: d, Tag: "ONLINE"}
	}
}

func (m *heartbeatMon) drop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, id)
}

func (m *heartbeatMon) alive() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	n := 0
	for _, e := range m.data {
		if _, live := tagStatus(now.Sub(e.At)); live {
			n++
		}
	}
	return n
}

func (m *heartbeatMon) check() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, e := range m.data {
		s, _ := tagStatus(now.Sub(e.At))
		e.Tag = s
	}
}

func (m *heartbeatMon) stats() map[string]int {
	out := map[string]int{"ONLINE": 0, "LAGGING": 0, "OFFLINE": 0, "TOTAL": 0}
	m.mu.RLock()
	now := time.Now()
	for _, e := range m.data {
		s, live := tagStatus(now.Sub(e.At))
		out[s]++
		if live {
			out["TOTAL"]++
		}
	}
	m.mu.RUnlock()
	if out["TOTAL"] == 0 {
		nodeDB.mu.RLock()
		n := 0
		fb := time.Now()
		for _, b := range nodeDB.entries {
			if fb.Sub(b.LastPing) <= deadThresh {
				n++
			}
		}
		nodeDB.mu.RUnlock()
		if n > 0 {
			out["ONLINE"] = n
			out["TOTAL"] = n
		}
	}
	return out
}

type beatDetail struct {
	Status string
	At     time.Time
	PingMs int64
	Live   bool
}

func (m *heartbeatMon) all() map[string]beatDetail {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]beatDetail)
	now := time.Now()
	for id, e := range m.data {
		s, live := tagStatus(now.Sub(e.At))
		out[id] = beatDetail{Status: s, At: e.At, PingMs: e.Ping.Milliseconds(), Live: live}
	}
	return out
}

func tagStatus(d time.Duration) (string, bool) {
	switch {
	case d > deadThresh:
		return "OFFLINE", false
	case d > lagThresh:
		return "LAGGING", true
	default:
		return "ONLINE", true
	}
}

func pulseLoop() {
	t := time.NewTicker(30 * time.Second)
	go func() {
		for range t.C {
			heartbeats.check()
		}
	}()
}

type nodeStore struct {
	entries map[string]node
	mu      sync.RWMutex
}

var nodeDB = &nodeStore{entries: make(map[string]node)}

func (db *nodeStore) save(id string, addr net.Addr, info sysinfo) {
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.entries[id]
	if !ok {
		e = node{ID: id, ConnAt: time.Now()}
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

func (db *nodeStore) setPing(id string, d time.Duration) {
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
	db.entries[id] = node{ID: id, ConnAt: time.Now(), LastPing: time.Now(), Status: "ONLINE", PingMs: ms}
}

func (db *nodeStore) logConn(id string, addr net.Addr) {
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.entries[id]
	if !ok {
		e = node{ID: id, ConnAt: time.Now()}
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

func (db *nodeStore) remove(id string) {
	db.mu.Lock()
	delete(db.entries, id)
	db.mu.Unlock()
}

func liveNodes() []node {
	db := nodeDB
	db.mu.RLock()
	snap := make(map[string]node, len(db.entries))
	for id, e := range db.entries {
		snap[id] = e
	}
	db.mu.RUnlock()

	hb := heartbeats.all()
	now := time.Now()
	var out []node
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
		if now.Sub(e.LastPing) > deadThresh {
			continue
		}
		out = append(out, e)
	}
	return out
}

type diagInfo struct {
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

func fetchDiag(c net.Conn) error {
	return sendMsg(c, newMsg(msgDiag, []byte{}))
}

func onDiag(id string, c net.Conn, w wireMsg) {
	if len(w.Data) < 101 {
		return
	}
	var d diagInfo
	copy(d.OS[:], w.Data[0:16])
	copy(d.Arch[:], w.Data[16:24])
	copy(d.CPU[:], w.Data[24:56])
	d.RAM = binary.BigEndian.Uint64(w.Data[56:64])
	d.Uptime = binary.BigEndian.Uint64(w.Data[64:72])
	d.Load1 = float32(binary.BigEndian.Uint32(w.Data[80:84])) / 100.0
	d.Load5 = float32(binary.BigEndian.Uint32(w.Data[84:88])) / 100.0
	d.Load15 = float32(binary.BigEndian.Uint32(w.Data[88:92])) / 100.0
	d.DiskUsage = binary.BigEndian.Uint64(w.Data[92:100])

	strip := func(b []byte) string { return strings.TrimSpace(string(bytes.TrimRight(b, "\x00"))) }

	info := sysinfo{
		OS: strip(d.OS[:]), Arch: strip(d.Arch[:]), CPU: strip(d.CPU[:]),
		RAM: fmt.Sprintf("%d MB", d.RAM), Uptime: fmt.Sprintf("%d seconds", d.Uptime),
		Load1: fmt.Sprintf("%.2f", d.Load1), Load5: fmt.Sprintf("%.2f", d.Load5),
		Load15: fmt.Sprintf("%.2f", d.Load15), Disk: fmt.Sprintf("%d MB", d.DiskUsage),
	}
	nodeDB.save(id, c.RemoteAddr(), info)
}

func diagLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		for _, c := range swarm.Conns() {
			go fetchDiag(c)
		}
	}
}

func serveBot(c *tls.Conn) {
	defer c.Close()
	id, err := checkBot(c)
	if err != nil {
		botLog(c.RemoteAddr().String(), false)
		sysLog("warn", "bot_auth_fail", map[string]interface{}{"ip": c.RemoteAddr().String(), "err": err.Error()})
		return
	}
	swarm.Register(id, c)
	nodeDB.logConn(id, c.RemoteAddr())
	defer func() {
		swarm.Unregister(id)
		heartbeats.drop(id)
		nodeDB.remove(id)
		botLog(c.RemoteAddr().String(), false)
	}()

	botLog(c.RemoteAddr().String(), true)
	heartbeats.ping(id, time.Now(), 0)

	stop := make(chan struct{})
	go keepAlive(c, id, stop)
	defer close(stop)

	fetchDiag(c)

	for {
		w, err := recvMsg(c)
		if err != nil {
			return
		}
		routePkt(c, w, id)
	}
}

func checkBot(c net.Conn) (string, error) {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	w, err := recvMsg(c)
	if err != nil {
		return "", fmt.Errorf("auth read: %w", err)
	}
	if w.Hdr.Type != msgAuth {
		return "", fmt.Errorf("expected auth pkt, got %d", w.Hdr.Type)
	}
	id := string(w.Data)
	if id == "" {
		return "", errors.New("empty bot id")
	}
	resp := newMsg(msgAuthOK, []byte("OK"))
	if err := sendMsg(c, resp); err != nil {
		return "", fmt.Errorf("auth reply: %w", err)
	}
	return id, nil
}

var pings sync.Map

func routePkt(c net.Conn, w wireMsg, id string) {
	switch w.Hdr.Type {
	case msgPong:
		if id == "" {
			id = swarm.Find(c)
		}
		var d time.Duration = -1
		if v, ok := pings.LoadAndDelete(id); ok {
			d = time.Since(v.(time.Time))
		}
		heartbeats.ping(id, time.Now(), d)
		nodeDB.setPing(id, d)
	case msgDiag:
		onDiag(id, c, w)
	case msgHeart:
		if id == "" {
			id = swarm.Find(c)
		}
		heartbeats.ping(id, time.Now(), 0)
		nodeDB.setPing(id, -1)
	}
}

func keepAlive(c net.Conn, id string, stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			pp := newMsg(msgPing, nil)
			pings.Store(id, time.Now())
			if sendMsg(c, pp) != nil {
				return
			}
		case <-stop:
			return
		}
	}
}

func nodeCount() int {
	n := len(liveNodes())
	if n == 0 {
		n = heartbeats.alive()
	}
	if n == 0 {
		n = swarm.Size()
	}
	return n
}
